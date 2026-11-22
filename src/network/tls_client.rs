use anyhow::Result;
use rustls::{
    ClientConfig, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub fn normalize_fingerprint(value: &str) -> String {
    value
        .trim()
        .strip_prefix("sha256/")
        .unwrap_or(value.trim())
        .replace([':', ' '], "")
        .to_ascii_uppercase()
}
#[derive(Debug)]
enum IdentityPolicy {
    Fingerprint(Option<String>),
    FtpValidityAndName,
}
#[derive(Debug)]
struct NativeVerifier {
    policy: IdentityPolicy,
    provider: Arc<CryptoProvider>,
}
impl ServerCertVerifier for NativeVerifier {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        match &self.policy {
            IdentityPolicy::Fingerprint(expected) => {
                let actual = hex::encode_upper(Sha256::digest(cert.as_ref()));
                if expected.as_ref().is_some_and(|pin| pin != &actual) {
                    return Err(rustls::Error::General(
                        "certificate fingerprint mismatch".into(),
                    ));
                }
            }
            IdentityPolicy::FtpValidityAndName => {
                verify_ftp_certificate(cert, intermediates, server_name, now)?
            }
        }
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
// Explicit pins/discovery and the pinned JVM's FTP policy share handshake-signature checks.
fn configuration(policy: IdentityPolicy) -> Result<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NativeVerifier { policy, provider }))
        .with_no_client_auth())
}
pub fn fingerprint_config(pin: Option<&str>) -> Result<ClientConfig> {
    configuration(IdentityPolicy::Fingerprint(pin.map(normalize_fingerprint)))
}
pub(crate) fn ftp_config() -> Result<ClientConfig> {
    configuration(IdentityPolicy::FtpValidityAndName)
}
fn wildcard_label(pattern: &str, name: &str) -> bool {
    let (mut p, mut n, mut star, mut back) = (0usize, 0usize, None, 0usize);
    let pbytes = pattern.as_bytes();
    let nbytes = name.as_bytes();
    while n < nbytes.len() {
        if p < pbytes.len() && pbytes[p].eq_ignore_ascii_case(&nbytes[n]) {
            p += 1;
            n += 1;
        } else if p < pbytes.len() && pbytes[p] == b'*' {
            star = Some(p);
            p += 1;
            back = n;
        } else if let Some(at) = star {
            back += 1;
            n = back;
            p = at + 1;
        } else {
            return false;
        }
    }
    while p < pbytes.len() && pbytes[p] == b'*' {
        p += 1;
    }
    p == pbytes.len()
}
fn verify_ftp_certificate(
    cert: &CertificateDer<'_>,
    chain: &[CertificateDer<'_>],
    name: &ServerName<'_>,
    now: UnixTime,
) -> std::result::Result<(), rustls::Error> {
    use rustls::{CertificateError as Invalid, Error};
    use x509_parser::prelude::{FromDer, X509Certificate};
    let bad = || Error::InvalidCertificate(Invalid::BadEncoding);
    let now = i64::try_from(now.as_secs()).map_err(|_| bad())?;
    // Commons Net's pinned default validates dates for every supplied certificate, without a CA path.
    for der in std::iter::once(cert).chain(chain.iter()) {
        let (tail, parsed) = X509Certificate::from_der(der.as_ref()).map_err(|_| bad())?;
        if !tail.is_empty() {
            return Err(bad());
        }
        if parsed.validity().not_before.timestamp() > now {
            return Err(Error::InvalidCertificate(Invalid::NotValidYet));
        }
        if parsed.validity().not_after.timestamp() < now {
            return Err(Error::InvalidCertificate(Invalid::Expired));
        }
    }
    let parsed = rustls::server::ParsedCertificate::try_from(cert)?;
    if rustls::client::verify_server_name(&parsed, name).is_ok() {
        return Ok(());
    }
    let (_, parsed) = X509Certificate::from_der(cert.as_ref()).map_err(|_| bad())?;
    let names = parsed.subject_alternative_name().map_err(|_| bad())?;
    let has_dns = names.is_some_and(|san| {
        san.value
            .general_names
            .iter()
            .any(|n| matches!(n, x509_parser::extensions::GeneralName::DNSName(_)))
    });
    if !has_dns
        && let ServerName::DnsName(dns) = name
        && let Some(common) = parsed
            .subject()
            .iter_common_name()
            .last()
            .and_then(|v| v.as_str().ok())
    {
        let names = dns.as_ref().split('.').collect::<Vec<_>>();
        let patterns = common.split('.').collect::<Vec<_>>();
        if names.len() == patterns.len()
            && patterns
                .iter()
                .zip(names)
                .all(|(pattern, label)| wildcard_label(pattern, label))
        {
            return Ok(());
        }
    }
    Err(Error::InvalidCertificate(Invalid::NotValidForName))
}

#[cfg(test)]
mod ftp_tests {
    use super::*;
    fn certificate(
        names: Vec<String>,
        common: Option<&str>,
        start: i32,
        end: i32,
    ) -> CertificateDer<'static> {
        let mut params = rcgen::CertificateParams::new(names).unwrap();
        params.not_before = rcgen::date_time_ymd(start, 1, 1);
        params.not_after = rcgen::date_time_ymd(end, 1, 1);
        if let Some(common) = common {
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, common);
        }
        params
            .self_signed(&rcgen::KeyPair::generate().unwrap())
            .unwrap()
            .der()
            .clone()
    }
    #[test]
    fn ftp_matches_pinned_validity_hostname_and_cn_policy_without_changing_pin_policy() {
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_700_000_000));
        let host = ServerName::try_from("ftp.example.test").unwrap();
        let valid = certificate(vec!["ftp.example.test".into()], None, 2020, 2030);
        assert!(verify_ftp_certificate(&valid, &[], &host, now).is_ok());
        let wrong = ServerName::try_from("other.example.test").unwrap();
        assert!(verify_ftp_certificate(&valid, &[], &wrong, now).is_err());
        let expired = certificate(vec!["ftp.example.test".into()], None, 2010, 2020);
        assert!(matches!(
            verify_ftp_certificate(&expired, &[], &host, now),
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Expired
            ))
        ));
        let future = certificate(vec!["ftp.example.test".into()], None, 2030, 2040);
        assert!(matches!(
            verify_ftp_certificate(&future, &[], &host, now),
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidYet
            ))
        ));
        assert!(verify_ftp_certificate(&valid, &[expired], &host, now).is_err());
        let common = certificate(vec![], Some("*.example.test"), 2020, 2030);
        assert!(verify_ftp_certificate(&common, &[], &host, now).is_ok());
        assert!(
            verify_ftp_certificate(
                &common,
                &[],
                &ServerName::try_from("a.b.example.test").unwrap(),
                now
            )
            .is_err()
        );
        assert!(
            verify_ftp_certificate(&CertificateDer::from(vec![1, 2, 3]), &[], &host, now).is_err()
        );
        use rustls::internal::msgs::codec::{Codec, Reader};
        let signature =
            DigitallySignedStruct::read(&mut Reader::init(&[0x04, 0x03, 0, 1, 0])).unwrap();
        let verifier = NativeVerifier {
            policy: IdentityPolicy::FtpValidityAndName,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        };
        assert!(
            verifier
                .verify_tls12_signature(b"invalid handshake", &valid, &signature)
                .is_err()
        );
        assert!(
            verifier
                .verify_tls13_signature(b"invalid handshake", &valid, &signature)
                .is_err()
        );
        let pin = NativeVerifier {
            policy: IdentityPolicy::Fingerprint(Some("wrong".into())),
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        };
        assert!(
            pin.verify_server_cert(&valid, &[], &host, &[], now)
                .is_err()
        );
    }
}
