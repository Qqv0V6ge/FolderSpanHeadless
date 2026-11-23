use crate::runtime::config::{private_directory, random_id, write_private};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1v15::{Signature, SigningKey, VerifyingKey},
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    signature::{SignatureEncoding, Signer, Verifier},
};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredIdentity {
    version: u32,
    device_id: String,
    private_key: String,
    certificate: String,
}

pub struct CertificateStatus {
    pub valid: bool,
    pub summary: String,
}

pub struct Identity {
    pub server: Arc<ServerConfig>,
    pub fingerprint: String,
    pub public_key: String,
    pub certificate_pem: String,
    pub device_id: String,
    key: RsaPrivateKey,
}
impl Identity {
    pub fn certificate_status(data: &Path) -> Result<Option<CertificateStatus>> {
        #[derive(Deserialize)]
        struct Certificate {
            version: u32,
            certificate: String,
        }
        let path = data.join("tls-identity/identity.json");
        let Some(bytes) = crate::config::read_state(&path, 64 * 1024)? else {
            return Ok(None);
        };
        let bytes = Zeroizing::new(bytes);
        let stored: Certificate = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid saved TLS identity"))?;
        ensure!(stored.version == 1, "unsupported TLS identity version");
        let der = STANDARD
            .decode(stored.certificate)
            .map_err(|_| anyhow::anyhow!("invalid saved TLS certificate"))?;
        let (rest, certificate) = x509_parser::parse_x509_certificate(&der)
            .map_err(|_| anyhow::anyhow!("invalid saved TLS certificate"))?;
        ensure!(rest.is_empty(), "invalid saved TLS certificate");
        let validity = certificate.validity();
        let valid = validity.is_valid();
        let state = if valid {
            "valid"
        } else {
            "outside validity dates"
        };
        Ok(Some(CertificateStatus {
            valid,
            summary: format!(
                "{state}. Valid from {} to {}. SHA-256 {}",
                validity.not_before,
                validity.not_after,
                hex::encode_upper(Sha256::digest(&der))
            ),
        }))
    }

    pub fn load(data: &Path) -> Result<Self> {
        let dir = data.join("tls-identity");
        private_directory(&dir)?;
        let path = dir.join("identity.json");
        let stored = if path.exists() {
            let bytes = Zeroizing::new(std::fs::read(&path)?);
            let stored: StoredIdentity = serde_json::from_slice(&bytes)?;
            ensure!(stored.version == 1, "unsupported TLS identity version");
            stored
        } else {
            let key = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048)?;
            let der = key.to_pkcs8_der()?;
            let pkcs8 = PrivatePkcs8KeyDer::from(der.as_bytes().to_vec());
            let pair =
                rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &rcgen::PKCS_RSA_SHA256)?;
            let mut params = rcgen::CertificateParams::new(vec![
                "localhost".into(),
                "127.0.0.1".into(),
                "::1".into(),
            ])?;
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "FolderSpan Device");
            let cert = params.self_signed(&pair)?;
            let id = random_id(16);
            let stored = StoredIdentity {
                version: 1,
                device_id: format!(
                    "{}-{}-{}-{}-{}",
                    &id[..8],
                    &id[8..12],
                    &id[12..16],
                    &id[16..20],
                    &id[20..]
                ),
                private_key: STANDARD.encode(der.as_bytes()),
                certificate: STANDARD.encode(cert.der()),
            };
            let bytes = Zeroizing::new(serde_json::to_vec(&stored)?);
            write_private(&path, &bytes)?;
            stored
        };
        let key_der = Zeroizing::new(STANDARD.decode(&stored.private_key)?);
        let key = RsaPrivateKey::from_pkcs8_der(&key_der)?;
        let cert = STANDARD.decode(&stored.certificate)?;
        let certificate_pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            stored.certificate,
        );
        let public_key = RsaPublicKey::from(&key).to_public_key_pem(rsa::pkcs8::LineEnding::LF)?;
        let fingerprint = hex::encode_upper(Sha256::digest(&cert));
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.to_vec())),
            )?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            server: Arc::new(config),
            fingerprint,
            public_key,
            certificate_pem,
            device_id: stored.device_id,
            key,
        })
    }
    pub fn sign(&self, payload: &[u8]) -> String {
        STANDARD.encode(
            SigningKey::<Sha256>::new(self.key.clone())
                .sign(payload)
                .to_bytes(),
        )
    }
    pub(crate) fn public_key_from_certificate(pem: &[u8]) -> Option<String> {
        if pem.len() > 8192 {
            return None;
        }
        let (rest, pem) = x509_parser::pem::parse_x509_pem(pem).ok()?;
        if pem.label != "CERTIFICATE" || !rest.iter().all(u8::is_ascii_whitespace) {
            return None;
        }
        let certificate = pem.parse_x509().ok()?;
        RsaPublicKey::from_public_key_der(certificate.public_key().raw)
            .ok()?
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .ok()
    }
    pub fn verify(key: &str, payload: &[u8], signature: &str) -> bool {
        let result = (|| -> Result<()> {
            ensure!(key.len() <= 16 * 1024, "public key too large");
            let key = RsaPublicKey::from_public_key_pem(key)?;
            let sig = Signature::try_from(STANDARD.decode(signature)?.as_slice())?;
            VerifyingKey::<Sha256>::new(key).verify(payload, &sig)?;
            Ok(())
        })();
        result.is_ok()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_persists_and_signatures_are_pkcs1_sha256() {
        let d = tempfile::tempdir_in(
            crate::runtime::config::canonical_path(&std::env::temp_dir()).unwrap(),
        )
        .unwrap();
        assert!(Identity::certificate_status(d.path()).unwrap().is_none());
        let a = Identity::load(d.path()).unwrap();
        let b = Identity::load(d.path()).unwrap();
        assert_eq!(a.device_id, b.device_id);
        assert_eq!(a.fingerprint, b.fingerprint);
        assert_eq!(a.certificate_pem, b.certificate_pem);
        assert!(
            Identity::certificate_status(d.path())
                .unwrap()
                .unwrap()
                .summary
                .contains(&a.fingerprint)
        );
        assert_eq!(
            Identity::public_key_from_certificate(a.certificate_pem.as_bytes()),
            Some(a.public_key.clone()),
        );
        assert!(Identity::public_key_from_certificate(a.public_key.as_bytes()).is_none());
        let signature = a.sign(b"hello");
        assert!(Identity::verify(&b.public_key, b"hello", &signature));
        assert!(!Identity::verify(&b.public_key, b"changed", &signature));
        std::fs::write(d.path().join("tls-identity/identity.json"), b"broken").unwrap();
        assert!(Identity::certificate_status(d.path()).is_err());
        assert!(Identity::load(d.path()).is_err());
    }
}
