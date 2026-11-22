//! Portable content formats shared with the pinned JVM host.
use aes_gcm::{Aes256Gcm, KeyInit, aead::AeadInOut};
use anyhow::{Result, ensure};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    num::NonZeroU32,
    path::Path,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const CHUNK_BYTES: usize = 1024 * 1024;
const ITERATIONS: u32 = 600_000;
const PASSWORD_DOMAIN: &[u8] = b"FolderSpan password location v1\0";
const RECOVERY_DOMAIN: &[u8] = b"FolderSpan classification recovery v2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ErrorCode {
    Unavailable,
    Locked,
    UnlockFailed,
    UnsupportedFormat,
    DamagedLocation,
    InitializationConflict,
    ReadOnly,
    UncertainResult,
    Conflict,
    SourceChanged,
}
#[derive(Debug)]
pub struct ContentError(pub ErrorCode, pub &'static str);
impl std::fmt::Display for ContentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.1)
    }
}
impl std::error::Error for ContentError {}

pub fn new_key() -> Result<Zeroizing<[u8; 32]>> {
    random()
}
fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    let mut bytes = Zeroizing::new([0; N]);
    rand::rngs::OsRng
        .try_fill_bytes(&mut *bytes)
        .map_err(|_| crate::management::reply::PlatformFailure)?;
    Ok(bytes)
}
fn scope_digest(scope: &str) -> Result<[u8; 32]> {
    ensure!(
        (1..=4096).contains(&scope.len()),
        "invalid encrypted location"
    );
    Ok(Sha256::digest(scope.as_bytes()).into())
}
fn password_length(password: &str, minimum: usize) -> Result<()> {
    ensure!(
        (minimum..=1024).contains(&password.encode_utf16().count()),
        "invalid content password length"
    );
    Ok(())
}
fn password_key(password: &str, salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0; 32]);
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(ITERATIONS).unwrap(),
        salt,
        password.as_bytes(),
        &mut *key,
    );
    key
}
fn crypt(
    encrypt: bool,
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(nonce.len() == 12, "invalid content nonce");
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| crate::management::reply::PlatformFailure)?;
    let mut output = Zeroizing::new(bytes.to_vec());
    let nonce: [u8; 12] = nonce.try_into()?;
    if encrypt {
        cipher.encrypt_in_place(&nonce.into(), aad, &mut *output)
    } else {
        cipher.decrypt_in_place(&nonce.into(), aad, &mut *output)
    }
    .map_err(|_| anyhow::anyhow!("content authentication failed"))?;
    Ok(output)
}
fn nonce(index: u64) -> Result<[u8; 12]> {
    ensure!(index <= i64::MAX as u64, "encrypted file is too large");
    let mut bytes = [0; 12];
    bytes[4..].copy_from_slice(&index.to_be_bytes());
    Ok(bytes)
}
fn frame_aad(header: &[u8], index: u64, count: u32, total: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(144);
    aad.extend_from_slice(header);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&count.to_be_bytes());
    aad.extend_from_slice(&total.to_be_bytes());
    aad
}
fn read_array<const N: usize>(reader: &mut impl Read) -> Result<[u8; N]> {
    let mut bytes = [0; N];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// Ciphertext is bounded to one authenticated 1 MiB frame at a time.
pub fn encrypt(
    source: &mut impl Read,
    destination: &mut impl Write,
    key: &[u8; 32],
    scope: &str,
    mut check_cancelled: impl FnMut() -> Result<()>,
) -> Result<()> {
    let digest = scope_digest(scope)?;
    let file_key = new_key()?;
    let mut header = Vec::with_capacity(124);
    header.extend_from_slice(b"FSPANENC");
    header.extend_from_slice(&1u32.to_be_bytes());
    header.extend_from_slice(&(CHUNK_BYTES as u32).to_be_bytes());
    header.extend_from_slice(random::<16>()?.as_ref());
    header.extend_from_slice(&digest);
    let wrap_nonce = random::<12>()?;
    let wrapped = crypt(true, key, wrap_nonce.as_ref(), &header, file_key.as_ref())?;
    header.extend_from_slice(wrap_nonce.as_ref());
    header.extend_from_slice(&wrapped);
    destination.write_all(&header)?;
    let mut block = Zeroizing::new(vec![0; CHUNK_BYTES]);
    let (mut total, mut index) = (0u64, 0u64);
    loop {
        check_cancelled()?;
        let mut count = 0;
        while count < CHUNK_BYTES {
            check_cancelled()?;
            match source.read(&mut block[count..]) {
                Ok(0) => break,
                Ok(read) => count += read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
        if count == 0 {
            break;
        }
        ensure!(
            total <= i64::MAX as u64 - count as u64,
            "encrypted file is too large"
        );
        let aad = frame_aad(&header, index, count as u32, total);
        let ciphertext = crypt(true, &file_key, &nonce(index)?, &aad, &block[..count])?;
        destination.write_all(&(count as u32).to_be_bytes())?;
        destination.write_all(&ciphertext)?;
        total += count as u64;
        index += 1;
    }
    check_cancelled()?;
    destination.write_all(&0u32.to_be_bytes())?;
    destination.write_all(&total.to_be_bytes())?;
    destination.write_all(&index.to_be_bytes())?;
    destination.write_all(&crypt(
        true,
        &file_key,
        &nonce(index)?,
        &frame_aad(&header, index, 0, total),
        &[],
    )?)?;
    destination.flush()?;
    Ok(())
}

pub(crate) fn decrypt(
    source: &mut impl Read,
    destination: &mut impl Write,
    key: &[u8; 32],
    scope: &str,
    check_cancelled: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    let prefix = read_array::<64>(source)?;
    ensure!(&prefix[..8] == b"FSPANENC", "unknown encrypted file format");
    ensure!(
        prefix[8..12] == 1u32.to_be_bytes(),
        "unsupported encrypted file version"
    );
    ensure!(
        prefix[12..16] == (CHUNK_BYTES as u32).to_be_bytes(),
        "unsupported encrypted chunk size"
    );
    ensure!(
        bool::from(prefix[32..64].ct_eq(&scope_digest(scope)?)),
        "encrypted location does not match"
    );
    let wrap_nonce = read_array::<12>(source)?;
    let wrapped = read_array::<48>(source)?;
    let unwrapped = crypt(false, key, &wrap_nonce, &prefix, &wrapped)?;
    let file_key: &[u8; 32] = unwrapped.as_slice().try_into()?;
    let header = [prefix.as_slice(), &wrap_nonce, &wrapped].concat();
    let (mut total, mut index, mut short) = (0u64, 0u64, false);
    loop {
        check_cancelled()?;
        let count = u32::from_be_bytes(read_array(source)?);
        ensure!(
            count <= CHUNK_BYTES as u32,
            "invalid encrypted frame length"
        );
        let aad = frame_aad(&header, index, count, total);
        if count == 0 {
            ensure!(
                u64::from_be_bytes(read_array(source)?) == total
                    && u64::from_be_bytes(read_array(source)?) == index,
                "encrypted length mismatch"
            );
            crypt(
                false,
                file_key,
                &nonce(index)?,
                &aad,
                &read_array::<16>(source)?,
            )?;
            let mut extra = [0; 1];
            loop {
                match source.read(&mut extra) {
                    Ok(0) => return Ok(()),
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error.into()),
                    Ok(_) => anyhow::bail!("unexpected encrypted trailing data"),
                }
            }
        }
        ensure!(
            !short && total <= i64::MAX as u64 - count as u64,
            "invalid encrypted frame sequence"
        );
        let mut ciphertext = vec![0; count as usize + 16];
        source.read_exact(&mut ciphertext)?;
        let plain = crypt(false, file_key, &nonce(index)?, &aad, &ciphertext)?;
        destination.write_all(&plain)?;
        short = count < CHUNK_BYTES as u32;
        total += count as u64;
        index += 1;
    }
}

/// No plaintext reaches the destination until the final frame and EOF are authenticated.
pub fn decrypt_and_publish(
    source: &mut impl Read,
    destination: &Path,
    key: &[u8; 32],
    scope: &str,
    mut check_cancelled: impl FnMut() -> Result<()>,
) -> Result<()> {
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .canonicalize()?;
    let destination = parent.join(
        destination
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("invalid destination"))?,
    );
    let mut temporary = tempfile::Builder::new()
        .prefix(".folderspan-decrypt-")
        .suffix(".part")
        .tempfile_in(&parent)?;
    crate::runtime::config::restrict_private(temporary.path(), false)?;
    decrypt(
        source,
        temporary.as_file_mut(),
        key,
        scope,
        &mut check_cancelled,
    )?;
    temporary.as_file().sync_all()?;
    check_cancelled()?;
    temporary
        .persist(&destination)
        .map_err(|error| error.error)?;
    Ok(())
}

pub fn export_recovery(key: &[u8; 32], scope: &str, password: &str) -> Result<Vec<u8>> {
    password_length(password, 12)?;
    let salt = random::<32>()?;
    let mut prefix = Vec::with_capacity(140);
    prefix.extend_from_slice(b"FSPANKEY");
    prefix.extend_from_slice(&1u32.to_be_bytes());
    prefix.extend_from_slice(&ITERATIONS.to_be_bytes());
    prefix.extend_from_slice(salt.as_ref());
    prefix.extend_from_slice(&scope_digest(scope)?);
    let nonce = random::<12>()?;
    let wrapping = password_key(password, salt.as_ref());
    let ciphertext = crypt(true, &wrapping, nonce.as_ref(), &prefix, key)?;
    prefix.extend_from_slice(nonce.as_ref());
    prefix.extend_from_slice(&ciphertext);
    Ok(prefix)
}
pub fn import_recovery(bytes: &[u8], scope: &str, password: &str) -> Result<Zeroizing<[u8; 32]>> {
    ensure!(bytes.len() == 140, "invalid recovery material");
    password_length(password, 12)?;
    ensure!(
        &bytes[..8] == b"FSPANKEY" && bytes[8..12] == 1u32.to_be_bytes(),
        "unsupported recovery format"
    );
    ensure!(
        bytes[12..16] == ITERATIONS.to_be_bytes(),
        "unsupported recovery derivation"
    );
    ensure!(
        bool::from(bytes[48..80].ct_eq(&scope_digest(scope)?)),
        "recovery location does not match"
    );
    let key = password_key(password, &bytes[16..48]);
    let unwrapped = crypt(false, &key, &bytes[80..92], &bytes[..80], &bytes[92..])?;
    Ok(Zeroizing::new(unwrapped.as_slice().try_into()?))
}

pub fn canonical_uuid(value: &str) -> Result<[u8; 16]> {
    ensure!(
        value.len() == 36
            && value
                .bytes()
                .enumerate()
                .all(|(i, b)| if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                }),
        "invalid content identity"
    );
    Ok(hex::decode(value.replace('-', ""))?.as_slice().try_into()?)
}
fn uuid(bytes: &[u8]) -> String {
    let value = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &value[..8],
        &value[8..12],
        &value[12..16],
        &value[16..20],
        &value[20..]
    )
}
pub fn export_classification_recovery(
    key: &[u8; 32],
    scope: &str,
    anchor: &str,
    password: &str,
) -> Result<Vec<u8>> {
    let anchor = canonical_uuid(anchor)?;
    let mut bytes = Vec::with_capacity(204);
    bytes.extend_from_slice(b"FSPANCAT");
    bytes.extend_from_slice(&2u32.to_be_bytes());
    bytes.extend_from_slice(&140u32.to_be_bytes());
    bytes.extend_from_slice(&export_recovery(key, scope, password)?);
    bytes.extend_from_slice(&anchor);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)?;
    mac.update(RECOVERY_DOMAIN);
    mac.update(&bytes);
    bytes.extend_from_slice(&mac.finalize().into_bytes());
    Ok(bytes)
}
pub fn import_classification_recovery(
    bytes: &[u8],
    scope: &str,
    password: &str,
) -> Result<(Zeroizing<[u8; 32]>, String)> {
    ensure!(
        bytes.len() == 204
            && &bytes[..8] == b"FSPANCAT"
            && bytes[8..12] == 2u32.to_be_bytes()
            && bytes[12..16] == 140u32.to_be_bytes(),
        "unsupported classification recovery format"
    );
    let key = import_recovery(&bytes[16..156], scope, password)?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_ref())?;
    mac.update(RECOVERY_DOMAIN);
    mac.update(&bytes[..172]);
    mac.verify_slice(&bytes[172..])
        .map_err(|_| anyhow::anyhow!("recovery classification anchor authentication failed"))?;
    Ok((key, uuid(&bytes[156..172])))
}

pub fn create_password_location(vault_id: &str, key: &[u8; 32], password: &str) -> Result<Vec<u8>> {
    password_length(password, 12)?;
    let mut prefix = Vec::with_capacity(124);
    prefix.extend_from_slice(b"FSPANVLT");
    prefix.extend_from_slice(&1u32.to_be_bytes());
    prefix.extend_from_slice(&canonical_uuid(vault_id)?);
    prefix.extend_from_slice(&ITERATIONS.to_be_bytes());
    let salt = random::<32>()?;
    let nonce = random::<12>()?;
    prefix.extend_from_slice(salt.as_ref());
    prefix.extend_from_slice(nonce.as_ref());
    let aad = [PASSWORD_DOMAIN, &prefix].concat();
    let wrapping = password_key(password, salt.as_ref());
    prefix.extend_from_slice(&crypt(true, &wrapping, nonce.as_ref(), &aad, key)?);
    Ok(prefix)
}
/// This identity is untrusted until unlock_password_location authenticates the envelope.
pub fn password_location_id(bytes: &[u8]) -> Result<String> {
    if bytes.len() != 124 {
        return Err(ContentError(
            ErrorCode::DamagedLocation,
            "invalid password location length",
        )
        .into());
    }
    if &bytes[..8] != b"FSPANVLT"
        || bytes[8..12] != 1u32.to_be_bytes()
        || bytes[28..32] != ITERATIONS.to_be_bytes()
    {
        return Err(ContentError(
            ErrorCode::UnsupportedFormat,
            "unsupported password location format",
        )
        .into());
    }
    Ok(uuid(&bytes[12..28]))
}
pub fn unlock_password_location(
    bytes: &[u8],
    password: &str,
) -> Result<(String, Zeroizing<[u8; 32]>)> {
    let id = password_location_id(bytes)?;
    password_length(password, 0)?;
    let key = password_key(password, &bytes[32..64]);
    let aad = [PASSWORD_DOMAIN, &bytes[..76]].concat();
    let unwrapped = crypt(false, &key, &bytes[64..76], &aad, &bytes[76..]).map_err(|_| {
        ContentError(
            ErrorCode::UnlockFailed,
            "unable to unlock; check the content password or location material",
        )
    })?;
    Ok((id, Zeroizing::new(unwrapped.as_slice().try_into()?)))
}

#[cfg(test)]
mod tests;
