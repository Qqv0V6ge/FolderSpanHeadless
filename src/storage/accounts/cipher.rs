use crate::{management::reply::PlatformFailure, runtime::config::write_private};
use aes_gcm::{Aes256Gcm, KeyInit, aead::AeadInOut};
use anyhow::{Result, ensure};
use rand::RngCore;
use std::path::Path;
use zeroize::Zeroizing;

pub(crate) const MAGIC: &[u8; 5] = b"FSAC\x01";
pub(crate) const OVERHEAD: usize = 5 + 12 + 16;
pub(crate) struct AccountCipher {
    key: Zeroizing<[u8; 32]>,
}
impl AccountCipher {
    pub fn load(directory: &Path, create: bool) -> Result<Self> {
        let path = directory.join("storage-account-key.bin");
        let key = match std::fs::symlink_metadata(&path) {
            Ok(meta) => {
                ensure!(
                    meta.is_file() && !meta.file_type().is_symlink() && meta.len() == 32,
                    "invalid storage account encryption key"
                );
                crate::runtime::config::restrict_private(&path, false)?;
                let bytes = Zeroizing::new(std::fs::read(&path)?);
                Zeroizing::new(
                    bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("invalid storage account encryption key"))?,
                )
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                ensure!(
                    create,
                    "storage account encryption key is missing; restore the original key"
                );
                let mut key = Zeroizing::new([0u8; 32]);
                rand::rngs::OsRng
                    .try_fill_bytes(&mut *key)
                    .map_err(|_| PlatformFailure)?;
                write_private(&path, key.as_ref())?;
                // Persist the key before replacing any plaintext preview state with ciphertext.
                #[cfg(unix)]
                std::fs::File::open(directory)?.sync_all()?;
                key
            }
            Err(e) => return Err(e.into()),
        };
        Ok(Self { key })
    }
    pub fn seal(&self, mut bytes: Zeroizing<Vec<u8>>) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(|_| PlatformFailure)?;
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| PlatformFailure)?;
        cipher
            .encrypt_in_place(&nonce.into(), MAGIC, &mut *bytes)
            .map_err(|_| PlatformFailure)?;
        let mut result = Vec::with_capacity(17 + bytes.len());
        result.extend_from_slice(MAGIC);
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&bytes);
        Ok(result)
    }
    pub fn open(&self, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(
            bytes.starts_with(MAGIC) && bytes.len() >= OVERHEAD,
            "invalid encrypted storage account state"
        );
        let nonce: [u8; 12] = bytes[5..17].try_into()?;
        let mut plaintext = Zeroizing::new(bytes[17..].to_vec());
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(|_| PlatformFailure)?;
        cipher
            .decrypt_in_place(&nonce.into(), MAGIC, &mut *plaintext)
            .map_err(|_| {
                anyhow::anyhow!(
                    "storage account authentication failed; restore the original state and key"
                )
            })?;
        Ok(plaintext)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypted_state_has_fresh_nonces_and_tampering_or_lost_keys_never_reset_it() {
        let root = tempfile::tempdir().unwrap();
        let cipher = AccountCipher::load(root.path(), true).unwrap();
        let a = cipher
            .seal(Zeroizing::new(b"private-access-token".to_vec()))
            .unwrap();
        let b = cipher
            .seal(Zeroizing::new(b"private-access-token".to_vec()))
            .unwrap();
        assert_ne!(a, b);
        assert!(!a.windows(20).any(|v| v == b"private-access-token"));
        assert_eq!(&*cipher.open(&a).unwrap(), b"private-access-token");
        for offset in [0, 5, 17, a.len() - 1] {
            let mut altered = a.clone();
            altered[offset] ^= 1;
            assert!(cipher.open(&altered).is_err());
        }
        for length in [0, 5, 17, a.len() - 1] {
            assert!(cipher.open(&a[..length]).is_err());
        }
        let key = root.path().join("storage-account-key.bin");
        std::fs::remove_file(&key).unwrap();
        assert!(AccountCipher::load(root.path(), false).is_err());
        assert!(!key.exists());
        let other = AccountCipher::load(root.path(), true).unwrap();
        assert!(other.open(&a).is_err());
    }
}
