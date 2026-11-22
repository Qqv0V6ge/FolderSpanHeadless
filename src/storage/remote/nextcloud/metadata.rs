use super::Nextcloud;
use crate::{
    management::reply::{PlatformFailure, ResourceUnavailable},
    storage::{
        content_crypto::canonical_uuid,
        http::{body, success},
        remote::Entry,
    },
};
use anyhow::{Context, Result, ensure};
use reqwest::header::{ACCEPT, ACCEPT_ENCODING, CONTENT_TYPE};
use serde_json::Value;
use std::collections::BTreeMap;

pub(crate) const BATCH_SIZE: usize = 32;
const BLOCK: usize = 512;

impl Nextcloud {
    pub(crate) async fn download_content_metadata(
        &self,
        directory: &str,
        reference: Option<&Value>,
        entries: &[&Entry],
        max_entry_bytes: usize,
    ) -> Result<Option<BTreeMap<String, Vec<u8>>>> {
        ensure!(
            (1..=BATCH_SIZE).contains(&entries.len()) && (1..=65584).contains(&max_entry_bytes),
            "invalid metadata batch limits"
        );
        let prefix = format!("{}/", directory.trim_end_matches('/'));
        let mut expected = BTreeMap::new();
        for entry in entries {
            let (id, suffix) = entry
                .name
                .rsplit_once('.')
                .context("invalid metadata name")?;
            canonical_uuid(id)?;
            ensure!(
                matches!(suffix, "location" | "root" | "commit")
                    && !entry.is_directory
                    && !entry.is_symbolic_link
                    && entry.path.strip_prefix(&prefix) == Some(entry.name.as_str())
                    && (0..=max_entry_bytes as i64).contains(&entry.size)
                    && expected
                        .insert(entry.name.as_str(), entry.size as usize)
                        .is_none(),
                "invalid metadata batch member"
            );
        }
        self.validate(directory, reference).await?;
        let account = self.account()?;
        let mut target = self.file_url(&account, directory)?;
        let names = entries.iter().map(|entry| &entry.name).collect::<Vec<_>>();
        target
            .query_pairs_mut()
            .append_pair("files", &serde_json::to_string(&names)?);
        let response = self
            .client
            .get(target)
            .basic_auth(&account.username, Some(&account.access_token))
            .header(ACCEPT, "application/x-tar")
            .header(ACCEPT_ENCODING, "identity")
            .send()
            .await
            .map_err(|_| PlatformFailure)?;
        if matches!(response.status().as_u16(), 404 | 405 | 406 | 415 | 501) {
            return Ok(None);
        }
        let response = success(response)?;
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .context(ResourceUnavailable("metadata archive has no content type"))?
            .to_str()?
            .split(';')
            .next()
            .unwrap_or_default()
            .trim();
        if !["application/x-tar", "application/tar"]
            .iter()
            .any(|kind| content_type.eq_ignore_ascii_case(kind))
        {
            return Ok(None);
        }
        let limit = 2 * BLOCK
            + expected
                .values()
                .map(|size| BLOCK + padded(*size))
                .sum::<usize>();
        let bytes = body(response, limit).await?;
        Ok(Some(parse_tar(&bytes, &expected)?))
    }
}

fn padded(size: usize) -> usize {
    size.div_ceil(BLOCK) * BLOCK
}

fn zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&byte| byte == 0)
}

fn parse_tar(bytes: &[u8], expected: &BTreeMap<&str, usize>) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut remaining = bytes;
    let mut files = BTreeMap::new();
    loop {
        let (header, contents) = remaining
            .split_at_checked(BLOCK)
            .context("truncated metadata archive header")?;
        if zero(header) {
            ensure!(
                contents.len() == BLOCK && zero(contents) && files.len() == expected.len(),
                "incomplete metadata archive or invalid ending"
            );
            return Ok(files);
        }
        let checksum = header[..148]
            .iter()
            .chain(&header[156..])
            .map(|&byte| u64::from(byte))
            .sum::<u64>()
            + 8 * 32;
        ensure!(
            octal(&header[148..156])? == checksum,
            "metadata archive checksum changed"
        );
        ensure!(
            &header[257..265] == b"ustar\x0000"
                && matches!(header[156], b'0' | 0)
                && zero(&header[157..257]),
            "metadata archive member is not an unlinked USTAR file"
        );
        let name = field(&header[..100])?;
        let prefix = field(&header[345..500])?;
        // Nextcloud can encode a leading "//" as prefix "/" plus the bare member name.
        let name = match prefix {
            "" => name.strip_prefix("//").unwrap_or(name),
            "/" => name,
            _ => return Err(anyhow::anyhow!("unexpected metadata archive path prefix")),
        };
        let size = *expected
            .get(name)
            .context("unexpected metadata archive member")?;
        ensure!(
            !files.contains_key(name) && octal(&header[124..136])? == size as u64,
            "duplicate metadata archive member or changed size"
        );
        let (block, rest) = contents
            .split_at_checked(padded(size))
            .context("truncated metadata archive member")?;
        ensure!(zero(&block[size..]), "invalid metadata archive padding");
        files.insert(name.to_owned(), block[..size].to_vec());
        remaining = rest;
    }
}

fn field(bytes: &[u8]) -> Result<&str> {
    let end = bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len());
    ensure!(
        zero(&bytes[end..]) && bytes[..end].is_ascii(),
        "invalid metadata archive text field"
    );
    Ok(std::str::from_utf8(&bytes[..end])?)
}

fn octal(bytes: &[u8]) -> Result<u64> {
    let text = std::str::from_utf8(bytes)?.trim_matches(['\0', ' ']);
    ensure!(
        text.bytes().all(|byte| matches!(byte, b'0'..=b'7')),
        "invalid metadata archive number"
    );
    Ok(u64::from_str_radix(text, 8)?)
}
