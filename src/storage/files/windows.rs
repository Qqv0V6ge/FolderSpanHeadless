use anyhow::{Result, ensure};
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions, OpenOptionsExt};
use std::{
    fs::File,
    os::windows::{fs::MetadataExt, io::AsRawHandle},
    path::Path,
    ptr,
    time::SystemTime,
};
use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError, LocalFree},
    Security::{
        Authorization::{ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT},
        LookupAccountSidW, OWNER_SECURITY_INFORMATION, PSID,
    },
    Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES,
        FILE_WRITE_ATTRIBUTES, READ_CONTROL,
    },
};

fn open_metadata(parent: &Dir, name: &Path, access: u32) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .access_mode(FILE_READ_ATTRIBUTES | access)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .follow(FollowSymlinks::No);
    let file = parent.open_with(name, &options)?.into_std();
    let metadata = file.metadata()?;
    ensure!(
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
            && (metadata.is_file() || metadata.is_dir()),
        super::denied()
    );
    Ok(file)
}

pub(super) fn set_modified(parent: &Dir, name: &Path, time: SystemTime) -> Result<()> {
    open_metadata(parent, name, FILE_WRITE_ATTRIBUTES)?.set_modified(time)?;
    Ok(())
}

pub(super) fn owner(parent: &Dir, name: &Path) -> Option<String> {
    let file = open_metadata(parent, name, READ_CONTROL).ok()?;
    let mut sid = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // The returned SID is owned by the descriptor until LocalFree.
    unsafe {
        let status = GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut sid,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        );
        let owner = if status == 0 && !sid.is_null() {
            account_name(sid).or_else(|| sid_text(sid))
        } else {
            None
        };
        if !descriptor.is_null() {
            LocalFree(descriptor);
        }
        owner
    }
}

fn account_name(sid: PSID) -> Option<String> {
    let mut name_len = 0;
    let mut domain_len = 0;
    let mut kind = 0;
    let code = unsafe {
        LookupAccountSidW(
            ptr::null(),
            sid,
            ptr::null_mut(),
            &mut name_len,
            ptr::null_mut(),
            &mut domain_len,
            &mut kind,
        );
        GetLastError()
    };
    if code != ERROR_INSUFFICIENT_BUFFER || !(1..=32768).contains(&name_len) || domain_len > 32768 {
        return None;
    }
    let mut name = vec![0; name_len as usize];
    let mut domain = vec![0; domain_len as usize];
    if unsafe {
        LookupAccountSidW(
            ptr::null(),
            sid,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    } == 0
    {
        return None;
    }
    let name = String::from_utf16_lossy(name.get(..name_len as usize)?)
        .trim_end_matches('\0')
        .to_owned();
    let domain = String::from_utf16_lossy(domain.get(..domain_len as usize)?);
    let domain = domain.trim_end_matches('\0');
    if domain.is_empty() {
        Some(name)
    } else {
        Some(format!("{domain}\\{name}"))
    }
}

fn sid_text(sid: PSID) -> Option<String> {
    let mut text = ptr::null_mut();
    // ConvertSidToStringSidW allocates a NUL-terminated string owned by LocalFree.
    unsafe {
        if ConvertSidToStringSidW(sid, &mut text) == 0 {
            return None;
        }
        let mut len = 0;
        while *text.add(len) != 0 {
            len += 1;
        }
        let result = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        Some(result)
    }
}
