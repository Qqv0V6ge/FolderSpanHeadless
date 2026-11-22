use anyhow::{Context, Result, ensure};
use std::{
    fs::OpenOptions,
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::Path,
    ptr,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GENERIC_ALL, LocalFree},
    Security::{
        Authorization::{
            EXPLICIT_ACCESS_W, SE_FILE_OBJECT, SET_ACCESS, SetEntriesInAclW, SetSecurityInfo,
            TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
        },
        DACL_SECURITY_INFORMATION, GetTokenInformation, PROTECTED_DACL_SECURITY_INFORMATION,
        SUB_CONTAINERS_AND_OBJECTS_INHERIT, TOKEN_QUERY, TOKEN_USER, TokenUser,
    },
    Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, READ_CONTROL, WRITE_DAC,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

pub(crate) fn restrict(path: &Path, directory: bool) -> Result<()> {
    // Windows 10 SetSecurityInfo also reads the current descriptor when replacing its DACL.
    let file = OpenOptions::new()
        .read(true)
        .access_mode(WRITE_DAC | READ_CONTROL | FILE_READ_ATTRIBUTES)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .context("open private ACL handle")?;
    let meta = file.metadata().context("inspect private ACL handle")?;
    ensure!(
        meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
            && if directory {
                meta.is_dir()
            } else {
                meta.is_file()
            },
        "private path type changed"
    );
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error()).context("read current-user token");
    }
    let result = (|| -> Result<()> {
        let mut size = 0;
        unsafe {
            GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut size);
        }
        ensure!(
            size as usize >= std::mem::size_of::<TOKEN_USER>(),
            "invalid current-user token"
        );
        let mut data = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
        if unsafe {
            GetTokenInformation(token, TokenUser, data.as_mut_ptr().cast(), size, &mut size)
        } == 0
        {
            return Err(std::io::Error::last_os_error()).context("read current-user token");
        }
        let user = unsafe { &*data.as_ptr().cast::<TOKEN_USER>() };
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: GENERIC_ALL,
            grfAccessMode: SET_ACCESS,
            grfInheritance: if directory {
                SUB_CONTAINERS_AND_OBJECTS_INHERIT
            } else {
                0
            },
            Trustee: TRUSTEE_W {
                pMultipleTrustee: ptr::null_mut(),
                MultipleTrusteeOperation: 0,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
                ptstrName: user.User.Sid.cast(),
            },
        };
        let mut acl = ptr::null_mut();
        let code = unsafe { SetEntriesInAclW(1, &entry, ptr::null(), &mut acl) };
        if code != 0 {
            return Err(std::io::Error::from_raw_os_error(code as i32))
                .context("build current-user private ACL");
        }
        let code = unsafe {
            SetSecurityInfo(
                file.as_raw_handle().cast(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                acl,
                ptr::null(),
            )
        };
        unsafe {
            LocalFree(acl.cast());
        }
        if code != 0 {
            return Err(std::io::Error::from_raw_os_error(code as i32))
                .context("set current-user private ACL");
        }
        Ok(())
    })();
    unsafe {
        CloseHandle(token);
    }
    result
}
