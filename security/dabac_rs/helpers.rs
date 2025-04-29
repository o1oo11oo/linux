// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM helper functions.
//!
//! Thinigs that probably belong somewhere in the kernel crate, but are kept
//! here for now.

use kernel::{
    alloc::Flags,
    bindings::{dentry_path_raw, PATH_MAX},
    fs::LocalFile,
    kvec,
    prelude::*,
    str::{BStr, CStr, CString},
    task::Kuid,
};

pub(crate) fn get_current_euid() -> usize {
    Kuid::current_euid().into_uid_in_current_ns() as _
}

// based on the unmerged fs bindings
pub(crate) fn _file_get_name(file: &LocalFile) -> &BStr {
    // SAFETY: `file` points to a valid file
    let dentry = unsafe { (*file.as_ptr()).f_path.dentry };
    // SAFETY: valid files have dentries
    let dname = unsafe { (*dentry).d_name };
    // SAFETY: accessing the len is ok for valid files
    let len = unsafe { dname.__bindgen_anon_1.__bindgen_anon_1.len } as _;
    // SAFETY: `name` points to bytes representing the name which are `len`
    // bytes long and live as long as `file` is valid
    let bytes: &[u8] = unsafe { core::slice::from_raw_parts(dname.name, len) };
    BStr::from_bytes(bytes)
}

pub(crate) fn file_get_full_name(file: &LocalFile) -> Result<CString> {
    let mut buf = kvec![0u8; PATH_MAX as _]?;
    // SAFETY: `file` points to a valid file
    let dentry = unsafe { (*file.as_ptr()).f_path.dentry };
    // SAFETY: FFI call, dentry comes from a valid `file`
    let full_name = unsafe { dentry_path_raw(dentry, buf.as_mut_ptr(), buf.len() as _) };
    // SAFETY: `full_name` points to a valid C string and is alive as long as
    // `buf` is not freed, which only happens after it is converted to CString
    Ok(unsafe { CStr::from_char_ptr(full_name as _) }.try_into()?)
}

pub(crate) fn file_get_inode_number(file: &LocalFile) -> kernel::ffi::c_ulong {
    // SAFETY: `file` points to a valid file
    let inode = unsafe { (*file.as_ptr()).f_inode };
    // SAFETY: valid files have inodes
    unsafe { (*inode).i_ino }
}

pub(crate) fn vec_clone<T: Clone>(src: &[T], flags: Flags) -> Result<KVec<T>> {
    let mut cp = kvec![];
    cp.extend_from_slice(src, flags)?;
    Ok(cp)
}
