// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM helper functions.
//!
//! Thinigs that probably belong somewhere in the kernel crate, but are kept
//! here for now.

use kernel::{
    alloc::Flags,
    bindings::{dentry_path_raw, PATH_MAX},
    fs::File,
    kvec,
    prelude::*,
    str::{BStr, CStr, CString},
};

// based on the unmerged fs bindings
pub(crate) fn _file_get_name(file: &File) -> &BStr {
    let dentry = unsafe { (*file.as_ptr()).f_path.dentry };
    let dname = unsafe { (*dentry).d_name };
    let len = unsafe { dname.__bindgen_anon_1.__bindgen_anon_1.len } as _;
    let bytes: &[u8] = unsafe { core::slice::from_raw_parts(dname.name, len) };
    BStr::from_bytes(bytes)
}

pub(crate) fn file_get_full_name(file: &File) -> Result<CString> {
    let mut buf = kvec![0u8; PATH_MAX as _]?;
    let dentry = unsafe { (*file.as_ptr()).f_path.dentry };
    let full_name = unsafe { dentry_path_raw(dentry, buf.as_mut_ptr(), buf.len() as _) };
    Ok(unsafe { CStr::from_char_ptr(full_name as _) }.try_into()?)
}

pub(crate) fn vec_clone<T: Clone>(src: &[T], flags: Flags) -> Result<KVec<T>> {
    let mut cp = kvec![];
    cp.extend_from_slice(src, flags)?;
    Ok(cp)
}
