// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM helper functions.
//!
//! Thinigs that probably belong somewhere in the kernel crate, but are kept
//! here for now.

use kernel::{
    alloc::Flags,
    bindings::dentry_path_raw,
    fs::LocalFile,
    kvec,
    prelude::*,
    str::{BStr, CStr},
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

pub(crate) fn file_get_full_name<'a>(file: &LocalFile, buf: &'a mut [u8]) -> &'a CStr {
    // SAFETY: `file` points to a valid file
    let dentry = unsafe { (*file.as_ptr()).f_path.dentry };
    // SAFETY: FFI call, dentry comes from a valid `file`
    let full_name = unsafe { dentry_path_raw(dentry, buf.as_mut_ptr(), buf.len() as _) };
    // SAFETY: `full_name` points to a valid C string and is alive as long as
    // `buf` is not freed, which only happens after it is converted to CString
    unsafe { CStr::from_char_ptr(full_name as _) }
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

/// Vendored [`global_lock`](kernel::sync::lock::global::global_lock)
///
/// This allows selecting the backend flexibly for the variants without needing to duplicate even
/// more code.
#[macro_export]
macro_rules! vendored_global_lock {
    {
        $(#[$meta:meta])* $pub:vis
        unsafe(uninit) static $name:ident: Lock<$valuety:ty> = $value:expr;
    } => {
        #[doc = ::core::concat!(
            "Backend type used by [`",
            ::core::stringify!($name),
            "`](static@",
            ::core::stringify!($name),
            ")."
        )]
        #[allow(clippy::upper_case_acronyms, non_camel_case_types, unreachable_pub)]
        $pub enum $name {}

        impl ::kernel::sync::lock::GlobalLockBackend for $name {
            const NAME: &'static ::kernel::str::CStr = ::kernel::c_str!(::core::stringify!($name));
            type Item = $valuety;
            type Backend = $crate::vendored_global_lock_inner!();

            fn get_lock_class() -> &'static ::kernel::sync::LockClassKey {
                ::kernel::static_lock_class!()
            }
        }

        $(#[$meta])*
        $pub static $name: ::kernel::sync::lock::GlobalLock<$name> = {
            // Defined here to be outside the unsafe scope.
            let init: $valuety = $value;

            // SAFETY:
            // * The user of this macro promises to initialize the macro before use.
            // * We are only generating one static with this backend type.
            unsafe { ::kernel::sync::lock::GlobalLock::new(init) }
        };
    };
}
pub(crate) use vendored_global_lock;
