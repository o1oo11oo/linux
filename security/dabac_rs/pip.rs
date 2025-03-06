// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM PDP.
//!
//! Policy Information Point for Rust-based DABAC LSM.

use kernel::{bindings::uid_t, c_str, str::CStr};

/// An Attribute-Value Pair (AVP) combines an attribute name and its value
type AVP = (&'static CStr, &'static CStr);

/// User attribute storage, const for now
const USER_ATTRIBUTES: [(uid_t, [AVP; 2]); 2] = [
    (
        0,
        [
            (c_str!("role"), c_str!("admin")),
            (c_str!("group"), c_str!("software")),
        ],
    ),
    (
        1000,
        [
            (c_str!("role"), c_str!("user")),
            (c_str!("group"), c_str!("sales")),
        ],
    ),
];

/// Object attribute storage, const for now
const OBJECT_ATTRIBUTES: [(&CStr, [AVP; 2]); 2] = [
    (
        c_str!("/home/dabac_rs/a"),
        [
            (c_str!("protection"), c_str!("secret")),
            (c_str!("type"), c_str!("doc")),
        ],
    ),
    (
        c_str!("/home/dabac_rs/b"),
        [
            (c_str!("protection"), c_str!("open")),
            (c_str!("type"), c_str!("pdf")),
        ],
    ),
];

/// Retrieve the AVPs for a specific user
pub(crate) fn get_user_attributes(uid: uid_t) -> &'static [AVP] {
    USER_ATTRIBUTES
        .iter()
        .find_map(|(k, v)| (*k == uid).then(|| v.as_ref()))
        .unwrap_or_default()
}

/// Retrieve the AVPs for a specific object
pub(crate) fn get_object_attributes(path: &CStr) -> &'static [AVP] {
    OBJECT_ATTRIBUTES
        .iter()
        .find_map(|(k, v)| (*k == path).then(|| v.as_ref()))
        .unwrap_or_default()
}
