//! **arrayvec** provides the types [`ArrayVec`] and [`ArrayString`]:
//! array-backed vector and string types, which store their contents inline.
//!
//! The arrayvec package has the following cargo features:
//!
//! - `std`
//!   - Optional, enabled by default
//!   - Use libstd; disable to use `no_std` instead.
//!
//! - `serde`
//!   - Optional
//!   - Enable serialization for ArrayVec and ArrayString using serde 1.x
//!
//! - `zeroize`
//!   - Optional
//!   - Implement `Zeroize` for ArrayVec and ArrayString
//!
//! ## Rust Version
//!
//! This version of arrayvec requires Rust 1.51 or later.
//!
#![allow(
    elided_lifetimes_in_paths,
    explicit_outlives_requirements,
    unreachable_pub,
    unsafe_op_in_unsafe_fn,
    clippy::let_and_return,
    clippy::manual_next_back,
    clippy::missing_safety_doc,
    clippy::module_inception,
    clippy::non_canonical_clone_impl,
    clippy::non_canonical_partial_ord_impl,
    clippy::precedence,
    clippy::question_mark,
    clippy::redundant_closure,
    clippy::redundant_field_names,
    clippy::redundant_static_lifetimes,
    clippy::undocumented_unsafe_blocks,
    clippy::unnecessary_safety_comment,
    clippy::while_let_on_iterator,
    clippy::write_literal
)]

pub(crate) type LenUint = u32;

macro_rules! assert_capacity_limit {
    ($cap:expr) => {
        if core::mem::size_of::<usize>() > core::mem::size_of::<LenUint>() {
            if $cap > LenUint::MAX as usize {
                panic!("ArrayVec: largest supported capacity is u32::MAX")
            }
        }
    };
}

macro_rules! assert_capacity_limit_const {
    ($cap:expr) => {
        if core::mem::size_of::<usize>() > core::mem::size_of::<LenUint>() {
            if $cap > LenUint::MAX as usize {
                [/*ArrayVec: largest supported capacity is u32::MAX*/][$cap]
            }
        }
    }
}

mod array_string;
mod arrayvec;
mod arrayvec_impl;
mod char;
mod errors;
mod utils;

pub use crate::alloc::arrayvec::array_string::ArrayString;
pub use crate::alloc::arrayvec::errors::CapacityError;

pub use crate::alloc::arrayvec::arrayvec::{ArrayVec, Drain, IntoIter};
