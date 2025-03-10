// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM policy types.
//!
//! This module contains types needed to represent the policy and attributes in
//! memory. They are mainly used by the PDP and the PIP. Both policy and
//! attribute assignments can be parsed from strings using the [`str::parse`]
//! function. The pre-condition [expressions] are implemented in the [`expr`]
//! module and documented there. The policy and attributions are described by
//! the following EBNF:
//!
//! ```EBNF
//! Policy = Rule ";" Rule | Rule | ε
//! Rule = PreCondition "=>" PostCondition | PreCondition
//!
//! PreCondition = Expression
//! PostCondition = PostCondition "," PostCondition | PolicyChange | ε
//! PolicyChange = AddUserAttribution | RemoveUserAttribution | AddObjectAttribution | RemoveObjectAttribution
//! AddUserAttribution = "+u" UserAttribution
//! RemoveUserAttribution = "-u" UserAttribution
//! AddObjectAttribution = "+o" ObjectAttribution
//! RemoveObjectAttribution = "-o" ObjectAttribution
//!
//! UserAttribution = usize ":" Attributions
//! ObjectAttribution = str ":" Attributions
//! Attributions = AVP "&" AVP | AVP | ε
//! AVP = usize "=" i32
//!
//! UserAttributes = UserAttributes "," UserAttributes | UserAttribution | ε
//! ObjectAttributes = ObjectAttributes "," ObjectAttributes | ObjectAttribution | ε
//! ```
//!
//! Here's what an example policy looks like:
//! ```text
//! u0=c0 & o0=c0 => -o /home/dabac_rs/a: 0=0, +o /home/dabac_rs/a: 0=1;
//! u0=c0 & o0=c1 => +u 1000: 0=0, -u 1000: 0=0;
//! u0=c1 & o0=c1"
//! ```
//!
//! [expressions]: crate::expr::Expression
//! [`expr`]: crate::expr
//! [AddUserAttribution]: PolicyChange::AddUserAttribution
//! [RemoveUserAttribution]: PolicyChange::RemoveUserAttribution
//! [AddObjectAttribution]: PolicyChange::AddObjectAttribution
//! [RemoveObjectAttribution]: PolicyChange::RemoveObjectAttribution

use core::str::FromStr;

use kernel::{alloc::KVec, bindings, kvec, prelude::*, str::CString};

use crate::expr::Expression;

#[derive(Debug)]
pub(crate) struct Policy {
    pub(crate) rules: KVec<Rule>,
}

impl FromStr for Policy {
    type Err = Error;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(Self { rules: kvec![] });
        }

        let mut rules = kvec![];
        for rule in s.split(';') {
            rules.push(rule.parse()?, GFP_KERNEL)?;
        }
        Ok(Self { rules })
    }
}

#[derive(Debug)]
pub(crate) struct Rule {
    pub(crate) pre: PreCondition,
    pub(crate) post: PostCondition,
}

impl FromStr for Rule {
    type Err = Error;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        match s.trim().split_once("=>") {
            None => Ok(Self {
                pre: s.parse()?,
                post: PostCondition { changes: kvec![] },
            }),
            Some((pre, post)) => Ok(Self {
                pre: pre.parse()?,
                post: post.parse()?,
            }),
        }
    }
}

#[derive(Debug)]
pub(crate) struct PreCondition {
    pub(crate) formula: Expression,
}

impl FromStr for PreCondition {
    type Err = Error;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        Ok(Self {
            formula: s.trim().parse()?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct PostCondition {
    pub(crate) changes: KVec<PolicyChange>,
}

impl FromStr for PostCondition {
    type Err = Error;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(Self { changes: kvec![] });
        }

        let mut changes = kvec![];
        for change in s.split(',') {
            changes.push(change.parse()?, GFP_KERNEL)?;
        }
        Ok(Self { changes })
    }
}

#[derive(Debug)]
pub(crate) enum PolicyChange {
    AddUserAttribution(UserAttribution),
    RemoveUserAttribution(UserAttribution),
    AddObjectAttribution(ObjectAttribution),
    RemoveObjectAttribution(ObjectAttribution),
}

impl FromStr for PolicyChange {
    type Err = Error;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        use PolicyChange::*;

        match s.trim().split_at_checked(2) {
            None => Err(EINVAL),
            Some(("+u", s)) => Ok(AddUserAttribution(s.parse()?)),
            Some(("-u", s)) => Ok(RemoveUserAttribution(s.parse()?)),
            Some(("+o", s)) => Ok(AddObjectAttribution(s.parse()?)),
            Some(("-o", s)) => Ok(RemoveObjectAttribution(s.parse()?)),
            Some(_) => Err(EINVAL),
        }
    }
}

/// An Attribute-Value Pair (AVP) combines an attribute "name" and its value.
///
/// For simplicity the name is encoded as an identifier and values only allow
/// integers, which are easier to work with in equations.
type AVP = (usize, i32);

#[derive(Debug)]
pub(crate) struct UserAttributes {
    pub(crate) attr: KVec<UserAttribution>,
}

impl FromStr for UserAttributes {
    type Err = Error;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(Self { attr: kvec![] });
        }

        let mut attrs = kvec![];
        for attr in s.split(',') {
            attrs.push(attr.parse()?, GFP_KERNEL)?;
        }

        Ok(Self { attr: attrs })
    }
}

#[derive(Debug)]
pub(crate) struct UserAttribution {
    pub(crate) user: bindings::uid_t,
    pub(crate) attr: Attributions,
}

impl FromStr for UserAttribution {
    type Err = Error;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        match s.trim().split_once(':') {
            None => Err(EINVAL),
            Some((uid, attr)) => Ok(Self {
                user: uid.parse()?,
                attr: attr.parse()?,
            }),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ObjectAttributes {
    pub(crate) attr: KVec<ObjectAttribution>,
}

impl FromStr for ObjectAttributes {
    type Err = Error;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(Self { attr: kvec![] });
        }

        let mut attrs = kvec![];
        for attr in s.split(',') {
            attrs.push(attr.parse()?, GFP_KERNEL)?;
        }

        Ok(Self { attr: attrs })
    }
}

#[derive(Debug)]
pub(crate) struct ObjectAttribution {
    pub(crate) object: CString,
    pub(crate) attr: Attributions,
}

impl FromStr for ObjectAttribution {
    type Err = Error;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        match s.trim().split_once(':') {
            None => Err(EINVAL),
            Some((object, attr)) => Ok(Self {
                object: object.try_into()?,
                attr: attr.parse()?,
            }),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Attributions {
    pub(crate) inner: KVec<AVP>,
}

impl Attributions {
    pub(crate) fn get(&self, identifier: usize) -> Option<i32> {
        self.inner
            .iter()
            .find_map(|&(i, v)| (i == identifier).then_some(v))
    }
}

impl FromStr for Attributions {
    type Err = Error;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(Self { inner: kvec![] });
        }

        let mut attrs = kvec![];
        for attr in s.split('&') {
            let (i, v) = attr.trim().split_once('=').ok_or(EINVAL)?;
            attrs.push((i.trim().parse()?, v.trim().parse()?), GFP_KERNEL)?;
        }

        Ok(Self { inner: attrs })
    }
}
