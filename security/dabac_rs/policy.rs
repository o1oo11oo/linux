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
//!
//! AddUserAttribution = "+u" AddAttribution
//! RemoveUserAttribution = "-u" RemoveAttribution
//! AddObjectAttribution = "+o" AddAttribution
//! RemoveObjectAttribution = "-o" RemoveAttribution
//! AddAttribution = usize ":" AVP
//! RemoveAttribution = usize ":" usize
//!
//! Attributions = AVP "&" AVP | AVP | ε
//! AVP = usize "=" NonZeroU32
//!
//! UserAttributes = UserAttributes "," UserAttributes | usize ":" Attributions | ε
//! ObjectAttributes = ObjectAttributes "," ObjectAttributes | usize ":" Attributions | ε
//! ```
//!
//! Here's what an example policy looks like:
//! ```text
//! u0=c1 & o0=c1 => -o 1048581: 0, +o 1048581: 0=2;
//! u0=c1 & o0=c2 => +u 1000: 0=1, -u 1000: 0;
//! u0=c2 & o0=c2
//! ```
//!
//! [expressions]: crate::expr::Expression
//! [`expr`]: crate::expr
//! [AddUserAttribution]: PolicyChange::AddUserAttribution
//! [RemoveUserAttribution]: PolicyChange::RemoveUserAttribution
//! [AddObjectAttribution]: PolicyChange::AddObjectAttribution
//! [RemoveObjectAttribution]: PolicyChange::RemoveObjectAttribution

use core::{num::NonZeroU32, str::FromStr};

use kernel::{kvec, prelude::*};

use crate::expr::Expression;

/// The maximum amount of attributes possible
const MAX_ATTR_IDENTIFIERS: usize = 0x100;

/// The maximum uid allowed
const MAX_UIDS: usize = 0x1000;

/// The minimum inode possible during testing, used to move the inode range down
///
/// During testing, inodes of new files were very close to the beginning of this
/// range, which is why this number was chosen.
const MIN_INODE: usize = 0x100000;

/// The maximum amount of inodes possible during testing
const MAX_INODES: usize = 0x1000;

/// Main policy type, stores all [`Rule`]s with their pre- and post-conditions.
#[derive(Debug)]
pub(crate) struct Policy {
    pub(crate) rules: KVec<Rule>,
}

impl FromStr for Policy {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(Self { rules: KVec::new() });
        }

        let mut rules = KVec::new();
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

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().split_once("=>") {
            None => Ok(Self {
                pre: s.parse()?,
                post: PostCondition {
                    changes: KVec::new(),
                },
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
    formula: Expression,
}

impl PreCondition {
    pub(crate) fn evaluate(
        &self,
        user_attr: &Attributions,
        object_attr: &Attributions,
    ) -> Result<bool> {
        self.formula.evaluate(user_attr, object_attr)
    }
}

impl FromStr for PreCondition {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
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

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(Self {
                changes: KVec::new(),
            });
        }

        let mut changes = KVec::new();
        for change in s.split(',') {
            changes.push(change.parse()?, GFP_KERNEL)?;
        }
        Ok(Self { changes })
    }
}

#[derive(Debug)]
pub(crate) enum PolicyChange {
    AddUserAttribution(AddAttribution),
    RemoveUserAttribution(RemoveAttribution),
    AddObjectAttribution(AddAttribution),
    RemoveObjectAttribution(RemoveAttribution),
}

impl FromStr for PolicyChange {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
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

#[derive(Debug)]
pub(crate) struct AddAttribution {
    pub(crate) entity: usize,
    pub(crate) identifier: usize,
    pub(crate) value: NonZeroU32,
}

impl FromStr for AddAttribution {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let (e, iv) = s.trim().split_once(":").ok_or(EINVAL)?;
        let (i, v) = iv.trim().split_once("=").ok_or(EINVAL)?;
        Ok(Self {
            entity: e.trim().parse()?,
            identifier: i.trim().parse()?,
            value: v.trim().parse()?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct RemoveAttribution {
    pub(crate) entity: usize,
    pub(crate) identifier: usize,
}

impl FromStr for RemoveAttribution {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let (e, i) = s.trim().split_once(":").ok_or(EINVAL)?;
        Ok(Self {
            entity: e.trim().parse()?,
            identifier: i.trim().parse()?,
        })
    }
}

/// Top level data type storing all user attributions
///
/// Maps user ids to a collection of attributions
#[derive(Debug)]
pub(crate) struct UserAttributes {
    map: KVec<Attributions>,
}

impl UserAttributes {
    pub(crate) const fn new() -> Self {
        Self { map: KVec::new() }
    }

    pub(crate) fn get(&self, uid: usize) -> Result<&Attributions> {
        self.map.get(uid).ok_or(EINVAL)
    }

    pub(crate) fn get_mut(&mut self, uid: usize) -> Result<&mut Attributions> {
        self.map.get_mut(uid).ok_or(EINVAL)
    }
}

impl FromStr for UserAttributes {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(Self { map: KVec::new() });
        }

        // Since Attributions is not Clone, kvec! cannot be used for initialization
        let mut attrs = KVec::with_capacity(MAX_UIDS, GFP_KERNEL)?;
        for _ in 0..MAX_UIDS {
            attrs.push(Attributions::new(), GFP_KERNEL)?
        }

        for s in s.split(',') {
            match s.trim().split_once(':') {
                None => return Err(EINVAL),
                Some((uid, attr)) => match attrs.get_mut(uid.trim().parse::<usize>()?) {
                    Some(a) => *a = attr.parse()?,
                    None => return Err(EINVAL),
                },
            }
        }

        Ok(Self { map: attrs })
    }
}

/// Top level data type storing all object attributions
///
/// Maps inode numbers (shifted in range by subtracting a constant) to a
/// collection of attributions.
#[derive(Debug)]
pub(crate) struct ObjectAttributes {
    map: KVec<Attributions>,
}

impl ObjectAttributes {
    pub(crate) const fn new() -> Self {
        Self { map: KVec::new() }
    }

    pub(crate) fn get(&self, inode: usize) -> Result<&Attributions> {
        self.map.get(inode - MIN_INODE).ok_or(EINVAL)
    }

    pub(crate) fn get_mut(&mut self, inode: usize) -> Result<&mut Attributions> {
        self.map.get_mut(inode - MIN_INODE).ok_or(EINVAL)
    }
}

impl FromStr for ObjectAttributes {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(Self { map: KVec::new() });
        }

        // Since Attributions is not Clone, kvec! cannot be used for initialization
        let mut attrs = KVec::with_capacity(MAX_INODES, GFP_KERNEL)?;
        for _ in 0..MAX_INODES {
            attrs.push(Attributions::new(), GFP_KERNEL)?
        }

        for s in s.split(',') {
            match s.trim().split_once(':') {
                None => return Err(EINVAL),
                Some((inode, attr)) => {
                    match attrs.get_mut(inode.trim().parse::<usize>()? - MIN_INODE) {
                        Some(a) => *a = attr.parse()?,
                        None => return Err(EINVAL),
                    }
                }
            }
        }

        Ok(Self { map: attrs })
    }
}

#[derive(Debug)]
pub(crate) struct Attributions {
    map: KVec<Option<NonZeroU32>>,
}

impl Attributions {
    pub(crate) const fn new() -> Self {
        Self { map: KVec::new() }
    }

    pub(crate) fn get(&self, identifier: usize) -> Option<NonZeroU32> {
        self.map.get(identifier).copied().flatten()
    }

    pub(crate) fn set(&mut self, identifier: usize, value: Option<NonZeroU32>) -> Result<()> {
        let entry = self.map.get_mut(identifier).ok_or(EINVAL)?;
        *entry = value;
        Ok(())
    }

    pub(crate) fn add(&mut self, identifier: usize, value: NonZeroU32) -> Result<()> {
        self.set(identifier, Some(value))
    }

    pub(crate) fn remove(&mut self, identifier: usize) -> Result<()> {
        self.set(identifier, None)
    }
}

impl FromStr for Attributions {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(Self { map: KVec::new() });
        }

        let mut attrs = kvec![None; MAX_ATTR_IDENTIFIERS]?;
        for attr in s.split('&') {
            let (i, v) = attr.trim().split_once('=').ok_or(EINVAL)?;
            let entry = attrs.get_mut(i.trim().parse::<usize>()?).ok_or(EINVAL)?;
            *entry = Some(v.trim().parse::<NonZeroU32>()?);
        }

        Ok(Self { map: attrs })
    }
}
