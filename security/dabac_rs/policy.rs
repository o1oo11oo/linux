// SPDX-License-Identifier: GPL-2.0

//! Rust DABAC LSM policy types.
//!
//! This module contains types needed to represent the policy and attributes in
//! memory. They are mainly used by the PDP and the PIP. Both policy and
//! attribute assignments can be parsed from strings using the [`str::parse`]
//! function. The pre-condition [expressions] are implemented in the [`expr`]
//! module and documented there.
//!
//! For each possible operation, the policy contains multiple rules. To evaluate
//! them, all pre-conditions for the operation are evaluated. After all rules
//! are tried, the post-conditions of the ones evaluating to true are executed
//! in order of their definition.
//!
//! The policy and attributions are described by the following BNF:
//!
//! ```BNF
//! Policy ::= Rule ";" Rule | Rule | ε
//! Rule ::= RuleIdentifier ":=" PreCondition "=>" PostCondition | RuleIdentifier ":=" PreCondition
//!
//! UserAttributes ::= UserAttributes "," UserAttributes | EntityIdentifier ":" Attributions | ε
//! ObjectAttributes ::= ObjectAttributes "," ObjectAttributes | EntityIdentifier ":" Attributions | ε
//!
//! PreCondition ::= Expression
//! PostCondition ::= PostCondition "," PostCondition | PolicyChange | ε
//! PolicyChange ::= AddUserAttribution | RemoveUserAttribution | AddObjectAttribution | RemoveObjectAttribution
//!
//! AddUserAttribution ::= "+u" AddAttribution
//! RemoveUserAttribution ::= "-u" RemoveAttribution
//! AddObjectAttribution ::= "+o" AddAttribution
//! RemoveObjectAttribution ::= "-o" RemoveAttribution
//! AddAttribution ::= EntityIdentifier ":" AVP
//! RemoveAttribution ::= EntityIdentifier ":" AttributeIdentifier
//!
//! Attributions ::= AVP "&" AVP | AVP | ε
//! AVP ::= AttributeIdentifier "=" AttributeValue
//!
//! RuleIdentifier ::= usize
//! EntityIdentifier ::= usize
//! AttributeIdentifier ::= usize
//! AttributeValue ::= NonZeroU32
//! ```
//!
//! Here's what an example policy looks like:
//! ```text
//! 0:= u0=c1 & o0=c1;
//! 1:= u0=c1 & o0=c1 => -o 1048581: 0, +o 1048581: 0=2;
//! 0:= u0=c1 & o0=c2 | u0=c2 & o0=c2;
//! 1:= u0=c1 & o0=c2 | u0=c2 & o0=c2
//! ```
//!
//! [expressions]: crate::expr::Expression
//! [`expr`]: crate::expr
//! [AddUserAttribution]: PolicyChange::AddUserAttribution
//! [RemoveUserAttribution]: PolicyChange::RemoveUserAttribution
//! [AddObjectAttribution]: PolicyChange::AddObjectAttribution
//! [RemoveObjectAttribution]: PolicyChange::RemoveObjectAttribution

use core::{
    fmt::{Display, Formatter},
    num::NonZeroU32,
    str::FromStr,
};

use kernel::{alloc::Flags, hash::HashMap, prelude::*};

use crate::expr::Expression;

/// Main policy type, stores all [`Rule`]s with their pre- and post-conditions.
#[derive(Debug)]
pub(crate) struct Policy {
    map: KVec<KVec<Rule>>,
}

impl Policy {
    pub(crate) fn get(&self, operation: usize) -> Option<&KVec<Rule>> {
        self.map.get(operation)
    }
}

impl FromStr for Policy {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(Self { map: KVec::new() });
        }

        // Only allocate the "HashMap" as needed by adding new entries on demand
        let mut rules = KVec::new();
        for rule in s.split(';') {
            let (id, rule) = rule.trim().split_once(":=").ok_or(EINVAL)?;
            let id: usize = id.trim().parse()?;

            // Add new default entries if some are still missing
            for _ in rules.len()..=id {
                rules.push(KVec::new(), GFP_KERNEL)?
            }

            let entry = rules.get_mut(id).ok_or(EINVAL)?;
            entry.push(rule.parse()?, GFP_KERNEL)?;
        }

        Ok(Self { map: rules })
    }
}

impl Display for Policy {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let mut first = true;
        for (op, rules) in self.map.iter().enumerate().filter(|(_, v)| !v.is_empty()) {
            for rule in rules {
                if !first {
                    writeln!(f, ";")?;
                }
                first = false;
                write!(f, "{}:= {}", op, rule)?;
            }
        }

        Ok(())
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

impl Display for Rule {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.pre)?;
        if !self.post.changes.is_empty() {
            write!(f, " => {}", self.post)?;
        }
        Ok(())
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
        env_attr: &Attributions,
    ) -> bool {
        self.formula.evaluate(user_attr, object_attr, env_attr)
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

impl Display for PreCondition {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.formula)
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

impl Display for PostCondition {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let Some(change) = self.changes.first() else {
            return Ok(());
        };
        write!(f, "{}", change)?;

        for change in self.changes.iter().skip(1) {
            write!(f, ", {}", change)?;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub(crate) enum PolicyChange {
    AddToUser(AddAttribution),
    RemoveFromUser(RemoveAttribution),
    AddToObject(AddAttribution),
    RemoveFromObject(RemoveAttribution),
}

impl FromStr for PolicyChange {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        use PolicyChange::*;

        match s.trim().split_at_checked(2) {
            None => Err(EINVAL),
            Some(("+u", s)) => Ok(AddToUser(s.parse()?)),
            Some(("-u", s)) => Ok(RemoveFromUser(s.parse()?)),
            Some(("+o", s)) => Ok(AddToObject(s.parse()?)),
            Some(("-o", s)) => Ok(RemoveFromObject(s.parse()?)),
            Some(_) => Err(EINVAL),
        }
    }
}

impl Display for PolicyChange {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            PolicyChange::AddToUser(attr) => write!(f, "+u {}", attr),
            PolicyChange::RemoveFromUser(attr) => write!(f, "-u {}", attr),
            PolicyChange::AddToObject(attr) => write!(f, "+o {}", attr),
            PolicyChange::RemoveFromObject(attr) => write!(f, "-o {}", attr),
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

impl Display for AddAttribution {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}={}", self.entity, self.identifier, self.value)
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

impl Display for RemoveAttribution {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", self.entity, self.identifier)
    }
}

/// Empty attributions to return if there are none for the identifier
///
/// Since entries to User- and ObjectAttributions are only added as needed, we
/// might need to return a reference to Attributions that are not actually
/// stored. In case of `get_mut()` this is easy to solve by first increasing the
/// length of the internal vector. In case of `get()` though this is not
/// possible, which is why we return this static empty instance instead.
pub(crate) static EMPTY_ATTRIBUTIONS: Attributions = Attributions::new();

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

    pub(crate) fn get(&self, uid: usize) -> &Attributions {
        self.map.get(uid).unwrap_or(&EMPTY_ATTRIBUTIONS)
    }

    pub(crate) fn get_mut(&mut self, uid: usize, flags: Flags) -> Result<&mut Attributions> {
        self.ensure_length(uid, flags)?;
        self.map.get_mut(uid).ok_or(EINVAL)
    }

    // Since this might be called from within an RCU read critical section,
    // allow specifying the flags when it is used instead of just using
    // GFP_KERNEL by default.
    fn ensure_length(&mut self, index: usize, flags: Flags) -> Result {
        for _ in self.map.len()..=index {
            self.map.push(Attributions::new(), flags)?
        }

        Ok(())
    }
}

impl FromStr for UserAttributes {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(Self { map: KVec::new() });
        }

        // Only allocate the "HashMap" as needed by adding new entries on demand
        let mut attrs = KVec::new();
        for s in s.split(',') {
            let (uid, attr) = s.trim().split_once(':').ok_or(EINVAL)?;
            let uid: usize = uid.trim().parse()?;

            // Add new default entries if some are still missing
            for _ in attrs.len()..=uid {
                attrs.push(Attributions::new(), GFP_KERNEL)?
            }

            let entry = attrs.get_mut(uid).ok_or(EINVAL)?;
            *entry = attr.parse()?;
        }

        Ok(Self { map: attrs })
    }
}

impl Display for UserAttributes {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let mut first = true;
        for (entity, attr) in self.map.iter().enumerate().filter(|(_, v)| !v.is_empty()) {
            if !first {
                writeln!(f, ",")?;
            }
            first = false;
            write!(f, "{}: {}", entity, attr)?;
        }

        Ok(())
    }
}

/// Top level data type storing all object attributions
///
/// Maps inode numbers to a collection of attributions.
#[derive(Debug)]
pub(crate) struct ObjectAttributes {
    map: HashMap<usize, Attributions>,
}

impl ObjectAttributes {
    /// # Safety
    ///
    /// The HashMap needs to be initialized before first use by calling
    /// [`ObjectAttributes::initialize()`].
    pub(crate) const unsafe fn new() -> Self {
        Self {
            // SAFETY: Will be initialized before first use according to safety contract.
            map: unsafe { HashMap::new_uninitialized() },
        }
    }

    pub(crate) fn initialize(&mut self) {
        self.map.reset();
    }

    pub(crate) fn get(&self, inode: usize) -> &Attributions {
        self.map.get(&inode).unwrap_or(&EMPTY_ATTRIBUTIONS)
    }

    pub(crate) fn get_mut(&mut self, inode: usize, flags: Flags) -> Result<&mut Attributions> {
        self.ensure_length(inode, flags)?;
        Ok(self.map.entry(inode).or_insert(Attributions::new(), flags))
    }

    // Since this might be called from within an RCU read critical section,
    // allow specifying the flags when it is used instead of just using
    // GFP_KERNEL by default.
    fn ensure_length(&mut self, index: usize, flags: Flags) -> Result {
        if !self.map.contains_key(&index) {
            self.map.try_reserve(1, flags)?
        }

        Ok(())
    }
}

impl FromStr for ObjectAttributes {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(Self {
                map: HashMap::new(),
            });
        }

        // Only allocate the "HashMap" as needed by adding new entries on demand
        let mut attrs = HashMap::new();
        for s in s.split(',') {
            let (inode, attr) = s.trim().split_once(':').ok_or(EINVAL)?;
            let index = inode.trim().parse::<usize>()?;
            let entry = attr.trim().parse()?;

            attrs.insert_resize_if_needed(index, entry, GFP_KERNEL)?;
        }

        Ok(Self { map: attrs })
    }
}

impl Display for ObjectAttributes {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let mut first = true;
        for (entity, attr) in self.map.iter().filter(|(_, v)| !v.is_empty()) {
            if !first {
                writeln!(f, ",")?;
            }
            first = false;
            write!(f, "{}: {}", entity, attr)?;
        }

        Ok(())
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

    pub(crate) fn set(
        &mut self,
        identifier: usize,
        value: Option<NonZeroU32>,
        flags: Flags,
    ) -> Result {
        self.ensure_length(identifier, flags)?;

        let entry = self.map.get_mut(identifier).ok_or(EINVAL)?;
        *entry = value;

        Ok(())
    }

    pub(crate) fn add(&mut self, identifier: usize, value: NonZeroU32, flags: Flags) -> Result {
        self.set(identifier, Some(value), flags)
    }

    pub(crate) fn remove(&mut self, identifier: usize, flags: Flags) -> Result {
        self.set(identifier, None, flags)
    }

    // Since this might be called from within an RCU read critical section,
    // allow specifying the flags when it is used instead of just using
    // GFP_KERNEL by default.
    fn ensure_length(&mut self, index: usize, flags: Flags) -> Result {
        for _ in self.map.len()..=index {
            self.map.push(None, flags)?
        }

        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.map.iter().all(|v| v.is_none())
    }
}

impl FromStr for Attributions {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(Self { map: KVec::new() });
        }

        // Only allocate the "HashMap" as needed by adding new entries on demand
        let mut attrs = KVec::new();
        for attr in s.split('&') {
            let (index, value) = attr.trim().split_once('=').ok_or(EINVAL)?;
            let index: usize = index.trim().parse()?;

            // Add new default entries if some are still missing
            for _ in attrs.len()..=index {
                attrs.push(None, GFP_KERNEL)?
            }

            let entry = attrs.get_mut(index).ok_or(EINVAL)?;
            *entry = Some(value.trim().parse::<NonZeroU32>()?);
        }

        Ok(Self { map: attrs })
    }
}

impl Display for Attributions {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let mut first = true;
        for (i, v) in self
            .map
            .iter()
            .enumerate()
            .filter_map(|(i, v)| v.and_then(|v| Some((i, v))))
        {
            if !first {
                write!(f, " & ")?;
            }
            first = false;
            write!(f, "{}={}", i, v)?;
        }

        Ok(())
    }
}
