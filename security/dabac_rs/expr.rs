// SPDX-License-Identifier: GPL-2.0

//! Logical formula expression tree and evaluation.
//!
//! To be used in [`Policy`] rules to determine access decisions.
//!
//! This is a simplified expression tree, which only accepts formulas in
//! disjunctive normal form (DNF).
//!
//! Formulas can be parsed from [`str`] using [`str::parse`], errors during
//! parsing result in [EINVAL]. The grammar is kept simple to simplifiy parsing.
//! Whitespace is ignored. Expression are discribed by the following EBNF:
//!
//! ```EBNF
//! Expression = Expression "|" Expression | Conjunction | ε
//! Conjunction = Conjunction "&" Conjunction | Literal | ε
//! Literal = Term | "!" Term
//! Term = Value "<" Value | Value "=" Value | Value ">" Value
//! Value = "u" usize | "o" usize | "e" usize | "c" NonZeroU32
//! ```
//!
//! Note that values can either be constants (starting with `"c"`) or
//! user/object attributes (starting with `"u"`/`"o"` respectively). The
//! attributes are evaluated by looking up their values from assignments in the
//! parameters/attributions passed to the evaluate function.
//!
//! [`Policy`]: crate::policy::Policy

use core::{
    fmt::{Display, Formatter},
    num::NonZeroU32,
    str::FromStr,
};

use kernel::{kvec, prelude::*};

use crate::policy::Attributions;

#[derive(Debug)]
pub(crate) struct Expression {
    clauses: KVec<Conjunction>,
}

impl Expression {
    pub(crate) fn evaluate(
        &self,
        user_attr: &Attributions,
        object_attr: &Attributions,
        env_attr: &Attributions,
    ) -> bool {
        self.clauses.iter().fold(false, |acc, clause| {
            acc || clause.evaluate(user_attr, object_attr, env_attr)
        })
    }
}

impl FromStr for Expression {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(Self { clauses: kvec![] });
        }

        let mut clauses = kvec![];
        for clause in s.split('|') {
            clauses.push(clause.parse()?, GFP_KERNEL)?;
        }

        Ok(Self { clauses })
    }
}

impl Display for Expression {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let Some(clause) = self.clauses.first() else {
            return Ok(());
        };
        write!(f, "{}", clause)?;

        for clause in self.clauses.iter().skip(1) {
            write!(f, " | {}", clause)?;
        }

        Ok(())
    }
}

#[derive(Debug)]
struct Conjunction {
    clauses: KVec<Literal>,
}

impl Conjunction {
    fn evaluate(
        &self,
        user_attr: &Attributions,
        object_attr: &Attributions,
        env_attr: &Attributions,
    ) -> bool {
        self.clauses.iter().fold(true, |acc, clause| {
            acc && clause.evaluate(user_attr, object_attr, env_attr)
        })
    }
}

impl FromStr for Conjunction {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(Self { clauses: kvec![] });
        }

        let mut clauses = kvec![];
        for clause in s.split('&') {
            clauses.push(clause.parse()?, GFP_KERNEL)?;
        }

        Ok(Self { clauses })
    }
}

impl Display for Conjunction {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let Some(clause) = self.clauses.first() else {
            return Ok(());
        };
        write!(f, "{}", clause)?;

        for clause in self.clauses.iter().skip(1) {
            write!(f, " & {}", clause)?;
        }

        Ok(())
    }
}

#[derive(Debug)]
enum Literal {
    Identity(Term),
    Negation(Term),
}

impl Literal {
    fn evaluate(
        &self,
        user_attr: &Attributions,
        object_attr: &Attributions,
        env_attr: &Attributions,
    ) -> bool {
        match self {
            Literal::Identity(term) => term.evaluate(user_attr, object_attr, env_attr),
            Literal::Negation(term) => !term.evaluate(user_attr, object_attr, env_attr),
        }
    }
}

impl FromStr for Literal {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().split_at_checked(1) {
            None => Err(EINVAL),
            Some(("!", s)) => Ok(Literal::Negation(s.parse()?)),
            Some(_) => Ok(Literal::Identity(s.parse()?)),
        }
    }
}

impl Display for Literal {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Literal::Identity(term) => write!(f, "{}", term),
            Literal::Negation(term) => write!(f, "!{}", term),
        }
    }
}

#[derive(Debug)]
enum Operation {
    Less,
    Equals,
    Greater,
}

impl Display for Operation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Operation::Less => write!(f, "<"),
            Operation::Equals => write!(f, "="),
            Operation::Greater => write!(f, ">"),
        }
    }
}

#[derive(Debug)]
struct Term {
    left: Value,
    right: Value,
    op: Operation,
}

impl Term {
    fn evaluate(
        &self,
        user_attr: &Attributions,
        object_attr: &Attributions,
        env_attr: &Attributions,
    ) -> bool {
        // If an attribute that is not set or found is requested for evaluation,
        // this is treated as an unfulfillable requirement, which means the
        // resolution is always false, even if both arguments would return as
        // None, similar to how NaN != NaN.
        let Some(left) = self.left.evaluate(user_attr, object_attr, env_attr) else {
            return false;
        };
        let Some(right) = self.right.evaluate(user_attr, object_attr, env_attr) else {
            return false;
        };

        match self.op {
            Operation::Less => left < right,
            Operation::Equals => left == right,
            Operation::Greater => left > right,
        }
    }
}

impl FromStr for Term {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        if let Some((left, right)) = s.split_once("<") {
            Ok(Term {
                left: left.parse()?,
                right: right.parse()?,
                op: Operation::Less,
            })
        } else if let Some((left, right)) = s.split_once("=") {
            Ok(Term {
                left: left.parse()?,
                right: right.parse()?,
                op: Operation::Equals,
            })
        } else if let Some((left, right)) = s.split_once(">") {
            Ok(Term {
                left: left.parse()?,
                right: right.parse()?,
                op: Operation::Greater,
            })
        } else {
            Err(EINVAL)
        }
    }
}

impl Display for Term {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}{}{}", self.left, self.op, self.right)
    }
}

#[derive(Debug)]
enum Value {
    UserAttr(usize),
    ObjectAttr(usize),
    EnvAttr(usize),
    Constant(NonZeroU32),
}

impl Value {
    fn evaluate(
        &self,
        user_attr: &Attributions,
        object_attr: &Attributions,
        env_attr: &Attributions,
    ) -> Option<NonZeroU32> {
        match self {
            Value::UserAttr(identifier) => user_attr.get(*identifier),
            Value::ObjectAttr(identifier) => object_attr.get(*identifier),
            Value::EnvAttr(identifier) => env_attr.get(*identifier),
            Value::Constant(x) => Some(*x),
        }
    }
}

impl FromStr for Value {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().split_at_checked(1) {
            None => Err(EINVAL),
            Some(("u", num)) => Ok(Value::UserAttr(num.trim().parse()?)),
            Some(("o", num)) => Ok(Value::ObjectAttr(num.trim().parse()?)),
            Some(("e", num)) => Ok(Value::EnvAttr(num.trim().parse()?)),
            Some(("c", num)) => Ok(Value::Constant(num.trim().parse()?)),
            Some(_) => Err(EINVAL),
        }
    }
}

impl Display for Value {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Value::UserAttr(identifier) => write!(f, "u{}", identifier),
            Value::ObjectAttr(identifier) => write!(f, "o{}", identifier),
            Value::EnvAttr(identifier) => write!(f, "e{}", identifier),
            Value::Constant(value) => write!(f, "c{}", value),
        }
    }
}
