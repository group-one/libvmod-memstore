//! An immutable set of multi-field rules, loaded from a block-based file.

mod bits;
mod column;
mod parse;
mod schema;

use std::path::Path;
use std::sync::Arc;

use bits::Bits;
use column::{CidrIndex, Column, Matcher, REGEX_CHUNK, compile};
use parse::{Cell, parse_blocks};
pub use schema::{Field, Input, Kind, Schema, SchemaError, TaskInputs};

use crate::cidr::EntryError;
use crate::file;
use crate::pattern::{self, PatternError};

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum LineError {
    #[error("expected \"field: value\"")]
    MissingColon,
    #[error("unknown field {0:?}")]
    UnknownField(String),
    #[error("field {0:?} appears twice in one rule")]
    DuplicateField(String),
    #[error("field {0:?} has an empty value")]
    EmptyValue(String),
    #[error("rule is missing required field {0:?}")]
    MissingRequired(String),
    #[error(transparent)]
    Cidr(#[from] EntryError),
}

#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    #[error("no fields defined: call field() before load()")]
    NoFields,
    #[error("line {line}: {source}")]
    Line {
        line: usize,
        #[source]
        source: LineError,
    },
    /// A regex value that does not compile, or a set of them too big to combine.
    #[error(transparent)]
    Pattern(#[from] PatternError),
    #[error(transparent)]
    Read(#[from] file::ReadError),
}

#[derive(Debug)]
pub struct RuleSet {
    schema: Arc<Schema>,
    /// First line of each rule, in file order -- also the rule's index.
    lines: Vec<usize>,
    /// Only fields some rule names; CIDR columns first, as they are the cheapest filter.
    columns: Vec<Column>,
}

impl RuleSet {
    pub fn empty(schema: Arc<Schema>) -> Self {
        Self {
            schema,
            lines: Vec::new(),
            columns: Vec::new(),
        }
    }

    /// Compile the rules in `text` against `schema`.
    ///
    /// Any bad line aborts the whole parse: callers reload into a fresh set and only swap
    /// on success, so a typo leaves the running rules untouched rather than dropping one.
    pub fn from_text(text: &str, schema: Arc<Schema>) -> Result<Self, RuleError> {
        if schema.is_empty() {
            return Err(RuleError::NoFields);
        }
        let raw = parse_blocks(text, &schema)?;
        let n = raw.len();

        let mut cidr_columns = Vec::new();
        let mut regex_pending = Vec::new();
        for (f, field) in schema.fields.iter().enumerate() {
            let cells: Vec<(usize, Cell)> = raw
                .iter()
                .enumerate()
                .filter_map(|(r, rule)| rule.cells[f].map(|c| (r, c)))
                .collect();
            if cells.is_empty() {
                continue;
            }
            let mut unconstrained = Bits::new(n);
            for (r, rule) in raw.iter().enumerate() {
                if rule.cells[f].is_none() {
                    unconstrained.insert(r);
                }
            }
            match field.kind {
                Kind::Cidr => cidr_columns.push(Column {
                    field: f,
                    unconstrained,
                    matcher: Matcher::Cidr(CidrIndex::build(&cells)?),
                }),
                Kind::Regex { case_insensitive } => {
                    regex_pending.push((f, unconstrained, case_insensitive, cells))
                }
            }
        }

        // All regex columns compile in one trip to the big stack. See `on_a_big_stack`.
        let chunked = pattern::on_a_big_stack(|| {
            regex_pending
                .iter()
                .map(|(_, _, ci, cells)| {
                    cells
                        .chunks(REGEX_CHUNK)
                        .map(|part| compile(part, *ci, n))
                        .collect::<Result<Vec<_>, _>>()
                })
                .collect::<Result<Vec<_>, _>>()
        })?;

        let mut columns = cidr_columns;
        for ((field, unconstrained, _, _), chunks) in regex_pending.into_iter().zip(chunked) {
            columns.push(Column {
                field,
                unconstrained,
                matcher: Matcher::Regex(chunks),
            });
        }

        Ok(Self {
            schema,
            lines: raw.iter().map(|r| r.line).collect(),
            columns,
        })
    }

    /// Read and compile `path`.
    ///
    /// With `allow_missing`, a file that is not there yields an empty set instead of an
    /// error. See [`file::read`] for exactly which failures that does and does not cover.
    pub fn from_file(
        path: &Path,
        schema: Arc<Schema>,
        allow_missing: bool,
    ) -> Result<Self, RuleError> {
        match file::read(path, allow_missing)? {
            Some(text) => Self::from_text(&text, schema),
            None if schema.is_empty() => Err(RuleError::NoFields),
            None => Ok(Self::empty(schema)),
        }
    }

    pub fn schema(&self) -> &Arc<Schema> {
        &self.schema
    }

    /// Number of rules.
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    /// Used by the constructor to spot an `allow_missing` cold start, and it keeps
    /// clippy::len_without_is_empty quiet.
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// Line number of the first rule, in file order, that matches `inputs`.
    ///
    /// `inputs` is indexed by field; a missing or `None` entry means no value was
    /// supplied, which only rules leaving that field out can match.
    pub fn first_match(&self, inputs: &[Option<Input>]) -> Option<usize> {
        // Every rule names at least one field, so there is always a column to start the
        // candidates off; an empty set has no columns and falls straight through.
        let mut candidates = None;
        for column in &self.columns {
            let input = inputs.get(column.field).and_then(Option::as_ref);
            candidates = Some(column.narrow(input, candidates)?);
        }
        candidates?.first().map(|r| self.lines[r])
    }
}

#[cfg(test)]
mod tests;
