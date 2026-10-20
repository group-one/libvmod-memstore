//! Splitting a rule file into rules, before any value is compiled.

use super::{LineError, RuleError, Schema};

/// One `field: value` line of a rule.
#[derive(Debug, Clone, Copy)]
pub(super) struct Cell<'a> {
    pub(super) line: usize,
    pub(super) value: &'a str,
}

/// A rule as written, before its values are compiled. `cells` is indexed by field.
#[derive(Debug)]
pub(super) struct RawRule<'a> {
    pub(super) line: usize,
    pub(super) cells: Vec<Option<Cell<'a>>>,
}

/// Split the file into rules.
///
/// A rule is a run of `field: value` lines; a blank line ends it. Lines whose first
/// non-space character is `#` are comments and do not end a rule. Only the *first* `:`
/// splits a line -- field names cannot contain one -- so values may contain spaces,
/// colons (IPv6) and `#` freely. Names and values are trimmed.
///
/// A rule lacking a required field is reported at the rule's first line.
pub(super) fn parse_blocks<'a>(
    text: &'a str,
    schema: &Schema,
) -> Result<Vec<RawRule<'a>>, RuleError> {
    let mut rules = Vec::new();
    let mut current: Option<RawRule> = None;
    for (idx, raw) in text.lines().enumerate() {
        let line = idx + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            if let Some(rule) = current.take() {
                rules.push(finish(rule, schema)?);
            }
            continue;
        }
        if trimmed.starts_with('#') {
            continue;
        }
        let err = |source| RuleError::Line { line, source };
        let (name, value) = trimmed
            .split_once(':')
            .ok_or_else(|| err(LineError::MissingColon))?;
        let (name, value) = (name.trim(), value.trim());
        let field = schema
            .index(name)
            .ok_or_else(|| err(LineError::UnknownField(name.to_string())))?;
        // An empty regex matches everything, which is never what a blank value meant.
        if value.is_empty() {
            return Err(err(LineError::EmptyValue(name.to_string())));
        }
        let rule = current.get_or_insert_with(|| RawRule {
            line,
            cells: vec![None; schema.len()],
        });
        if rule.cells[field].is_some() {
            return Err(err(LineError::DuplicateField(name.to_string())));
        }
        rule.cells[field] = Some(Cell { line, value });
    }
    if let Some(rule) = current {
        rules.push(finish(rule, schema)?);
    }
    Ok(rules)
}

/// Check a complete rule for required fields it left out.
fn finish<'a>(rule: RawRule<'a>, schema: &Schema) -> Result<RawRule<'a>, RuleError> {
    let missing = schema
        .fields
        .iter()
        .zip(&rule.cells)
        .find(|(field, cell)| field.required && cell.is_none());
    match missing {
        Some((field, _)) => Err(RuleError::Line {
            line: rule.line,
            source: LineError::MissingRequired(field.name.clone()),
        }),
        None => Ok(rule),
    }
}
