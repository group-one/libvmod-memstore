//! The fields a rule set matches on, and the values a request supplies for them.

use std::net::IpAddr;

/// How a field compares its rule value to the value supplied at request time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The rule value is a CIDR prefix; the supplied value is an IP address.
    Cidr,
    /// The rule value is a regex, matched unanchored like VCL's `~`.
    Regex { case_insensitive: bool },
}

#[derive(Debug, Clone)]
pub struct Field {
    pub name: String,
    pub kind: Kind,
    /// Every rule must name this field. Without it, a rule that leaves it out matches
    /// any value for it.
    pub required: bool,
}

/// The fields a rule set is built from, in declaration order.
#[derive(Debug, Default, Clone)]
pub struct Schema {
    pub(super) fields: Vec<Field>,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SchemaError {
    #[error("invalid field name {0:?}: use letters, digits, '_', '-' and '.'")]
    InvalidName(String),
    #[error("field {0:?} is already defined")]
    Duplicate(String),
    #[error("unknown field type {0:?}, expected \"cidr\" or \"regex\"")]
    UnknownType(String),
    #[error("case_insensitive only applies to regex fields")]
    CaseInsensitiveCidr,
}

impl Schema {
    /// Declare a field. `kind` is the VCL-facing type name, `"cidr"` or `"regex"`.
    ///
    /// A `required` field must appear in every rule. That turns a forgotten line into a
    /// load error, instead of a rule that silently matches any value for the field.
    ///
    /// Names are restricted to a conservative character set: they appear before the `:`
    /// in the file, so a colon or whitespace in one would make the format ambiguous.
    pub fn add(
        &mut self,
        name: &str,
        kind: &str,
        case_insensitive: bool,
        required: bool,
    ) -> Result<(), SchemaError> {
        let valid = !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
        if !valid {
            return Err(SchemaError::InvalidName(name.to_string()));
        }
        if self.index(name).is_some() {
            return Err(SchemaError::Duplicate(name.to_string()));
        }
        let kind = match kind {
            "cidr" if case_insensitive => return Err(SchemaError::CaseInsensitiveCidr),
            "cidr" => Kind::Cidr,
            "regex" => Kind::Regex { case_insensitive },
            other => return Err(SchemaError::UnknownType(other.to_string())),
        };
        self.fields.push(Field {
            name: name.to_string(),
            kind,
            required,
        });
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.fields.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    pub fn index(&self, name: &str) -> Option<usize> {
        self.fields.iter().position(|f| f.name == name)
    }

    /// Turn a request-time value for field `idx` into something the matcher can use.
    ///
    /// Returns `None` for an address that does not parse: an unusable value is treated
    /// like an absent one, so only rules that leave the field out can match.
    pub fn input(&self, idx: usize, value: &[u8]) -> Option<Input> {
        match self.fields[idx].kind {
            Kind::Cidr => String::from_utf8_lossy(value)
                .trim()
                .parse()
                .ok()
                .map(Input::Ip),
            Kind::Regex { .. } => Some(Input::Text(value.into())),
        }
    }
}

/// A value supplied for one field during a request.
#[derive(Debug, Clone)]
pub enum Input {
    Ip(IpAddr),
    Text(Box<[u8]>),
}

/// The values supplied with `set()` during one task, per `rule_set` instance.
///
/// Varnish hands every method of a VMOD the same `PRIV_TASK`, so all `rule_set` objects
/// in a VCL share one of these per task. Keying the slots by owner keeps their values
/// apart; there are rarely more than a handful, so a linear scan beats a map.
#[derive(Debug, Default)]
pub struct TaskInputs {
    slots: Vec<(usize, Vec<Option<Input>>)>,
}

impl TaskInputs {
    /// The values for `owner`, created empty with room for `width` fields on first use.
    pub fn slot_mut(&mut self, owner: usize, width: usize) -> &mut [Option<Input>] {
        let pos = match self.slots.iter().position(|(o, _)| *o == owner) {
            Some(pos) => pos,
            None => {
                self.slots.push((owner, vec![None; width]));
                self.slots.len() - 1
            }
        };
        &mut self.slots[pos].1
    }

    pub fn get(&self, owner: usize) -> &[Option<Input>] {
        self.slots
            .iter()
            .find(|(o, _)| *o == owner)
            .map_or(&[], |(_, values)| values.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_rejects_bad_declarations() {
        let mut s = Schema::default();
        assert_eq!(
            s.add("", "cidr", false, false),
            Err(SchemaError::InvalidName(String::new()))
        );
        assert_eq!(
            s.add("a b", "cidr", false, false),
            Err(SchemaError::InvalidName("a b".into()))
        );
        assert_eq!(
            s.add("a:b", "regex", false, false),
            Err(SchemaError::InvalidName("a:b".into()))
        );
        assert_eq!(
            s.add("ip", "ip", false, false),
            Err(SchemaError::UnknownType("ip".into()))
        );
        assert_eq!(
            s.add("ip", "cidr", true, false),
            Err(SchemaError::CaseInsensitiveCidr)
        );
        s.add("req.http.user-agent", "regex", false, false).unwrap();
        assert_eq!(
            s.add("req.http.user-agent", "cidr", false, false),
            Err(SchemaError::Duplicate("req.http.user-agent".into()))
        );
    }

    #[test]
    fn task_inputs_are_kept_per_owner() {
        let mut t = TaskInputs::default();
        t.slot_mut(1, 2)[0] = Some(Input::Text("a".as_bytes().into()));
        t.slot_mut(2, 1)[0] = Some(Input::Text("b".as_bytes().into()));
        assert!(matches!(&t.get(1)[0], Some(Input::Text(v)) if &**v == b"a"));
        assert!(matches!(&t.get(2)[0], Some(Input::Text(v)) if &**v == b"b"));
        assert_eq!(t.get(1).len(), 2);
        assert!(t.get(3).is_empty());
    }
}
