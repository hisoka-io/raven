//! JSON values that keep member order and print the way `JSON.stringify` does, so a recorded
//! upstream body re-serializes to its own bytes. `serde_json::Value` sorts object keys.

use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Json {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    pub(crate) fn parse(bytes: &[u8]) -> serde_json::Result<Self> {
        serde_json::from_slice(bytes)
    }

    pub(crate) fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub(crate) fn get_mut(&mut self, key: &str) -> Option<&mut Self> {
        match self {
            Self::Object(members) => members.iter_mut().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Replaces in place, so the member keeps its position; appends otherwise.
    pub(crate) fn set(&mut self, key: &str, value: Self) {
        if let Self::Object(members) = self {
            match members.iter_mut().find(|(k, _)| k == key) {
                Some((_, slot)) => *slot = value,
                None => members.push((key.to_owned(), value)),
            }
        }
    }

    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Number(n) => n.as_f64(),
            _ => None,
        }
    }

    pub(crate) fn is_object(&self) -> bool {
        matches!(self, Self::Object(_))
    }

    /// JavaScript truthiness.
    pub(crate) fn is_truthy(&self) -> bool {
        match self {
            Self::Null => false,
            Self::Bool(b) => *b,
            Self::Number(n) => n.as_f64().is_some_and(|v| v != 0.0),
            Self::String(s) => !s.is_empty(),
            Self::Array(_) | Self::Object(_) => true,
        }
    }

    pub(crate) fn from_u64(v: u64) -> Self {
        Self::Number(v.into())
    }

    pub(crate) fn write(&self, out: &mut String) {
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(true) => out.push_str("true"),
            Self::Bool(false) => out.push_str("false"),
            Self::Number(n) => write_number(n, out),
            Self::String(s) => write_string(s, out),
            Self::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Self::Object(members) => {
                out.push('{');
                for (i, (key, value)) in members.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_string(key, out);
                    out.push(':');
                    value.write(out);
                }
                out.push('}');
            }
        }
    }
}

/// JavaScript prints an integral double without a fraction or exponent below 1e21.
fn write_number(n: &serde_json::Number, out: &mut String) {
    use std::fmt::Write as _;
    if n.is_u64() || n.is_i64() {
        let _ = write!(out, "{n}");
        return;
    }
    match n.as_f64() {
        Some(0.0) => out.push('0'),
        Some(v) if v.fract() == 0.0 && v.abs() < 1e21 => {
            let _ = write!(out, "{v:.0}");
        }
        _ => {
            let _ = write!(out, "{n}");
        }
    }
}

/// `JSON.stringify` string escaping: the two mandatory escapes, the five short forms, and
/// `\u00xx` for the other control characters.
pub(crate) fn write_string(s: &str, out: &mut String) {
    use std::fmt::Write as _;
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

impl<'de> Deserialize<'de> for Json {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(JsonVisitor)
    }
}

struct JsonVisitor;

impl<'de> Visitor<'de> for JsonVisitor {
    type Value = Json;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Json, E> {
        Ok(Json::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Json, E> {
        Ok(Json::Number(v.into()))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Json, E> {
        Ok(Json::Number(v.into()))
    }

    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Json, E> {
        serde_json::Number::from_f64(v)
            .map(Json::Number)
            .ok_or_else(|| E::custom(format!("non-finite number {v}")))
    }

    fn visit_str<E>(self, v: &str) -> Result<Json, E> {
        Ok(Json::String(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Json, E> {
        Ok(Json::String(v))
    }

    fn visit_unit<E>(self) -> Result<Json, E> {
        Ok(Json::Null)
    }

    fn visit_none<E>(self) -> Result<Json, E> {
        Ok(Json::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Json, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(Json::Array(items))
    }

    // `JSON.parse` keeps a repeated key at its first position with its last value.
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Json, A::Error> {
        let mut object = Json::Object(Vec::new());
        while let Some((key, value)) = map.next_entry::<String, Json>()? {
            object.set(&key, value);
        }
        Ok(object)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(text: &str) -> String {
        let mut out = String::new();
        Json::parse(text.as_bytes()).expect("parse").write(&mut out);
        out
    }

    #[test]
    fn compact_body_prints_back_to_its_own_bytes() {
        let body = &r#"{"z":1,"a":{"y":[true,false,null],"b":-7},"s":"q\"\\\n\u0001NON_ASCII","n":18446744073709551615,"f":1.5}"#.replace("NON_ASCII", "\u{e9}");
        assert_eq!(round_trip(body), *body);
    }

    #[test]
    fn integral_doubles_print_as_javascript_does() {
        assert_eq!(
            round_trip(r#"{"id":5.0,"z":-0.0,"e":1e3}"#),
            r#"{"id":5,"z":0,"e":1000}"#
        );
    }

    #[test]
    fn repeated_key_keeps_first_position_and_last_value() {
        assert_eq!(round_trip(r#"{"a":1,"b":2,"a":3}"#), r#"{"a":3,"b":2}"#);
    }
}
