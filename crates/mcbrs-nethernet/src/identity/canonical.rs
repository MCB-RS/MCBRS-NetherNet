//! Canonical JSON (subset of RFC 8785) used as the detached JWS payload.
//!
//! * object keys sorted lexicographically (by code point);
//! * no insignificant whitespace;
//! * minimal string escaping (RFC 8259).

use serde_json::Value;

use crate::sdp::Fingerprint;

/// Serializes a JSON value canonically.
pub fn to_canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|(a, _), (b, _)| a.cmp(b));
            out.push('{');
            for (i, (key, item)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, key);
                out.push(':');
                write_value(out, item);
            }
            out.push('}');
        }
    }
}

fn write_string(out: &mut String, s: &str) {
    // serde_json only escapes `"`, `\` and control characters, which is the
    // minimal escaping required by RFC 8259 / RFC 8785.
    out.push_str(&serde_json::to_string(s).expect("serializing a str cannot fail"));
}

/// Builds the canonical payload signed by the `fingerprints` detached JWS:
/// `{"fingerprint":[{"algorithm":"sha-256","digest":"..."}]}`.
pub fn fingerprint_payload(fingerprints: &[Fingerprint]) -> String {
    let value = serde_json::json!({
        "fingerprint": fingerprints
            .iter()
            .map(|f| serde_json::json!({ "algorithm": f.algorithm, "digest": f.digest }))
            .collect::<Vec<_>>()
    });
    to_canonical_json(&value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_guide_example() {
        let fps = [Fingerprint {
            algorithm: "sha-256".into(),
            digest: "4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB".into(),
        }];
        assert_eq!(
            fingerprint_payload(&fps),
            r#"{"fingerprint":[{"algorithm":"sha-256","digest":"4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB"}]}"#
        );
    }

    #[test]
    fn sorts_keys_and_strips_whitespace() {
        let v: Value =
            serde_json::from_str(r#"{ "b": [1, 2, {"z": null, "a": true}], "a": "x\"y/é" }"#)
                .unwrap();
        assert_eq!(
            to_canonical_json(&v),
            r#"{"a":"x\"y/é","b":[1,2,{"a":true,"z":null}]}"#
        );
    }

    #[test]
    fn empty_fingerprint_list() {
        assert_eq!(fingerprint_payload(&[]), r#"{"fingerprint":[]}"#);
    }
}
