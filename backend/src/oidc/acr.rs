//! Authentication Context Class References (R11). Two levels, both derived from the session's
//! `amr`, so nothing new is stored:
//!
//! - `phr`: a passkey sign-in (phishing-resistant, OpenID EAP ACR Values).
//! - `0`: anything else (an upstream provider or the dev test account). Handstamp can't vouch for
//!   how the upstream authenticated, so it claims nothing (OIDC Core §2, level 0).
//!
//! A higher level satisfies a request for a lower one. When an app asks for levels through
//! `acr_values` or the `claims` parameter (`id_token.acr` with `value` or `values`), and the
//! session is below the lowest level asked for, the person signs in again. Values Handstamp doesn't
//! know are ignored; a request with none it knows proceeds as if there were none.

use std::collections::BTreeMap;

use serde_json::Value;

use super::RequestedClaims;

pub const PHR: &str = "phr";
pub const BASIC: &str = "0";

/// What discovery advertises, strongest first.
pub const SUPPORTED: [&str; 2] = [PHR, BASIC];

fn level(acr: &str) -> Option<u8> {
    match acr {
        PHR => Some(1),
        BASIC => Some(0),
        _ => None,
    }
}

/// The acr a sign-in with these methods earns.
pub fn of(amr: Option<&[String]>) -> &'static str {
    if amr.is_some_and(|a| a.iter().any(|m| m == "pop")) {
        PHR
    } else {
        BASIC
    }
}

/// The lowest supported level the request asks for, if it asks for any.
pub fn required(params: &BTreeMap<String, String>) -> Option<u8> {
    let mut values: Vec<String> = params
        .get("acr_values")
        .map(|v| v.split(' ').filter(|s| !s.is_empty()).map(str::to_string).collect())
        .unwrap_or_default();
    let claims = RequestedClaims::from_value(
        params
            .get("claims")
            .and_then(|c| serde_json::from_str::<Value>(c).ok())
            .as_ref(),
    );
    if let Some(acr) = claims.id_token.get("acr").and_then(Value::as_object) {
        if let Some(value) = acr.get("value").and_then(Value::as_str) {
            values.push(value.to_string());
        }
        if let Some(list) = acr.get("values").and_then(Value::as_array) {
            values.extend(list.iter().filter_map(Value::as_str).map(str::to_string));
        }
    }
    values.iter().filter_map(|v| level(v)).min()
}

/// Whether a session signed in with `amr` meets what the request asks for.
pub fn satisfied(amr: Option<&[String]>, params: &BTreeMap<String, String>) -> bool {
    required(params).is_none_or(|needed| level(of(amr)).is_some_and(|have| have >= needed))
}

/// The request can only be met by a passkey sign-in.
pub fn needs_passkey(params: &BTreeMap<String, String>) -> bool {
    required(params).is_some_and(|needed| needed >= 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn passkey() -> Vec<String> {
        ["pop", "user", "mfa"].map(String::from).to_vec()
    }

    #[test]
    fn passkey_sign_ins_are_phishing_resistant() {
        assert_eq!(of(Some(&passkey())), PHR);
        assert_eq!(of(None), BASIC);
        assert_eq!(of(Some(&[])), BASIC);
    }

    #[test]
    fn the_lowest_requested_level_wins() {
        assert_eq!(required(&params(&[("acr_values", "phr 0")])), Some(0));
        assert_eq!(required(&params(&[("acr_values", "phr")])), Some(1));
        assert!(satisfied(None, &params(&[("acr_values", "phr 0")])));
        assert!(!satisfied(None, &params(&[("acr_values", "phr")])));
        assert!(satisfied(Some(&passkey()), &params(&[("acr_values", "0")])));
    }

    #[test]
    fn unknown_values_are_ignored() {
        assert_eq!(required(&params(&[("acr_values", "urn:example:gold 2")])), None);
        assert!(satisfied(None, &params(&[("acr_values", "urn:example:gold")])));
        assert!(!satisfied(None, &params(&[("acr_values", "urn:example:gold phr")])));
    }

    #[test]
    fn the_claims_parameter_counts_too() {
        let claims = r#"{"id_token":{"acr":{"essential":true,"values":["phr"]}}}"#;
        assert!(needs_passkey(&params(&[("claims", claims)])));
        let claims = r#"{"id_token":{"acr":{"value":"0"}}}"#;
        assert!(!needs_passkey(&params(&[("claims", claims)])));
        assert!(!needs_passkey(&params(&[])));
    }
}
