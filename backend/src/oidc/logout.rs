//! RP-initiated logout (/session/end, /session/end/confirm, /session/end/success) and
//! back-channel logout to apps.

use std::net::IpAddr;

use anyhow::{Result, bail};
use axum::{
    extract::State,
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

use super::{
    OidcError, OidcResult,
    authorize::verify_id_token_hint,
    form_post,
    models::{LogoutState, Session},
    single_params,
    store::{SESSION, now, token_id},
};
use crate::{
    app::App,
    crypto::{b64url, constant_time_eq, random_token},
    http::{Out, Req},
};

/// Tells one app that a session ended (OpenID Back-Channel Logout 1.0). Fire and forget.
pub fn backchannel(app: &App, client_id: String, account_id: String, sid: String) {
    let app = app.clone();
    tokio::spawn(async move {
        if let Err(error) = send_backchannel(&app, &client_id, &account_id, &sid).await {
            tracing::warn!(client_id = %client_id, error = %format!("{error:#}"), "back-channel logout failed");
        }
    });
}

/// Anything that isn't a public unicast address: loopback, private, link-local, CGNAT, multicast,
/// "this network", and IPv6 forms that embed an IPv4 address (mapped, compatible, NAT64, 6to4).
pub fn private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || a == 0
                || (a == 100 && (64..128).contains(&b))
                || (a == 192 && b == 0 && v4.octets()[2] == 0)
                || a >= 240
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || s[0] == 0x2002
                || (s[0] == 0x64 && s[1] == 0xff9b)
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                || v6.to_ipv4_mapped().is_some_and(|v4| private(IpAddr::V4(v4)))
                || (s[..6].iter().all(|x| *x == 0)
                    && private(IpAddr::V4(std::net::Ipv4Addr::new(
                        (s[6] >> 8) as u8,
                        s[6] as u8,
                        (s[7] >> 8) as u8,
                        s[7] as u8,
                    ))))
        }
    }
}

async fn send_backchannel(app: &App, client_id: &str, account_id: &str, sid: &str) -> Result<()> {
    let Some(client) = app.clients.load(client_id).await? else {
        return Ok(());
    };
    let Some(uri) = client.backchannel_logout_uri.clone() else {
        return Ok(());
    };
    let url = url::Url::parse(&uri)?;
    // Resolve once, check every address, then connect to exactly the address that was checked, so
    // a DNS answer that changes between the check and the connection (rebinding) can't slip
    // through. Apps on the same private network as Handstamp need ALLOW_PRIVATE_NETWORKS.
    let host = url.host_str().unwrap_or_default().trim_matches(['[', ']']).to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let addrs: Vec<std::net::SocketAddr> = match host.parse::<IpAddr>() {
        Ok(ip) => vec![(ip, port).into()],
        Err(_) => tokio::net::lookup_host((host.as_str(), port)).await?.collect(),
    };
    let Some(pinned) = addrs.first().copied() else {
        bail!("{host} did not resolve")
    };
    if !app.config.allow_private_networks && addrs.iter().any(|a| private(a.ip())) {
        bail!("refusing to call a private network address (set ALLOW_PRIVATE_NETWORKS=1 to allow)");
    }
    let http = reqwest::Client::builder()
        .user_agent("Handstamp")
        .redirect(reqwest::redirect::Policy::none())
        .resolve(&host, pinned)
        .build()?;
    let iat = now();
    let signer = app.keys.signer().await?;
    let token = signer.sign(
        &json!({ "alg": crate::keys::ALG, "typ": "logout+jwt", "kid": signer.kid }),
        &json!({
            "iss": app.issuer,
            "aud": client.client_id,
            "iat": iat,
            "exp": iat + 120,
            "jti": random_token(16),
            "sub": account_id,
            "sid": sid,
            "events": { "http://schemas.openid.net/event/backchannel-logout": {} },
        }),
    )?;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("logout_token", &token)
        .finish();
    let response = http
        .post(url)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await?;
    if !response.status().is_success() {
        bail!("{} answered {}", client.client_id, response.status());
    }
    Ok(())
}

/// Ends an SSO session the way /session/end/confirm does: back-channel to every app in it, revoke
/// grants that don't persist past logout, destroy the session.
pub async fn end_session(app: &App, session: &Session, _all: bool) -> Result<()> {
    if let Some(account) = &session.account_id {
        for (client_id, authorization) in &session.authorizations {
            backchannel(app, client_id.clone(), account.clone(), authorization.sid.clone());
            if !authorization.persists_logout
                && let Some(grant) = &authorization.grant_id
            {
                app.store.revoke_grant(grant).await?;
            }
        }
    }
    if !session.new {
        app.store.destroy(SESSION, &token_id(&session.id)).await?;
    }
    Ok(())
}

const END_PARAMS: [&str; 6] = [
    "id_token_hint",
    "post_logout_redirect_uri",
    "state",
    "ui_locales",
    "client_id",
    "logout_hint",
];

fn pairs(req: &Req) -> Vec<(String, String)> {
    if req.method == Method::POST {
        req.form_pairs()
    } else {
        req.query_pairs()
    }
}

fn decode_payload(jwt: &str) -> Option<Value> {
    let part = jwt.split('.').nth(1)?;
    serde_json::from_slice(&crate::crypto::b64url_decode(part)?).ok()
}

/// GET or POST /session/end: confirm before signing out (or straight through when signed out).
pub async fn end(State(app): State<App>, req: Req) -> Response {
    let mut session = match app.load_session(&req).await {
        Ok(s) => s,
        Err(e) => return app.render_error(&e.into()).await.into_response(),
    };
    let previous = (!session.new).then(|| session.id.clone());
    let out = match end_inner(&app, &req, &mut session).await {
        Ok(out) => out,
        Err(error) => return app.render_error(&error).await.into_response(),
    };
    match app.save_session(&session, previous.as_deref()).await {
        Ok(cookies) => out.no_store().cookies(cookies).into_response(),
        Err(e) => app.render_error(&e.into()).await.into_response(),
    }
}

async fn end_inner(app: &App, req: &Req, session: &mut Session) -> OidcResult<Out> {
    let mut params = single_params(pairs(req), Some(&END_PARAMS))?;
    let mut client = None;
    if let Some(hint) = params.get("id_token_hint").cloned() {
        let payload =
            decode_payload(&hint).ok_or_else(|| OidcError::invalid_request("could not decode id_token_hint"))?;
        let aud = match &payload["aud"] {
            Value::String(aud) => aud.clone(),
            Value::Array(auds) => auds.first().and_then(Value::as_str).unwrap_or_default().to_string(),
            _ => String::new(),
        };
        if params.get("client_id").is_some_and(|id| *id != aud) {
            return Err(OidcError::invalid_request(
                "client_id does not match the provided id_token_hint",
            ));
        }
        let found = app.clients.load(&aud).await?;
        let Some(found) = found else {
            return Err(OidcError::invalid_client("unrecognized id_token_hint audience"));
        };
        verify_id_token_hint(app, &hint, &found.client_id)
            .await
            .map_err(|_| OidcError::invalid_request("could not validate id_token_hint"))?;
        client = Some(found);
    } else if let Some(id) = params.get("client_id") {
        client = app.clients.load(id).await?;
        if client.is_none() {
            return Err(OidcError::invalid_client("client is invalid"));
        }
    }
    if let Some(uri) = params.get("post_logout_redirect_uri") {
        match &client {
            Some(c) if !c.post_logout_redirect_uris.iter().any(|r| r == uri) => {
                return Err(OidcError::invalid_request("post_logout_redirect_uri not registered"));
            }
            Some(_) => {}
            None => {
                params.remove("post_logout_redirect_uri");
            }
        }
    }
    let secret = random_token(16);
    session.state = Some(LogoutState {
        secret: secret.clone(),
        client_id: client.as_ref().map(|c| c.client_id.clone()),
        state: params.get("state").cloned(),
        post_logout_redirect_uri: params.get("post_logout_redirect_uri").cloned(),
    });
    session.touched = true;
    let action = format!("{}/session/end/confirm", app.issuer);
    if session.account_id.is_none() {
        return Ok(form_post(&action, &[("xsrf", secret), ("logout", "yes".into())]));
    }
    if app.config.conformance_mode {
        // Plain form for the conformance suite's browser automation.
        let html = format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Sign out</title></head><body><form id=\"op.logoutForm\" method=\"post\" action=\"{action}\"><input type=\"hidden\" name=\"xsrf\" value=\"{secret}\"/></form><button id=\"hs-logout\" type=\"submit\" form=\"op.logoutForm\" name=\"logout\" value=\"yes\">Sign out</button></body></html>"
        );
        return Ok(Out::html(StatusCode::OK, html));
    }
    let name = client
        .as_ref()
        .map(|c| c.display_name().to_string())
        .unwrap_or_default();
    let html = app
        .shell
        .render(
            "/logout",
            &[
                ("view", "logout"),
                ("xsrf", &secret),
                ("action", &action),
                ("client", &name),
            ],
        )
        .await;
    Ok(Out::html(StatusCode::OK, html))
}

/// POST /session/end/confirm.
pub async fn confirm(State(app): State<App>, req: Req) -> Response {
    let mut session = match app.load_session(&req).await {
        Ok(s) => s,
        Err(e) => return app.render_error(&e.into()).await.into_response(),
    };
    let previous = (!session.new).then(|| session.id.clone());
    let result = confirm_inner(&app, &req, &mut session).await;
    match result {
        Ok((out, destroyed)) => {
            if destroyed {
                return out.no_store().cookie(app.clear_session_cookie()).into_response();
            }
            match app.save_session(&session, previous.as_deref()).await {
                Ok(cookies) => out.no_store().cookies(cookies).into_response(),
                Err(e) => app.render_error(&e.into()).await.into_response(),
            }
        }
        Err(error) => app.render_error(&error).await.into_response(),
    }
}

async fn confirm_inner(app: &App, req: &Req, session: &mut Session) -> OidcResult<(Out, bool)> {
    let params = single_params(req.form_pairs(), Some(&["xsrf", "logout"]))?;
    let state = session.state.clone();
    let valid = match (&state, params.get("xsrf")) {
        (Some(state), Some(xsrf)) => constant_time_eq(state.secret.as_bytes(), xsrf.as_bytes()),
        _ => false,
    };
    let Some(state) = state.filter(|_| valid) else {
        return Err(OidcError::invalid_request("could not find logout details"));
    };
    let logout_all = params.contains_key("logout");
    if let Some(account) = &session.account_id {
        for (client_id, authorization) in &session.authorizations {
            if logout_all || Some(client_id) == state.client_id.as_ref() {
                backchannel(app, client_id.clone(), account.clone(), authorization.sid.clone());
            }
        }
    }
    let mut destroyed = false;
    if logout_all {
        for authorization in session.authorizations.values() {
            if !authorization.persists_logout
                && let Some(grant) = &authorization.grant_id
            {
                app.store.revoke_grant(grant).await?;
            }
        }
        if !session.new {
            app.store.destroy(SESSION, &token_id(&session.id)).await?;
        }
        destroyed = true;
    } else if let Some(client_id) = &state.client_id {
        if let Some(authorization) = session.authorizations.remove(client_id)
            && !authorization.persists_logout
            && let Some(grant) = authorization.grant_id
        {
            app.store.revoke_grant(&grant).await?;
        }
        session.state = None;
        session.reset_identifier();
    }
    let origin = &app.issuer;
    let location = match &state.post_logout_redirect_uri {
        Some(uri) => {
            let mut url =
                url::Url::parse(uri).map_err(|_| OidcError::invalid_request("post_logout_redirect_uri is invalid"))?;
            if let Some(s) = &state.state {
                url.query_pairs_mut().append_pair("state", s);
            }
            url.to_string()
        }
        None => {
            let mut url = format!("{origin}/session/end/success");
            if !logout_all && let Some(client_id) = &state.client_id {
                url.push_str(&format!(
                    "?client_id={}",
                    url::form_urlencoded::byte_serialize(client_id.as_bytes()).collect::<String>()
                ));
            }
            url
        }
    };
    Ok((Out::see_other(&location), destroyed))
}

/// GET /session/end/success.
pub async fn success(State(app): State<App>, req: Req) -> Response {
    let name = match req.query_param("client_id") {
        Some(id) => match app.clients.load(&id).await {
            Ok(Some(client)) => client.display_name().to_string(),
            Ok(None) => {
                return app
                    .render_error(&OidcError::invalid_client("client is invalid"))
                    .await
                    .into_response();
            }
            Err(e) => return app.render_error(&e.into()).await.into_response(),
        },
        None => String::new(),
    };
    let html = app
        .shell
        .render("/signed-out", &[("view", "signed-out"), ("client", &name)])
        .await;
    Out::html(StatusCode::OK, html).no_store().into_response()
}

pub fn _jti() -> String {
    b64url(&crate::crypto::random_bytes::<16>())
}

#[cfg(test)]
mod tests {
    use super::private;

    #[test]
    fn refuses_non_public_addresses() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.1.2.3",
            "224.0.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
            "64:ff9b::a00:1",
            "2002:a00:1::",
            "::10.0.0.1",
        ] {
            assert!(private(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["93.184.216.34", "2606:4700::1111"] {
            assert!(!private(ip.parse().unwrap()), "{ip}");
        }
    }
}
