//! Request plumbing shared by every route: the request context, client IP behind trusted proxies,
//! cookies, same-origin checks, rate limits and JSON errors.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, FromRequest, Request},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

use crate::{app::App, config::TrustProxy};

/// Long enough for consent and WebAuthn payloads, small enough to refuse junk.
pub const BODY_LIMIT: usize = 64 * 1024;
pub const CSRF_HEADER: &str = "x-handstamp-csrf";

/// Everything a handler needs from the request, with the body already read.
pub struct Req {
    pub method: Method,
    pub path: String,
    pub query: Option<String>,
    pub headers: HeaderMap,
    pub ip: IpAddr,
    pub cookies: HashMap<String, String>,
    pub body: Bytes,
}

impl FromRequest<App> for Req {
    type Rejection = Response;

    async fn from_request(req: Request, app: &App) -> Result<Self, Self::Rejection> {
        let peer = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip())
            .unwrap_or(IpAddr::from([127, 0, 0, 1]));
        let (parts, body) = req.into_parts();
        let ip = client_ip(&app.config.trust_proxy, peer, &parts.headers);
        let body = axum::body::to_bytes(body, BODY_LIMIT).await.map_err(|_| {
            ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "too_large", "That request is too large.").into_response()
        })?;
        Ok(Req {
            method: parts.method,
            path: parts.uri.path().to_string(),
            query: parts.uri.query().map(str::to_string),
            cookies: parse_cookies(&parts.headers),
            headers: parts.headers,
            ip,
            body,
        })
    }
}

impl Req {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    pub fn cookie(&self, name: &str) -> Option<&str> {
        self.cookies.get(name).map(String::as_str).filter(|v| !v.is_empty())
    }

    pub fn query_pairs(&self) -> Vec<(String, String)> {
        url::form_urlencoded::parse(self.query.as_deref().unwrap_or_default().as_bytes()).into_owned().collect()
    }

    pub fn query_param(&self, name: &str) -> Option<String> {
        self.query_pairs().into_iter().find(|(k, _)| k == name).map(|(_, v)| v)
    }

    pub fn is_form(&self) -> bool {
        self.header("content-type").is_some_and(|ct| ct.starts_with("application/x-www-form-urlencoded"))
    }

    pub fn form_pairs(&self) -> Vec<(String, String)> {
        if !self.is_form() {
            return Vec::new();
        }
        url::form_urlencoded::parse(&self.body).into_owned().collect()
    }

    /// The JSON body, or an empty object when there is none (`{}` and no body mean the same).
    pub fn json(&self) -> Value {
        if self.body.is_empty() {
            return json!({});
        }
        serde_json::from_slice(&self.body).unwrap_or_else(|_| json!({}))
    }

    /// The URL as the browser saw it (path and query), for callbacks.
    pub fn path_and_query(&self) -> String {
        match &self.query {
            Some(q) => format!("{}?{q}", self.path),
            None => self.path.clone(),
        }
    }

    pub fn user_agent(&self) -> Option<&str> {
        self.header("user-agent")
    }

    /// State-changing requests must come from our own pages: the Origin must be the issuer, or,
    /// when a browser omits it, Sec-Fetch-Site must say same-origin (S5).
    pub fn same_origin(&self, issuer_origin: &str) -> bool {
        match self.header("origin") {
            Some(origin) => origin == issuer_origin,
            None => self.header("sec-fetch-site") == Some("same-origin"),
        }
    }
}

/// The client address. Never "trust everyone": X-Forwarded-For counts only through trusted hops.
pub fn client_ip(trust: &TrustProxy, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
    let forwarded: Vec<IpAddr> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|v| v.trim().parse().ok())
        .collect();
    match trust {
        TrustProxy::Off => peer,
        // Hop count: the address `hops` entries in from the right, counting the peer as one.
        TrustProxy::Hops(hops) => {
            let mut chain = forwarded.clone();
            chain.push(peer);
            let index = chain.len().saturating_sub(1 + hops);
            chain.get(index).copied().unwrap_or(peer)
        }
        // Address list: walk back from the peer while the hop is trusted.
        TrustProxy::Addrs(nets) => {
            let trusted = |ip: &IpAddr| nets.iter().any(|n| n.contains(ip));
            if !trusted(&peer) {
                return peer;
            }
            let mut current = peer;
            for ip in forwarded.iter().rev() {
                current = *ip;
                if !trusted(ip) {
                    break;
                }
            }
            current
        }
    }
}

pub fn parse_cookies(headers: &HeaderMap) -> HashMap<String, String> {
    let mut cookies = HashMap::new();
    for value in headers.get_all(header::COOKIE).iter().filter_map(|v| v.to_str().ok()) {
        for pair in value.split(';') {
            if let Some((name, value)) = pair.trim().split_once('=') {
                cookies.entry(name.trim().to_string()).or_insert_with(|| value.trim().to_string());
            }
        }
    }
    cookies
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    Lax,
    None,
}

#[derive(Clone)]
pub struct CookieOptions {
    pub path: String,
    pub max_age: Option<i64>,
    pub same_site: SameSite,
    pub secure: bool,
}

impl CookieOptions {
    pub fn lax(path: impl Into<String>, secure: bool, max_age: Option<i64>) -> Self {
        Self { path: path.into(), max_age, same_site: SameSite::Lax, secure }
    }
}

/// Set-Cookie for an HttpOnly cookie. Values are base64url or URL-safe tokens, never raw input.
pub fn set_cookie(name: &str, value: &str, options: &CookieOptions) -> String {
    let mut cookie = format!("{name}={value}; Path={}", options.path);
    if let Some(max_age) = options.max_age {
        let expires = chrono::Utc::now() + chrono::Duration::seconds(max_age);
        cookie.push_str(&format!("; Max-Age={max_age}; Expires={}", expires.format("%a, %d %b %Y %H:%M:%S GMT")));
    }
    cookie.push_str("; HttpOnly");
    cookie.push_str(match options.same_site {
        SameSite::Lax => "; SameSite=Lax",
        SameSite::None => "; SameSite=None",
    });
    if options.secure {
        cookie.push_str("; Secure");
    }
    cookie
}

pub fn clear_cookie(name: &str, options: &CookieOptions) -> String {
    let mut cookie =
        format!("{name}=; Path={}; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly", options.path);
    cookie.push_str(match options.same_site {
        SameSite::Lax => "; SameSite=Lax",
        SameSite::None => "; SameSite=None",
    });
    if options.secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// A response under construction: status, headers, cookies, body.
pub struct Out {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub cookies: Vec<String>,
    pub body: Body,
}

impl Out {
    pub fn new(status: StatusCode) -> Self {
        Self { status, headers: HeaderMap::new(), cookies: Vec::new(), body: Body::empty() }
    }

    pub fn json(status: StatusCode, value: &Value) -> Self {
        let mut out = Self::new(status);
        out.headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
        out.body = Body::from(value.to_string());
        out
    }

    pub fn html(status: StatusCode, html: String) -> Self {
        let mut out = Self::new(status);
        out.headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
        out.body = Body::from(html);
        out
    }

    pub fn redirect(status: StatusCode, location: &str) -> Self {
        let mut out = Self::new(status);
        if let Ok(value) = HeaderValue::from_str(location) {
            out.headers.insert(header::LOCATION, value);
        }
        out
    }

    pub fn see_other(location: &str) -> Self {
        Self::redirect(StatusCode::SEE_OTHER, location)
    }

    pub fn header(mut self, name: header::HeaderName, value: &str) -> Self {
        if let Ok(value) = HeaderValue::from_str(value) {
            self.headers.insert(name, value);
        }
        self
    }

    pub fn no_store(self) -> Self {
        self.header(header::CACHE_CONTROL, "no-store")
    }

    pub fn cookie(mut self, cookie: String) -> Self {
        self.cookies.push(cookie);
        self
    }

    pub fn cookies(mut self, cookies: impl IntoIterator<Item = String>) -> Self {
        self.cookies.extend(cookies);
        self
    }
}

impl IntoResponse for Out {
    fn into_response(self) -> Response {
        let mut response = Response::new(self.body);
        *response.status_mut() = self.status;
        *response.headers_mut() = self.headers;
        for cookie in self.cookies {
            if let Ok(value) = HeaderValue::from_str(&cookie) {
                response.headers_mut().append(header::SET_COOKIE, value);
            }
        }
        response
    }
}

/// JSON errors for the console, interaction and admin APIs: what happened, what to do next.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub extra: Value,
    pub cookies: Vec<String>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self { status, code, message: message.into(), extra: json!({}), cookies: Vec::new() }
    }

    pub fn with(mut self, extra: Value) -> Self {
        self.extra = extra;
        self
    }

    pub fn server() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Something went wrong on our side. Try again in a moment.",
        )
    }

    pub fn rate_limited() -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "Too many attempts. Wait a minute and try again.")
    }

    pub fn not_found(what: &str) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", format!("That {what} no longer exists."))
    }

    pub fn csrf() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "csrf",
            "We blocked this request because it did not come from this page. Reload and try again.",
        )
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        tracing::error!(error = %format!("{error:#}"), "request failed");
        Self::server()
    }
}

impl From<tokio_postgres::Error> for ApiError {
    fn from(error: tokio_postgres::Error) -> Self {
        anyhow::Error::from(error).into()
    }
}

impl From<deadpool_postgres::PoolError> for ApiError {
    fn from(error: deadpool_postgres::PoolError) -> Self {
        anyhow::Error::from(error).into()
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = json!({ "error": self.code, "message": self.message });
        if let (Some(target), Some(extra)) = (body.as_object_mut(), self.extra.as_object()) {
            for (k, v) in extra {
                target.insert(k.clone(), v.clone());
            }
        }
        Out::json(self.status, &body).cookies(self.cookies).into_response()
    }
}

pub type ApiResult<T = Out> = Result<T, ApiError>;

/// Every rate limit in one place (S7). `scale` multiplies them all: 1 in production; the
/// conformance stack raises it because the whole suite runs from a single IP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Limit {
    Token,
    Authorization,
    Interaction,
    Setup,
}

impl Limit {
    fn budget(self, scale: f64) -> (u32, Duration) {
        let per = |max: f64| (max * scale).ceil() as u32;
        match self {
            Limit::Token => (per(120.0), Duration::from_secs(60)),
            Limit::Authorization => (per(60.0), Duration::from_secs(60)),
            Limit::Interaction => (per(30.0), Duration::from_secs(60)),
            // Guessing a 100-bit setup code is hopeless anyway; this keeps the logs quiet.
            Limit::Setup => (per(5.0), Duration::from_secs(15 * 60)),
        }
    }
}

/// Fixed windows per (route, client IP), in memory: one process per instance. Like
/// @fastify/rate-limit, each route template has its own budget.
pub struct RateLimiter {
    scale: f64,
    windows: Mutex<HashMap<(Limit, String, IpAddr), (Instant, u32)>>,
}

/// The route template for a path: interaction and resume IDs don't make a new bucket.
fn route_key(path: &str) -> String {
    let mut parts: Vec<&str> = path.split('/').collect();
    if parts.len() > 2 && matches!(parts[1], "interaction" | "auth") {
        parts[2] = ":uid";
    }
    parts.join("/")
}

impl RateLimiter {
    pub fn new(scale: f64) -> Arc<Self> {
        Arc::new(Self { scale, windows: Mutex::new(HashMap::new()) })
    }

    /// True when this request is within budget.
    pub fn check(&self, limit: Limit, path: &str, ip: IpAddr) -> bool {
        let (max, window) = limit.budget(self.scale);
        let now = Instant::now();
        let mut windows = self.windows.lock().unwrap();
        if windows.len() > 100_000 {
            windows.retain(|_, (start, _)| now.duration_since(*start) < Duration::from_secs(15 * 60));
        }
        let entry = windows.entry((limit, route_key(path), ip)).or_insert((now, 0));
        if now.duration_since(entry.0) >= window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= max
    }

    pub fn guard(&self, limit: Limit, path: &str, ip: IpAddr) -> Result<(), ApiError> {
        if self.check(limit, path, ip) { Ok(()) } else { Err(ApiError::rate_limited()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_trust_proxy;

    fn headers(xff: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_str(xff).unwrap());
        h
    }

    #[test]
    fn ignores_forwarded_for_unless_trusted() {
        let peer: IpAddr = "10.0.0.2".parse().unwrap();
        let h = headers("1.2.3.4");
        assert_eq!(client_ip(&TrustProxy::Off, peer, &h), peer);
        assert_eq!(client_ip(&parse_trust_proxy("10.0.0.0/8").unwrap(), peer, &h), "1.2.3.4".parse::<IpAddr>().unwrap());
        assert_eq!(client_ip(&parse_trust_proxy("1").unwrap(), peer, &h), "1.2.3.4".parse::<IpAddr>().unwrap());
        // An untrusted peer can't claim a forwarded address.
        let stranger: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(client_ip(&parse_trust_proxy("10.0.0.0/8").unwrap(), stranger, &h), stranger);
        // A spoofed left-most entry doesn't win over the first untrusted hop.
        let spoofed = headers("6.6.6.6, 1.2.3.4");
        assert_eq!(
            client_ip(&parse_trust_proxy("10.0.0.0/8").unwrap(), peer, &spoofed),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn rate_limits_per_ip() {
        let limiter = RateLimiter::new(1.0);
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        let allowed = (0..35).filter(|i| limiter.check(Limit::Interaction, &format!("/interaction/{i}/details"), ip)).count();
        assert_eq!(allowed, 30);
        assert!(limiter.check(Limit::Interaction, "/interaction/x/details", "2.2.2.2".parse().unwrap()));
        assert!(limiter.check(Limit::Interaction, "/interaction/x/consent", ip));
        assert!(limiter.check(Limit::Token, "/token", ip));
    }

    #[test]
    fn cookies_round_trip() {
        let set = set_cookie("hs_session", "abc", &CookieOptions::lax("/", true, Some(60)));
        assert!(set.starts_with("hs_session=abc; Path=/; Max-Age=60; Expires="));
        assert!(set.ends_with("; HttpOnly; SameSite=Lax; Secure"));
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_static("a=1; hs_session=abc"));
        assert_eq!(parse_cookies(&h)["hs_session"], "abc");
    }
}
