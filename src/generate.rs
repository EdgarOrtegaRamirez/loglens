//! Log generation module — produces realistic mock log files for testing pipelines.
//!
//! Supports multiple output formats, simulated services, configurable levels,
//! correlation IDs, time ranges, and rate limiting.

use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use uuid::Uuid;

/// Configuration for log generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateConfig {
    /// Output format
    pub format: String,
    /// Number of log lines to generate
    pub count: u64,
    /// Lines per second (rate limit, 0 = unlimited)
    pub rate: u64,
    /// Time range start (ISO 8601)
    pub start: Option<String>,
    /// Time range end (ISO 8601)
    pub end: Option<String>,
    /// Correlation ID prefix (empty = no correlation IDs)
    pub correlation_prefix: Option<String>,
    /// YAML config overrides for service weights, level weights, etc.
    pub extra: Option<HashMap<String, String>>,
}

impl Default for GenerateConfig {
    fn default() -> Self {
        Self {
            format: "json".to_string(),
            count: 100,
            rate: 0,
            start: None,
            end: None,
            correlation_prefix: None,
            extra: None,
        }
    }
}

/// A simulated service source.
#[derive(Debug, Clone)]
pub struct Service {
    pub name: &'static str,
    pub weight: u32,
    pub messages: &'static [&'static str],
    pub level_weights: &'static [(u32, u32)], // (weight, log_level_numeric)
}

/// Numeric log level for weighted selection.
const LEVEL_TRACE: u32 = 0;
const LEVEL_DEBUG: u32 = 1;
const LEVEL_INFO: u32 = 2;
const LEVEL_WARN: u32 = 3;
const LEVEL_ERROR: u32 = 4;
const LEVEL_FATAL: u32 = 5;

fn level_name(l: u32) -> &'static str {
    match l {
        0 => "TRACE",
        1 => "DEBUG",
        2 => "INFO",
        3 => "WARN",
        4 => "ERROR",
        5 => "FATAL",
        _ => "INFO",
    }
}

/// Service definitions with realistic log messages.
const SERVICES: &[Service] = &[
    Service {
        name: "api-gateway",
        weight: 30,
        messages: &[
            "Request processed in {dur}ms — {method} {path} → {status}",
            "Rate limit exceeded for client {client} ({limit} req/min)",
            "Request routing failed: no upstream for {path}",
            "Upstream {upstream} healthy — latency {lat}ms",
            "TLS handshake completed — {version}, cipher {cipher}",
            "WebSocket connection {action}: client {client}",
            "Request validation failed: {field} is {reason}",
            "Response compressed: {size} bytes → {compressed} bytes ({ratio}%)",
            "Circuit breaker opened for {upstream} — health check failed",
            "Authentication token refreshed for user {user}",
        ],
        level_weights: &[
            (5, LEVEL_TRACE),
            (20, LEVEL_DEBUG),
            (50, LEVEL_INFO),
            (17, LEVEL_WARN),
            (7, LEVEL_ERROR),
            (1, LEVEL_FATAL),
        ],
    },
    Service {
        name: "auth-service",
        weight: 15,
        messages: &[
            "User {user} authenticated via {auth_method} from {ip}",
            "Login failed for {user}: {reason}",
            "Session created for user {user} — expires in {hours}h",
            "Password reset requested for {email}",
            "OAuth2 token exchange: provider={provider}, scope={scope}",
            "MFA challenge sent to {channel}: {address}",
            "SSO assertion validation: {issuer} → {outcome}",
            "Account locked for {user} — {attempts} failed attempts",
            "Role assignment: user={user}, role={role}",
            "JWT key rotation completed — new key {kid}",
        ],
        level_weights: &[
            (5, LEVEL_TRACE),
            (10, LEVEL_DEBUG),
            (45, LEVEL_INFO),
            (25, LEVEL_WARN),
            (13, LEVEL_ERROR),
            (2, LEVEL_FATAL),
        ],
    },
    Service {
        name: "user-service",
        weight: 12,
        messages: &[
            "User profile updated for {user}: {field}={value}",
            "User {user} registered via {method}",
            "Account deletion requested for user {user} — scheduled for {date}",
            "User search: query=\"{query}\", results={count}",
            "Preferences saved for user {user}: {prefs}",
            "Profile picture uploaded: {size} bytes, dimensions {w}x{h}",
            "Email verification completed for {email}",
            "Subscription plan changed: {user} → {plan}",
            "User {user} logged in from new device ({device})",
            "Export request for user {user}: {export_type}",
        ],
        level_weights: &[
            (3, LEVEL_TRACE),
            (12, LEVEL_DEBUG),
            (55, LEVEL_INFO),
            (20, LEVEL_WARN),
            (9, LEVEL_ERROR),
            (1, LEVEL_FATAL),
        ],
    },
    Service {
        name: "order-service",
        weight: 18,
        messages: &[
            "Order {order} created — {items} items, total ${total}",
            "Payment processed for order {order}: ${amount} via {method}",
            "Order {order} status changed: {old} → {new}",
            "Inventory check: {sku} — available={avail}, reserved={reserved}",
            "Shipping label generated for order {order}: carrier={carrier}",
            "Refund initiated for order {order}: ${amount} — reason: {reason}",
            "Order {order} cancelled by {actor}",
            "Fraud check on order {order}: {result} (score={score})",
            "Invoice generated for order {order}: invoice #{inv}",
            "Order validation failed: {field} — {details}",
        ],
        level_weights: &[
            (3, LEVEL_TRACE),
            (10, LEVEL_DEBUG),
            (52, LEVEL_INFO),
            (22, LEVEL_WARN),
            (11, LEVEL_ERROR),
            (2, LEVEL_FATAL),
        ],
    },
    Service {
        name: "payment-service",
        weight: 10,
        messages: &[
            "Transaction {txn}: {amount} {currency} from {from} to {to} — {outcome}",
            "Card charge {result}: {amount} on card {last4} ({brand})",
            "Payout initiated: {amount} to {recipient} via {method}",
            "Transaction declined: {reason} (code={code})",
            "Chargeback received: transaction {txn}, amount {amount}, reason={reason}",
            "Refund processed: {amount} to {customer} for order {order}",
            "Currency conversion: {from_amt} {from_ccy} → {to_amt} {to_ccy} (rate={rate})",
            "Recurring billing executed for subscription {sub}: ${amount}",
            "Wallet balance changed: user={user}, {delta}, new={balance}",
            "Payment gateway {gateway} response time: {lat}ms",
        ],
        level_weights: &[
            (2, LEVEL_TRACE),
            (8, LEVEL_DEBUG),
            (48, LEVEL_INFO),
            (25, LEVEL_WARN),
            (15, LEVEL_ERROR),
            (2, LEVEL_FATAL),
        ],
    },
    Service {
        name: "cache-service",
        weight: 8,
        messages: &[
            "Cache {op} for key={key}: {result} ({dur}ms)",
            "Cache eviction: key={key} (policy={policy}, size={size})",
            "Cache cluster sync: node={node}, keys={count}, lag={lag}s",
            "Cache hit ratio: {ratio}% ({hits}/{total})",
            "Cache warmup started for keyset={keyset}",
            "Cache invalidation: pattern={pattern}, keys_affected={count}",
            "Redis connection {state}: {endpoint}",
            "Cache serialization error: key={key}, type={type}",
            "Memcache pool status: active={active}, idle={idle}, max={max}",
            "Cache TTL extended for {key}: {old}s → {new}s",
        ],
        level_weights: &[
            (8, LEVEL_TRACE),
            (20, LEVEL_DEBUG),
            (50, LEVEL_INFO),
            (15, LEVEL_WARN),
            (6, LEVEL_ERROR),
            (1, LEVEL_FATAL),
        ],
    },
    Service {
        name: "db-service",
        weight: 7,
        messages: &[
            "Query executed in {dur}ms: {query_prefix}",
            "Connection pool: active={active}, idle={idle}, waiting={waiting}",
            "Slow query detected: {query_prefix} ({dur}ms, {rows} rows)",
            "Migration {migration} {outcome} ({dur}ms)",
            "Deadlock detected: transaction {txn} rolled back",
            "Replica lag: {lag}s behind primary ({primary_lsn} → {replica_lsn})",
            "Table {table} index rebuild completed ({dur}ms)",
            "Connection timeout: {host}:{port} — retry {attempt}/{max}",
            "Transaction {txn} committed: {statements} statements, {dur}ms",
            "Backup completed: {table}, {size} MB, {dur}s",
        ],
        level_weights: &[
            (5, LEVEL_TRACE),
            (15, LEVEL_DEBUG),
            (45, LEVEL_INFO),
            (22, LEVEL_WARN),
            (11, LEVEL_ERROR),
            (2, LEVEL_FATAL),
        ],
    },
];

fn weighted_service_index(rng: &mut impl Rng) -> usize {
    let total: u32 = SERVICES.iter().map(|s| s.weight).sum();
    let roll: u32 = rng.random_range(0..total);
    let mut cumulative = 0;
    for (i, service) in SERVICES.iter().enumerate() {
        cumulative += service.weight;
        if roll < cumulative {
            return i;
        }
    }
    0
}

fn weighted_level(service: &Service, rng: &mut impl Rng) -> u32 {
    let total: u32 = service.level_weights.iter().map(|(w, _)| w).sum();
    if total == 0 {
        return LEVEL_INFO;
    }
    let roll: u32 = rng.random_range(0..total);
    let mut cumulative = 0;
    for &(w, level) in service.level_weights {
        cumulative += w;
        if roll < cumulative {
            return level;
        }
    }
    LEVEL_INFO
}

fn random_int(rng: &mut impl Rng, min: i64, max: i64) -> i64 {
    rng.random_range(min..=max)
}

fn random_float(rng: &mut impl Rng, min: f64, max: f64) -> f64 {
    let val = min + (max - min) * rng.random::<f64>();
    (val * 100.0).round() / 100.0
}

fn random_str(rng: &mut impl Rng, len: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    (0..len)
        .map(|_| CHARSET[rng.random_range(0..CHARSET.len())] as char)
        .collect()
}

fn random_path(rng: &mut impl Rng) -> String {
    const PATHS: &[&str] = &[
        "/api/v1/users",
        "/api/v1/orders",
        "/api/v1/products",
        "/api/v1/auth/login",
        "/api/v1/auth/refresh",
        "/api/v1/payments",
        "/api/v1/checkout",
        "/api/v1/search",
        "/api/v1/notifications",
        "/api/v2/inventory",
        "/health",
        "/metrics",
        "/api/v1/webhooks/stripe",
        "/api/v1/webhooks/github",
        "/api/v1/export",
    ];
    PATHS[rng.random_range(0..PATHS.len())].to_string()
}

fn random_method(rng: &mut impl Rng) -> &'static str {
    const METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE", "PATCH"];
    METHODS[rng.random_range(0..METHODS.len())]
}

fn random_status(rng: &mut impl Rng) -> u16 {
    const STATUSES: &[(u16, u32)] = &[
        (200, 400),
        (201, 80),
        (204, 30),
        (301, 10),
        (302, 15),
        (400, 50),
        (401, 40),
        (403, 20),
        (404, 35),
        (409, 15),
        (422, 20),
        (429, 25),
        (500, 25),
        (502, 10),
        (503, 15),
        (504, 10),
    ];
    let total: u32 = STATUSES.iter().map(|(_, w)| w).sum();
    let roll: u32 = rng.random_range(0..total);
    let mut cumulative = 0;
    for &(status, weight) in STATUSES {
        cumulative += weight;
        if roll < cumulative {
            return status;
        }
    }
    200
}

fn fill_template(template: &str, rng: &mut impl Rng) -> String {
    let mut result = String::with_capacity(template.len() + 32);
    let mut i = 0;
    let chars: Vec<char> = template.chars().collect();
    let len = chars.len();

    while i < len {
        if chars[i] == '{' {
            let end = chars[i..]
                .iter()
                .position(|&c| c == '}')
                .map(|p| i + p + 1)
                .unwrap_or(len);
            let key: String = chars[i + 1..end - 1].iter().collect();
            let value = match key.as_str() {
                "dur" | "lat" | "latency" | "lag" => random_int(rng, 1, 5000).to_string(),
                "method" => random_method(rng).to_string(),
                "path" => random_path(rng),
                "status" => random_status(rng).to_string(),
                "client" | "user" | "from" | "to" | "customer" | "actor" | "recipient" => {
                    format!("user_{}", random_str(rng, 8))
                }
                "upstream" => format!("svc-{}-{}", random_str(rng, 4), random_int(rng, 1, 99)),
                "version" => format!("TLSv1.{}", rng.random_range(2..=3)),
                "cipher" => {
                    let ciphers = &[
                        "TLS_AES_128_GCM_SHA256",
                        "TLS_AES_256_GCM_SHA384",
                        "TLS_CHACHA20_POLY1305_SHA256",
                    ];
                    ciphers[rng.random_range(0..ciphers.len())].to_string()
                }
                "field" => {
                    let fields = &[
                        "email", "username", "password", "role", "age", "phone", "address",
                    ];
                    fields[rng.random_range(0..fields.len())].to_string()
                }
                "reason" | "details" => {
                    let reasons = &[
                        "invalid format",
                        "already exists",
                        "not found",
                        "required field missing",
                        "too short",
                        "duplicate entry",
                        "permission denied",
                    ];
                    reasons[rng.random_range(0..reasons.len())].to_string()
                }
                "size" | "compressed" => random_int(rng, 50, 50000).to_string(),
                "ratio" => format!("{:.1}", random_float(rng, 10.0, 90.0)),
                "action" => {
                    let actions = &["opened", "closed", "established", "terminated"];
                    actions[rng.random_range(0..actions.len())].to_string()
                }
                "ip" => format!(
                    "{}.{}.{}.{}",
                    rng.random_range(1..255),
                    rng.random_range(0..255),
                    rng.random_range(0..255),
                    rng.random_range(1..255)
                ),
                "email" => format!("{}@example.com", random_str(rng, 8)),
                "auth_method" => {
                    let auth_methods = &[
                        "password", "oauth2", "saml", "ldap", "mfa", "api_key", "sso",
                    ];
                    auth_methods[rng.random_range(0..auth_methods.len())].to_string()
                }
                "hours" => (random_int(rng, 1, 72)).to_string(),
                "limit" => format!("{}", random_int(rng, 10, 1000)),
                "scope" => {
                    let scopes = &[
                        "read:users",
                        "write:orders",
                        "admin",
                        "read:payments",
                        "write:profile",
                    ];
                    scopes[rng.random_range(0..scopes.len())].to_string()
                }
                "channel" => {
                    let channels = &["email", "sms", "authenticator", "push"];
                    channels[rng.random_range(0..channels.len())].to_string()
                }
                "address" => format!("{}@example.com", random_str(rng, 8)),
                "provider" | "issuer" | "gateway" => {
                    let providers = &[
                        "google",
                        "github",
                        "microsoft",
                        "facebook",
                        "apple",
                        "stripe",
                        "paypal",
                    ];
                    providers[rng.random_range(0..providers.len())].to_string()
                }
                "attempts" => random_int(rng, 1, 10).to_string(),
                "role" => {
                    let roles = &["admin", "editor", "viewer", "moderator", "user"];
                    roles[rng.random_range(0..roles.len())].to_string()
                }
                "kid" => random_str(rng, 8),
                "value" | "prefs" => {
                    let vals = &[
                        "enabled",
                        "disabled",
                        "dark_mode",
                        "notifications_on",
                        "language=en",
                    ];
                    vals[rng.random_range(0..vals.len())].to_string()
                }
                "query" => {
                    let queries = &["john", "test", "admin", "error", "order123", "recent"];
                    queries[rng.random_range(0..queries.len())].to_string()
                }
                "count" | "active" | "idle" | "waiting" | "hits" | "keys_affected" | "rows"
                | "available" | "reserved" | "items" | "attempt" | "max" => {
                    random_int(rng, 1, 1000).to_string()
                }
                "w" | "h" => random_int(rng, 32, 1920).to_string(),
                "plan" => {
                    let plans = &["free", "pro", "enterprise", "team"];
                    plans[rng.random_range(0..plans.len())].to_string()
                }
                "device" => {
                    let devices = &[
                        "Chrome/Windows",
                        "Safari/macOS",
                        "Firefox/Linux",
                        "Mobile iOS",
                        "Mobile Android",
                    ];
                    devices[rng.random_range(0..devices.len())].to_string()
                }
                "export_type" => {
                    let types = &["csv", "json", "pdf", "xlsx"];
                    types[rng.random_range(0..types.len())].to_string()
                }
                "order" | "sub" => format!("ORD-{}", random_int(rng, 10000, 99999)),
                "total" | "amount" | "from_amt" | "to_amt" => {
                    format!("{:.2}", random_float(rng, 0.50, 9999.99))
                }
                "currency" | "from_ccy" | "to_ccy" => {
                    let currencies = &["USD", "EUR", "GBP", "JPY", "CAD"];
                    currencies[rng.random_range(0..currencies.len())].to_string()
                }
                "rate" => format!("{:.4}", random_float(rng, 0.0001, 2.0)),
                "txn" => format!("txn_{}", random_str(rng, 16)),
                "last4" => format!("{:04}", rng.random_range(0..9999)),
                "brand" => {
                    let brands = &["Visa", "Mastercard", "Amex", "Discover"];
                    brands[rng.random_range(0..brands.len())].to_string()
                }
                "result" | "outcome" | "state" => {
                    let outcomes = &[
                        "success",
                        "completed",
                        "failed",
                        "pending",
                        "approved",
                        "declined",
                        "timeout",
                    ];
                    outcomes[rng.random_range(0..outcomes.len())].to_string()
                }
                "code" | "score" => random_int(rng, 100, 999).to_string(),
                "carrier" => {
                    let carriers = &["UPS", "FedEx", "USPS", "DHL"];
                    carriers[rng.random_range(0..carriers.len())].to_string()
                }
                "inv" => format!("INV-{}", random_int(rng, 10000, 99999)),
                "sku" => format!("SKU-{}", random_str(rng, 6).to_uppercase()),
                "old" | "new" | "old_s" | "new_s" => {
                    let states = &[
                        "pending",
                        "confirmed",
                        "processing",
                        "shipped",
                        "delivered",
                        "cancelled",
                        "refunded",
                    ];
                    states[rng.random_range(0..states.len())].to_string()
                }
                "date" => {
                    let now = Utc::now();
                    let ts = now + Duration::days(random_int(rng, 1, 30));
                    ts.format("%Y-%m-%d").to_string()
                }
                "delta" => {
                    let dir = if rng.random_bool(0.5) { "+" } else { "-" };
                    format!("{}{:.2}", dir, random_float(rng, 1.0, 1000.0))
                }
                "balance" => format!("{:.2}", random_float(rng, 0.0, 50000.0)),
                "op" => {
                    let ops = &["get", "set", "delete", "exists", "ttl", "incr"];
                    ops[rng.random_range(0..ops.len())].to_string()
                }
                "key" | "keyset" => format!("{}:{}", random_str(rng, 4), random_str(rng, 8)),
                "policy" => {
                    let policies = &["LRU", "LFU", "TTL", "FIFO"];
                    policies[rng.random_range(0..policies.len())].to_string()
                }
                "node" | "endpoint" | "host" => format!(
                    "{}-{}.cluster.local",
                    random_str(rng, 6),
                    random_int(rng, 0, 9)
                ),
                "port" => random_int(rng, 1024, 65535).to_string(),
                "pattern" => format!("{}:*", random_str(rng, 4)),
                "type" | "data_type" => {
                    let types = &["string", "list", "hash", "set", "zset"];
                    types[rng.random_range(0..types.len())].to_string()
                }
                "query_prefix" => {
                    let queries = &[
                        "SELECT * FROM users",
                        "INSERT INTO orders",
                        "UPDATE inventory SET",
                        "DELETE FROM sessions",
                        "SELECT u.name, o.total FROM",
                    ];
                    queries[rng.random_range(0..queries.len())].to_string()
                }
                "migration" => format!("V{}__{}", random_int(rng, 1, 99), random_str(rng, 10)),
                "table" => {
                    let tables = &[
                        "users",
                        "orders",
                        "products",
                        "sessions",
                        "audit_log",
                        "payments",
                    ];
                    tables[rng.random_range(0..tables.len())].to_string()
                }
                "primary_lsn" | "replica_lsn" => {
                    format!("{}/{}", random_str(rng, 8), random_str(rng, 8))
                }
                "statements" => random_int(rng, 1, 20).to_string(),
                _ => format!("{{{}}}", key),
            };
            result.push_str(&value);
            i = end;
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }
    result
}

/// Generate log lines and write them to the provided writer.
pub fn generate_logs<W: Write>(
    config: &GenerateConfig,
    writer: &mut W,
) -> Result<u64, Box<dyn std::error::Error>> {
    let mut rng = rand::rng();

    // Parse time range
    let (start_ts, end_ts) = match (&config.start, &config.end) {
        (Some(s), Some(e)) => {
            let start = s.parse::<DateTime<Utc>>()?;
            let end = e.parse::<DateTime<Utc>>()?;
            (start, end)
        }
        _ => {
            let now = Utc::now();
            (now - Duration::hours(1), now)
        }
    };

    let time_span = (end_ts - start_ts).num_milliseconds();
    let has_correlation = config.correlation_prefix.is_some();

    let rate_delay = if config.rate > 0 {
        std::time::Duration::from_secs_f64(1.0 / config.rate as f64)
    } else {
        std::time::Duration::from_secs(0)
    };

    let format = config.format.to_lowercase();
    let mut generated = 0u64;
    let batch_size = std::cmp::max(1, config.rate / 10);

    for i in 0..config.count {
        // Determine timestamp for this line
        let fraction = if config.count > 1 {
            i as f64 / (config.count - 1) as f64
        } else {
            0.0
        };
        let ts_offset = (time_span as f64 * fraction) as i64;
        let timestamp = start_ts + Duration::milliseconds(ts_offset);
        let ts_str = timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        let svc_idx = weighted_service_index(&mut rng);
        let service = &SERVICES[svc_idx];
        let level_num = weighted_level(service, &mut rng);
        let level_name = level_name(level_num);

        let msg_template = service.messages[rng.random_range(0..service.messages.len())];
        let message = fill_template(msg_template, &mut rng);

        let correlation = if has_correlation {
            let prefix = config.correlation_prefix.as_deref().unwrap_or("req");
            let uid = Uuid::new_v4();
            format!(" {}={}", prefix, uid)
        } else {
            String::new()
        };

        match format.as_str() {
            "json" | "jsonl" => {
                let line = serde_json::json!({
                    "timestamp": ts_str,
                    "level": level_name,
                    "logger": service.name,
                    "msg": message,
                });
                writeln!(writer, "{}", line)?;
            }
            "logfmt" => {
                let escaped_msg = message.replace('"', "\\\"");
                writeln!(
                    writer,
                    "level={} msg=\"{}\" logger={} timestamp=\"{}\"{}",
                    level_name, escaped_msg, service.name, ts_str, correlation
                )?;
            }
            "syslog" => {
                let priority = match level_name {
                    "TRACE" | "DEBUG" => 7, // debug
                    "INFO" => 6,            // info
                    "WARN" => 4,            // warning
                    "ERROR" => 3,           // error
                    "FATAL" => 2,           // critical
                    _ => 6,
                };
                let hostname = format!("svc-{}", service.name.replace('-', ""));
                let app_name = service.name.replace('-', "");
                writeln!(
                    writer,
                    "<{pri}>{ts} {host} {app}[{pid}]: [{level}] {msg}{corr}",
                    pri = priority,
                    ts = timestamp.format("%b %d %H:%M:%S"),
                    host = hostname,
                    app = app_name,
                    pid = rng.random_range(1000..99999),
                    level = level_name,
                    msg = message,
                    corr = correlation,
                )?;
            }
            "apache" | "apache_combined" | "combined" => {
                let client_ip = format!(
                    "{}.{}.{}.{}",
                    rng.random_range(1..255),
                    rng.random_range(0..255),
                    rng.random_range(0..255),
                    rng.random_range(1..255)
                );
                let method = random_method(&mut rng);
                let path = random_path(&mut rng);
                let status = random_status(&mut rng);
                let bytes = random_int(&mut rng, 100, 50000);
                let user_agent =
                    format!("Mozilla/5.0 (compatible; Bot-{})", random_str(&mut rng, 6));
                writeln!(
                    writer,
                    "{} - - [{}] \"{} {} HTTP/1.1\" {} {} \"-\" \"{}\"{corr}",
                    client_ip,
                    timestamp.format("%d/%b/%Y:%H:%M:%S %z"),
                    method,
                    path,
                    status,
                    bytes,
                    user_agent,
                    corr = correlation,
                )?;
            }
            "nginx" => {
                let client_ip = format!(
                    "{}.{}.{}.{}",
                    rng.random_range(1..255),
                    rng.random_range(0..255),
                    rng.random_range(0..255),
                    rng.random_range(1..255)
                );
                let method = random_method(&mut rng);
                let path = random_path(&mut rng);
                let status = random_status(&mut rng);
                let bytes = random_int(&mut rng, 100, 50000);
                let resp_time = random_float(&mut rng, 0.001, 5.0);
                let upstream = format!(
                    "{}.{}:{}",
                    random_str(&mut rng, 8),
                    random_int(&mut rng, 1, 99),
                    rng.random_range(3000..9999)
                );
                writeln!(
                    writer,
                    r#"{} - - [{}] "{} {} HTTP/1.1" {} {} "{}" "-" "{:.3}" "-" "{}"{corr}"#,
                    client_ip,
                    timestamp.format("%d/%b/%Y:%H:%M:%S %z"),
                    method,
                    path,
                    status,
                    bytes,
                    upstream,
                    resp_time,
                    upstream,
                    corr = correlation,
                )?;
            }
            "csv" => {
                // CSV: timestamp,level,source,message,correlation_id
                let escaped_msg = message.replace('"', "\"\"");
                writeln!(
                    writer,
                    "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"",
                    ts_str,
                    level_name,
                    service.name,
                    escaped_msg,
                    if has_correlation {
                        Uuid::new_v4().to_string()
                    } else {
                        String::new()
                    },
                )?;
            }
            "plain" | "text" => {
                let line = if correlation.is_empty() {
                    format!("{} [{}] {}: {}", ts_str, level_name, service.name, message)
                } else {
                    format!(
                        "{} [{}] {}: {}{}",
                        ts_str, level_name, service.name, message, correlation
                    )
                };
                writeln!(writer, "{}", line)?;
            }
            _ => {
                // Default to plain
                writeln!(
                    writer,
                    "{} [{}] {}: {}",
                    ts_str, level_name, service.name, message
                )?;
            }
        }

        generated += 1;

        // Rate limiting
        if config.rate > 0 && i % batch_size == 0 && i > 0 {
            std::thread::sleep(rate_delay);
        }
    }

    Ok(generated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_json() {
        let config = GenerateConfig {
            format: "json".to_string(),
            count: 10,
            rate: 0,
            start: None,
            end: None,
            correlation_prefix: None,
            extra: None,
        };
        let mut output = Vec::new();
        let count = generate_logs(&config, &mut output).unwrap();
        assert_eq!(count, 10);
        let text = String::from_utf8(output).unwrap();
        assert_eq!(text.lines().count(), 10);
        // Each line should be valid JSON
        for line in text.lines() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(v.get("timestamp").is_some());
            assert!(v.get("level").is_some());
            assert!(v.get("logger").is_some());
            assert!(v.get("msg").is_some());
        }
    }

    #[test]
    fn test_generate_logfmt() {
        let config = GenerateConfig {
            format: "logfmt".to_string(),
            count: 5,
            ..Default::default()
        };
        let mut output = Vec::new();
        let count = generate_logs(&config, &mut output).unwrap();
        assert_eq!(count, 5);
        let text = String::from_utf8(output).unwrap();
        for line in text.lines() {
            assert!(line.contains("level="));
            assert!(line.contains("msg=\""));
            assert!(line.contains("logger="));
        }
    }

    #[test]
    fn test_generate_apache() {
        let config = GenerateConfig {
            format: "apache".to_string(),
            count: 3,
            ..Default::default()
        };
        let mut output = Vec::new();
        let count = generate_logs(&config, &mut output).unwrap();
        assert_eq!(count, 3);
        let text = String::from_utf8(output).unwrap();
        for line in text.lines() {
            assert!(line.contains("HTTP/1.1"));
            assert!(line.contains('"'));
        }
    }

    #[test]
    fn test_generate_nginx() {
        let config = GenerateConfig {
            format: "nginx".to_string(),
            count: 3,
            ..Default::default()
        };
        let mut output = Vec::new();
        let count = generate_logs(&config, &mut output).unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn test_generate_correlation_ids() {
        let config = GenerateConfig {
            format: "json".to_string(),
            count: 5,
            correlation_prefix: Some("req".to_string()),
            ..Default::default()
        };
        let mut output = Vec::new();
        let count = generate_logs(&config, &mut output).unwrap();
        assert_eq!(count, 5);
    }

    #[test]
    fn test_generate_csv() {
        let config = GenerateConfig {
            format: "csv".to_string(),
            count: 3,
            ..Default::default()
        };
        let mut output = Vec::new();
        let count = generate_logs(&config, &mut output).unwrap();
        assert_eq!(count, 3);
        let text = String::from_utf8(output).unwrap();
        for line in text.lines() {
            assert!(line.starts_with('"'));
            assert!(line.ends_with('"'));
            let fields: Vec<&str> = line.split("\",\"").collect();
            assert!(fields.len() == 5, "CSV line should have 5 fields: {}", line);
        }
    }

    #[test]
    fn test_generate_syslog() {
        let config = GenerateConfig {
            format: "syslog".to_string(),
            count: 3,
            ..Default::default()
        };
        let mut output = Vec::new();
        let count = generate_logs(&config, &mut output).unwrap();
        assert_eq!(count, 3);
        let text = String::from_utf8(output).unwrap();
        for line in text.lines() {
            assert!(
                line.starts_with('<'),
                "Syslog line should start with <priority>"
            );
        }
    }

    #[test]
    fn test_generate_plain_text() {
        let config = GenerateConfig {
            format: "plain".to_string(),
            count: 3,
            ..Default::default()
        };
        let mut output = Vec::new();
        let count = generate_logs(&config, &mut output).unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn test_generate_zero_count() {
        let config = GenerateConfig {
            format: "json".to_string(),
            count: 0,
            ..Default::default()
        };
        let mut output = Vec::new();
        let count = generate_logs(&config, &mut output).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_fill_template_basic() {
        let mut rng = rand::rng();
        let result = fill_template("Request processed in {dur}ms", &mut rng);
        assert!(result.starts_with("Request processed in "));
        assert!(result.ends_with("ms"));
    }

    #[test]
    fn test_fill_template_no_placeholders() {
        let mut rng = rand::rng();
        let result = fill_template("Hello world", &mut rng);
        assert_eq!(result, "Hello world");
    }
}
