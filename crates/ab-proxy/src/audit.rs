//! JSONL audit log of proxy decisions.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;

/// One allow/deny/error event.
#[derive(Debug, Clone)]
pub struct AuditRecord {
    pub event: &'static str, // "allow" | "deny" | "error"
    pub host: String,
    pub port: u16,
    pub reason: String,
    /// Whether a credential was injected for this request.
    pub cred_injected: bool,
}

/// Maximum buffered audit lines before the writer catches up. Bounded so a
/// flood of decisions (e.g. connection-limit errors from a runaway sandbox)
/// cannot grow memory without limit; beyond the cap events are dropped rather
/// than ever blocking the data path.
const AUDIT_BACKLOG: usize = 8192;

/// Cheap cloneable sink; `None` tx means disabled.
#[derive(Clone, Default)]
pub struct Audit {
    tx: Option<mpsc::Sender<String>>,
}

impl Audit {
    pub fn disabled() -> Self {
        Self { tx: None }
    }

    /// Open (truncate) a JSONL file and spawn the writer task.
    pub fn file(path: &Path) -> std::io::Result<Self> {
        use std::io::Write;
        // The log records browsing/egress destinations; keep it owner-only.
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)?
        };
        #[cfg(not(unix))]
        let file = std::fs::File::create(path)?;
        let std_writer = std::io::BufWriter::new(file);
        let (tx, mut rx) = mpsc::channel::<String>(AUDIT_BACKLOG);
        tokio::task::spawn_blocking(move || {
            let mut w = std_writer;
            while let Some(line) = rx.blocking_recv() {
                if writeln!(w, "{line}").is_err() {
                    break;
                }
                let _ = w.flush();
            }
        });
        Ok(Self { tx: Some(tx) })
    }

    /// Record an event; never blocks the data path (drops when the bounded
    /// backlog is full).
    pub fn record(&self, rec: AuditRecord) {
        if let Some(tx) = &self.tx {
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or_default();
            let line = serde_json::json!({
                "ts": ts,
                "event": rec.event,
                "host": rec.host,
                "port": rec.port,
                "reason": rec.reason,
                "cred_injected": rec.cred_injected,
            })
            .to_string();
            let _ = tx.try_send(line);
        }
    }
}
