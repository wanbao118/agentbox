//! ab-runtime — turns an agent profile into an enforced MXC sandbox session.

mod configgen;
mod mxcbin;
mod prereq;
mod session;

pub use configgen::{build_config, Containment, ExecSpec, FsPolicy, NetworkPosture};
pub use mxcbin::{find_mxc_binary, mxc_binary_name, sibling_mxc_hint, SIBLING_DISCOVERY_ENV};
pub use prereq::{run_doctor, Check};
pub use session::{
    is_strict_violation, run_session, AuditSummary, ConfigMode, RunOptions, STRICT_EXIT_CODE,
};

/// Platform containment selection: Seatbelt on macOS, Bubblewrap elsewhere.
pub fn default_containment() -> Containment {
    if std::env::consts::OS == "macos" {
        Containment::Seatbelt
    } else {
        Containment::Bubblewrap
    }
}
