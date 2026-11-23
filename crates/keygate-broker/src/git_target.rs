//! The configured directory is the destination's ref database. Replicas
//! and remote-tracking branches cannot establish that a push is absent.
use keygate_core::{git_land::GitLand, journal::TicketState};
use std::{
    io,
    path::Path,
    process::{Command, Output},
};

pub trait TargetStateProbe {
    fn observe(&self, land: &GitLand) -> io::Result<TicketState>;
}
pub struct GitRefProbe<'a>(pub &'a Path);
impl GitRefProbe<'_> {
    fn git(&self, args: &[&str]) -> io::Result<Output> {
        Command::new("git")
            .env_clear()
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .arg("--no-replace-objects")
            .arg("--git-dir")
            .arg(self.0)
            .args(args)
            .output()
    }
}
impl TargetStateProbe for GitRefProbe<'_> {
    fn observe(&self, land: &GitLand) -> io::Result<TicketState> {
        if !land.valid() {
            return Err(io::Error::other("invalid CAS binding"));
        }
        let probe = self.git(&[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{}^{{commit}}", land.reference),
        ])?;
        if !probe.status.success() {
            return Err(io::Error::other("cannot read authoritative ref"));
        }
        let head = std::str::from_utf8(&probe.stdout)
            .map_err(io::Error::other)?
            .trim_end();

        if head == land.new_oid {
            return Ok(TicketState::Committed);
        }
        match self
            .git(&["merge-base", "--is-ancestor", &land.new_oid, head])?
            .status
            .code()
        {
            Some(0) => Ok(TicketState::Committed),
            Some(1) if head == land.expected_old => Ok(TicketState::SafeToRetry),
            Some(1) => Ok(TicketState::Uncertain),
            // A not-yet-received object cannot be in the observed history.
            _ if head == land.expected_old
                && self
                    .git(&[
                        "rev-parse",
                        "--verify",
                        "--quiet",
                        &format!("{}^{{object}}", land.new_oid),
                    ])?
                    .status
                    .code()
                    == Some(1) =>
            {
                Ok(TicketState::SafeToRetry)
            }
            _ => Err(io::Error::other("cannot establish authoritative ancestry")),
        }
    }
}
