//! Process hardening applied before runtime paths or secret-bearing inputs open.

use rustix::process::{self, DumpableBehavior, Resource, Rlimit};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HardenError {
    CoreLimit,
    Dumpable,
}

pub fn harden_process() -> Result<(), HardenError> {
    process::setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(|_| HardenError::CoreLimit)?;
    process::set_dumpable_behavior(DumpableBehavior::NotDumpable).map_err(|_| HardenError::Dumpable)
}
