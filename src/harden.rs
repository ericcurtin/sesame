//! Best-effort process hardening.
//!
//! A crash while secrets are in memory would otherwise write them to a core
//! dump on disk. These calls make that much less likely. Failures are ignored:
//! hardening is defence in depth, not a precondition for working.

/// Apply what the platform offers.
///
/// * unix: set the core-dump size limit to zero.
/// * Linux: additionally mark the process non-dumpable, which also stops
///   other processes of the same user attaching with `ptrace` or reading
///   `/proc/<pid>/mem`.
/// * Windows: nothing. Windows Error Reporting dumps are opt-in per machine
///   policy, and there is no process-wide switch equivalent to the above.
#[allow(unsafe_code)]
pub fn apply() {
    #[cfg(unix)]
    {
        let none = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `none` is a valid, initialised `rlimit` that outlives the
        // call; setrlimit only reads it.
        unsafe {
            libc::setrlimit(libc::RLIMIT_CORE, &none);
        }
    }

    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_SET_DUMPABLE takes one integer argument and touches no
        // memory of ours; the remaining arguments are ignored.
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    #[allow(unsafe_code)]
    fn core_dumps_are_disabled_after_apply() {
        apply();
        let mut lim = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: `lim` is a valid out-pointer for getrlimit.
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut lim) };
        assert_eq!(rc, 0);
        assert_eq!(lim.rlim_cur, 0);
        assert_eq!(lim.rlim_max, 0);
    }
}
