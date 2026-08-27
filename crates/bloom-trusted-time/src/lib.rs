//! Platform time sampling pinned by the installer-owned edge manifest.

use std::{
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

/// The compiled forward-jump ceiling required by architecture section 10.3.
pub const MAX_FORWARD_STEP_MS: u64 = 60 * 60 * 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustedTimeSource {
    LinuxSystemClock,
    MacosManagedTimed,
}

impl TrustedTimeSource {
    pub fn for_current_platform(source_id: &str) -> Result<Self, TrustedTimeError> {
        match source_id {
            #[cfg(target_os = "linux")]
            // Schema-1 manifests historically used `linux-chrony-nts`. Decode
            // both spellings so draft/newer manifests remain usable, while
            // `source_id` keeps emitting the rollback-compatible schema-1 ID.
            "linux-system-clock" | "linux-chrony-nts" => Ok(Self::LinuxSystemClock),
            #[cfg(target_os = "macos")]
            "macos-managed-timed" => Ok(Self::MacosManagedTimed),
            _ => Err(TrustedTimeError::SourceMismatch(source_id.to_owned())),
        }
    }

    pub const fn source_id(self) -> &'static str {
        match self {
            // This is a schema-1 wire identifier, not a statement that the
            // implementation still requires Chrony. Changing it would make a
            // regenerated manifest unreadable by older binaries during a
            // mixed-version rollout or rollback.
            Self::LinuxSystemClock => "linux-chrony-nts",
            Self::MacosManagedTimed => "macos-managed-timed",
        }
    }

    /// Whether Bloom must maintain a durable discontinuity guard in addition
    /// to the platform wall clock.
    ///
    /// Linux persists a floor and a suspend-aware monotonic anchor so an
    /// unprivileged service cannot move authority time backwards. On macOS,
    /// changing the host clock is an administrator operation; administrator
    /// compromise is outside Bloom's local service boundary, so persisting a
    /// second effective clock adds failure modes without adding authority
    /// separation.
    pub const fn requires_durable_clock_guard(self) -> bool {
        match self {
            Self::LinuxSystemClock => true,
            Self::MacosManagedTimed => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlatformTimeReading {
    pub utc_ms: Option<u64>,
    pub monotonic_anchor_ns: u64,
    pub monotonic_elapsed_ms: u64,
}

/// The service-owned subset of durable clock state needed to evaluate the
/// next trusted-time observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistedClockState {
    pub last_effective_ms: u64,
    pub monotonic_anchor_ns: u64,
    /// The monotonic domain the anchor was sampled in. `None` for state
    /// written before this field existed, which is treated as unknown and
    /// therefore fail-closed.
    pub boot_epoch: Option<[u8; 16]>,
}

/// A neutral trusted-time outcome. Services remain responsible for mapping
/// this into their protocol types and for persisting/auditing the transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableClockCondition {
    Healthy,
    Untrusted,
    RollbackFrozen,
    ForwardJumpRejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableClockDecision {
    pub effective_now_ms: u64,
    pub condition: DurableClockCondition,
}

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum DurableClockError {
    #[error("monotonic clock arithmetic overflow")]
    ArithmeticOverflow,
}

/// Evaluate a platform reading against durable clock state without performing
/// storage, audit, readiness, or authority mutations.
///
/// A sampler's `monotonic_elapsed_ms` is process-relative and therefore starts
/// at zero after a service restart. When a non-zero absolute monotonic anchor
/// was persisted and the current anchor has not moved backwards, its delta
/// supplies restart-safe elapsed time in the same continuous-clock domain.
/// Legacy zero anchors and anchor rollback in a confirmed matching boot remain
/// fail-closed by falling back to the bounded process-relative elapsed
/// reading. Across a reboot, monotonic anchors cannot measure powered-off time,
/// so a nondecreasing wall clock is accepted while the durable floor still
/// rejects rollback. A zero effective-time sentinel is initialized by the
/// first available wall-clock sample. This transition only moves authority
/// time forward, so existing expirations can shorten but can never be extended.
pub fn evaluate_durable_clock(
    previous: Option<PersistedClockState>,
    reading: &PlatformTimeReading,
    current_boot_epoch: Option<[u8; 16]>,
    max_forward_step_ms: u64,
) -> Result<DurableClockDecision, DurableClockError> {
    let Some(utc_ms) = reading.utc_ms else {
        return Ok(DurableClockDecision {
            effective_now_ms: previous.map_or(0, |state| state.last_effective_ms),
            condition: DurableClockCondition::Untrusted,
        });
    };
    let Some(previous) = previous else {
        return Ok(DurableClockDecision {
            effective_now_ms: utc_ms,
            condition: DurableClockCondition::Healthy,
        });
    };
    if previous.last_effective_ms == 0 {
        return Ok(DurableClockDecision {
            effective_now_ms: utc_ms,
            condition: DurableClockCondition::Healthy,
        });
    }

    let confirmed_reboot = persisted_anchor_is_from_different_boot(&previous, current_boot_epoch);
    let monotonic_now = previous
        .last_effective_ms
        .checked_add(elapsed_since_persisted_anchor(
            &previous,
            current_boot_epoch,
            reading,
        ))
        .ok_or(DurableClockError::ArithmeticOverflow)?;
    if utc_ms < previous.last_effective_ms {
        return Ok(DurableClockDecision {
            effective_now_ms: previous.last_effective_ms,
            condition: DurableClockCondition::RollbackFrozen,
        });
    }
    // Only two present, unequal epochs prove that CLOCK_BOOTTIME restarted.
    // Unknown epochs include legacy persisted state and must not silently turn
    // a same-boot wall-clock attack into a healthy observation.
    if !confirmed_reboot && utc_ms > monotonic_now.saturating_add(max_forward_step_ms) {
        return Ok(DurableClockDecision {
            effective_now_ms: monotonic_now,
            condition: DurableClockCondition::ForwardJumpRejected,
        });
    }
    Ok(DurableClockDecision {
        effective_now_ms: utc_ms.max(monotonic_now),
        condition: DurableClockCondition::Healthy,
    })
}

/// Absolute anchors are only comparable within one monotonic domain.
///
/// `CLOCK_BOOTTIME` and `mach_continuous_time` both restart at zero on boot, so
/// subtracting a persisted anchor from a current one is meaningful only when
/// both were sampled in the same boot. A numerically smaller current anchor is
/// an obvious reset, but a *larger* one is not evidence of continuity: a short
/// prior boot followed by a longer current one produces a valid-looking
/// subtraction that credits time which never elapsed. Crediting it inflates the
/// effective now, which is what the forward-step guard is measured against, so
/// a large UTC step would then be accepted instead of rejected.
///
/// The domain identifier decides whether the persisted anchor can contribute
/// elapsed time. Anything other than a confirmed match — a different domain,
/// or an unknown one on either side — falls back to process-relative elapsed
/// time. The caller waives the forward-step ceiling only for a *confirmed*
/// reboot. Unknown domains remain fail-closed; treating missing legacy state
/// as proof of a reboot would create a one-time unguarded forward-jump window.
fn elapsed_since_persisted_anchor(
    previous: &PersistedClockState,
    current_boot_epoch: Option<[u8; 16]>,
    reading: &PlatformTimeReading,
) -> u64 {
    let same_domain = persisted_anchor_matches_current_boot(previous, current_boot_epoch);
    if same_domain && previous.monotonic_anchor_ns != 0 {
        if let Some(anchor_elapsed_ns) = reading
            .monotonic_anchor_ns
            .checked_sub(previous.monotonic_anchor_ns)
        {
            return (anchor_elapsed_ns / 1_000_000).max(reading.monotonic_elapsed_ms);
        }
    }
    reading.monotonic_elapsed_ms
}

fn persisted_anchor_matches_current_boot(
    previous: &PersistedClockState,
    current_boot_epoch: Option<[u8; 16]>,
) -> bool {
    matches!(
        (previous.boot_epoch, current_boot_epoch),
        (Some(persisted), Some(current)) if persisted == current
    )
}

fn persisted_anchor_is_from_different_boot(
    previous: &PersistedClockState,
    current_boot_epoch: Option<[u8; 16]>,
) -> bool {
    matches!(
        (previous.boot_epoch, current_boot_epoch),
        (Some(persisted), Some(current)) if persisted != current
    )
}

#[derive(Debug, thiserror::Error)]
pub enum TrustedTimeError {
    #[error("trusted time source {0:?} does not match this platform or reviewed packaging")]
    SourceMismatch(String),
    #[error("platform wall-clock value is outside the supported range")]
    WallClockRange,
    #[error("trusted time sampler state was poisoned")]
    StatePoisoned,
}

pub struct PlatformTimeSampler {
    source: TrustedTimeSource,
    sample_state: Mutex<Option<SampleState>>,
}

#[derive(Clone, Copy)]
struct SampleState {
    prior_anchor_ns: u64,
    fractional_ns: u64,
}

impl PlatformTimeSampler {
    pub fn new(source_id: &str) -> Result<Self, TrustedTimeError> {
        Ok(Self {
            source: TrustedTimeSource::for_current_platform(source_id)?,
            sample_state: Mutex::new(None),
        })
    }

    pub const fn source(&self) -> TrustedTimeSource {
        self.source
    }

    /// Samples the host wall clock and a suspend-aware monotonic anchor. Bloom
    /// never changes the host clock and does not depend on a separate time
    /// daemon; Linux services apply the durable rollback and same-boot
    /// discontinuity guard before using this value as authority time.
    pub fn sample(&self) -> Result<PlatformTimeReading, TrustedTimeError> {
        let (monotonic_anchor_ns, monotonic_elapsed_ms) = {
            let mut state = self
                .sample_state
                .lock()
                .map_err(|_| TrustedTimeError::StatePoisoned)?;
            let anchor = continuous_time_ns()?;
            let elapsed_ms = advance_sample_state(&mut state, anchor)?;
            (anchor, elapsed_ms)
        };
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TrustedTimeError::WallClockRange)?
            .as_millis();
        let utc_ms = Some(u64::try_from(millis).map_err(|_| TrustedTimeError::WallClockRange)?);
        Ok(PlatformTimeReading {
            utc_ms,
            monotonic_anchor_ns,
            monotonic_elapsed_ms,
        })
    }
}

fn advance_sample_state(
    state: &mut Option<SampleState>,
    anchor_ns: u64,
) -> Result<u64, TrustedTimeError> {
    let Some(prior) = *state else {
        *state = Some(SampleState {
            prior_anchor_ns: anchor_ns,
            fractional_ns: 0,
        });
        return Ok(0);
    };
    let elapsed_ns = anchor_ns
        .checked_sub(prior.prior_anchor_ns)
        .and_then(|elapsed| elapsed.checked_add(prior.fractional_ns))
        .ok_or(TrustedTimeError::WallClockRange)?;
    *state = Some(SampleState {
        prior_anchor_ns: anchor_ns,
        fractional_ns: elapsed_ns % 1_000_000,
    });
    Ok(elapsed_ns / 1_000_000)
}

#[cfg(target_os = "linux")]
fn continuous_time_ns() -> Result<u64, TrustedTimeError> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `time` is a valid writable timespec. CLOCK_BOOTTIME is a
    // read-only clock query and, unlike CLOCK_MONOTONIC, includes suspend.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0 {
        return Err(TrustedTimeError::WallClockRange);
    }
    timespec_ns(time.tv_sec, time.tv_nsec)
}

#[cfg(target_os = "macos")]
fn continuous_time_ns() -> Result<u64, TrustedTimeError> {
    #[repr(C)]
    struct MachTimebaseInfo {
        numer: u32,
        denom: u32,
    }
    unsafe extern "C" {
        fn mach_continuous_time() -> u64;
        fn mach_timebase_info(info: *mut MachTimebaseInfo) -> libc::c_int;
    }
    let mut info = MachTimebaseInfo { numer: 0, denom: 0 };
    // SAFETY: `info` is writable and the function does not retain the pointer.
    if unsafe { mach_timebase_info(&mut info) } != 0 || info.denom == 0 {
        return Err(TrustedTimeError::WallClockRange);
    }
    // SAFETY: `mach_continuous_time` has no preconditions and includes sleep.
    let ticks = unsafe { mach_continuous_time() };
    let nanos = u128::from(ticks)
        .checked_mul(u128::from(info.numer))
        .ok_or(TrustedTimeError::WallClockRange)?
        / u128::from(info.denom);
    u64::try_from(nanos).map_err(|_| TrustedTimeError::WallClockRange)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn continuous_time_ns() -> Result<u64, TrustedTimeError> {
    Err(TrustedTimeError::SourceMismatch(
        "no reviewed continuous clock".into(),
    ))
}

#[cfg(target_os = "linux")]
fn timespec_ns(seconds: libc::time_t, nanoseconds: libc::c_long) -> Result<u64, TrustedTimeError> {
    let seconds = u64::try_from(seconds).map_err(|_| TrustedTimeError::WallClockRange)?;
    let nanoseconds = u64::try_from(nanoseconds).map_err(|_| TrustedTimeError::WallClockRange)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(TrustedTimeError::WallClockRange)
}

#[cfg(test)]
mod tests {
    /// Two distinct monotonic domains, standing in for two boots.
    const EPOCH_A: [u8; 16] = [0xa1; 16];
    const EPOCH_B: [u8; 16] = [0xb2; 16];

    use super::*;

    #[test]
    fn source_id_round_trips() {
        #[cfg(target_os = "linux")]
        let expected = TrustedTimeSource::LinuxSystemClock;
        #[cfg(target_os = "macos")]
        let expected = TrustedTimeSource::MacosManagedTimed;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        return;

        assert_eq!(
            TrustedTimeSource::for_current_platform(expected.source_id()).unwrap(),
            expected
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn schema_one_linux_source_id_remains_rollback_compatible() {
        assert_eq!(
            TrustedTimeSource::for_current_platform("linux-chrony-nts").unwrap(),
            TrustedTimeSource::LinuxSystemClock
        );
        assert_eq!(
            TrustedTimeSource::for_current_platform("linux-chrony-nts")
                .unwrap()
                .source_id(),
            "linux-chrony-nts"
        );
        assert_eq!(
            TrustedTimeSource::for_current_platform("linux-system-clock").unwrap(),
            TrustedTimeSource::LinuxSystemClock
        );
    }

    #[test]
    fn other_platform_or_unknown_source_fails_closed() {
        assert!(TrustedTimeSource::for_current_platform("peer-supplied-time").is_err());
        #[cfg(target_os = "linux")]
        assert!(TrustedTimeSource::for_current_platform("macos-managed-timed").is_err());
        #[cfg(target_os = "macos")]
        assert!(TrustedTimeSource::for_current_platform("linux-system-clock").is_err());
    }

    #[test]
    fn linux_system_time_uses_the_durable_guard() {
        assert!(TrustedTimeSource::LinuxSystemClock.requires_durable_clock_guard());
        assert!(!TrustedTimeSource::MacosManagedTimed.requires_durable_clock_guard());
    }

    #[test]
    fn samples_never_invent_a_peer_or_fallback_timestamp() {
        #[cfg(target_os = "linux")]
        let source = "linux-system-clock";
        #[cfg(target_os = "macos")]
        let source = "macos-managed-timed";
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        return;

        let reading = PlatformTimeSampler::new(source).unwrap().sample().unwrap();
        assert!(reading.monotonic_anchor_ns > 0);
        assert!(reading.utc_ms.is_some_and(|utc_ms| utc_ms > 0));
    }

    #[test]
    fn absolute_suspend_aware_anchor_is_monotonic_across_concurrent_samples() {
        #[cfg(target_os = "linux")]
        let source = "linux-system-clock";
        #[cfg(target_os = "macos")]
        let source = "macos-managed-timed";
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        return;

        let sampler = std::sync::Arc::new(PlatformTimeSampler::new(source).unwrap());
        let baseline = sampler.sample().unwrap();
        let mut threads = Vec::new();
        for _ in 0..8 {
            let sampler = sampler.clone();
            threads.push(std::thread::spawn(move || sampler.sample().unwrap()));
        }
        let mut readings = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        readings.sort_unstable_by_key(|reading| reading.monotonic_anchor_ns);
        assert!(
            readings
                .windows(2)
                .all(|pair| { pair[0].monotonic_anchor_ns <= pair[1].monotonic_anchor_ns })
        );
        let elapsed_sum = readings
            .iter()
            .map(|reading| reading.monotonic_elapsed_ms)
            .sum::<u64>();
        let span_ms = readings
            .last()
            .unwrap()
            .monotonic_anchor_ns
            .saturating_sub(baseline.monotonic_anchor_ns)
            / 1_000_000;
        assert!(elapsed_sum <= span_ms.saturating_add(1));
    }

    #[test]
    fn elapsed_conversion_carries_sub_millisecond_remainders() {
        let mut state = None;
        assert_eq!(advance_sample_state(&mut state, 1_000_000).unwrap(), 0);
        assert_eq!(advance_sample_state(&mut state, 1_500_000).unwrap(), 0);
        assert_eq!(advance_sample_state(&mut state, 2_100_000).unwrap(), 1);
        assert_eq!(state.unwrap().fractional_ns, 100_000);
    }

    #[test]
    fn suspend_interval_is_included_in_elapsed_time() {
        let mut state = None;
        let before_suspend = 10_000_000_000;
        advance_sample_state(&mut state, before_suspend).unwrap();
        let two_hours_ns = 2 * 60 * 60 * 1_000_000_000;
        assert_eq!(
            advance_sample_state(&mut state, before_suspend + two_hours_ns).unwrap(),
            2 * 60 * 60 * 1_000
        );
    }

    #[test]
    fn durable_clock_initializes_and_freezes_without_trusted_utc() {
        let reading = PlatformTimeReading {
            utc_ms: Some(10_000),
            monotonic_anchor_ns: 1_000_000_000,
            monotonic_elapsed_ms: 0,
        };
        assert_eq!(
            evaluate_durable_clock(None, &reading, Some(EPOCH_A), MAX_FORWARD_STEP_MS).unwrap(),
            DurableClockDecision {
                effective_now_ms: 10_000,
                condition: DurableClockCondition::Healthy,
            }
        );
        assert_eq!(
            evaluate_durable_clock(
                Some(PersistedClockState {
                    last_effective_ms: 10_000,
                    monotonic_anchor_ns: reading.monotonic_anchor_ns,
                    boot_epoch: Some(EPOCH_A),
                }),
                &PlatformTimeReading {
                    utc_ms: None,
                    monotonic_anchor_ns: 2_000_000_000,
                    monotonic_elapsed_ms: 1_000,
                },
                Some(EPOCH_A),
                MAX_FORWARD_STEP_MS,
            )
            .unwrap(),
            DurableClockDecision {
                effective_now_ms: 10_000,
                condition: DurableClockCondition::Untrusted,
            }
        );
    }

    #[test]
    fn durable_clock_initializes_a_persisted_zero_effective_time() {
        let utc_ms = 1_787_279_361_000;
        let decision = evaluate_durable_clock(
            Some(PersistedClockState {
                last_effective_ms: 0,
                monotonic_anchor_ns: 42_000_000_000,
                boot_epoch: Some(EPOCH_A),
            }),
            &PlatformTimeReading {
                utc_ms: Some(utc_ms),
                monotonic_anchor_ns: 43_000_000_000,
                monotonic_elapsed_ms: 0,
            },
            Some(EPOCH_A),
            MAX_FORWARD_STEP_MS,
        )
        .unwrap();
        assert_eq!(
            decision,
            DurableClockDecision {
                effective_now_ms: utc_ms,
                condition: DurableClockCondition::Healthy,
            },
            "a persisted zero means no trusted epoch was ever established"
        );
    }

    #[test]
    fn durable_clock_restart_credits_absolute_monotonic_downtime() {
        let two_hours_ms = 2 * 60 * 60 * 1_000;
        let decision = evaluate_durable_clock(
            Some(PersistedClockState {
                last_effective_ms: 10_000,
                monotonic_anchor_ns: 1_000_000_000,
                boot_epoch: Some(EPOCH_A),
            }),
            &PlatformTimeReading {
                utc_ms: Some(10_000 + two_hours_ms),
                monotonic_anchor_ns: 1_000_000_000 + two_hours_ms * 1_000_000,
                monotonic_elapsed_ms: 0,
            },
            Some(EPOCH_A),
            MAX_FORWARD_STEP_MS,
        )
        .unwrap();
        assert_eq!(
            decision,
            DurableClockDecision {
                effective_now_ms: 10_000 + two_hours_ms,
                condition: DurableClockCondition::Healthy,
            }
        );
    }

    #[test]
    fn durable_clock_accepts_non_decreasing_wall_time_after_reboot() {
        // A reboot restarts CLOCK_BOOTTIME at zero. Its new anchor cannot prove
        // how long the machine was powered off, so the durable floor rejects
        // rollback while a nondecreasing host clock re-establishes current
        // time without requiring a separate synchronization daemon.
        let two_hours_ms = 2 * 60 * 60 * 1_000;
        let previous = PersistedClockState {
            last_effective_ms: 10_000,
            // Persisted one minute into the prior boot.
            monotonic_anchor_ns: 60 * 1_000_000_000,
            boot_epoch: Some(EPOCH_A),
        };
        let reading = PlatformTimeReading {
            utc_ms: Some(10_000 + two_hours_ms),
            // Two hours into the current boot: larger, but a different domain.
            monotonic_anchor_ns: 2 * 60 * 60 * 1_000_000_000,
            monotonic_elapsed_ms: 0,
        };

        assert_eq!(
            evaluate_durable_clock(Some(previous), &reading, Some(EPOCH_B), MAX_FORWARD_STEP_MS)
                .unwrap(),
            DurableClockDecision {
                effective_now_ms: 10_000 + two_hours_ms,
                condition: DurableClockCondition::Healthy,
            },
            "a nondecreasing wall clock must recover normally after reboot"
        );

        // An unknown domain is not evidence that a reboot occurred. This is
        // the legacy-upgrade path, and it must retain the process-relative
        // ceiling until an operator establishes trusted state.
        for (persisted, current) in [(None, Some(EPOCH_A)), (Some(EPOCH_A), None), (None, None)] {
            let decision = evaluate_durable_clock(
                Some(PersistedClockState {
                    boot_epoch: persisted,
                    ..previous
                }),
                &reading,
                current,
                MAX_FORWARD_STEP_MS,
            )
            .unwrap();
            assert_eq!(
                decision,
                DurableClockDecision {
                    effective_now_ms: previous.last_effective_ms,
                    condition: DurableClockCondition::ForwardJumpRejected,
                },
                "unknown domain must not waive the forward-step ceiling"
            );
        }

        // Within one confirmed boot, a small monotonic advance still exposes
        // and rejects a large wall-clock discontinuity.
        let jump_reading = PlatformTimeReading {
            monotonic_anchor_ns: previous.monotonic_anchor_ns + 1_000_000_000,
            monotonic_elapsed_ms: 0,
            ..reading
        };
        assert_eq!(
            evaluate_durable_clock(
                Some(previous),
                &jump_reading,
                Some(EPOCH_A),
                MAX_FORWARD_STEP_MS,
            )
            .unwrap()
            .condition,
            DurableClockCondition::ForwardJumpRejected,
            "matching domains must retain the forward-step guard"
        );
    }

    #[test]
    fn durable_clock_anchor_rollback_and_legacy_zero_stay_fail_closed() {
        let two_hours_ms = 2 * 60 * 60 * 1_000;
        for persisted_anchor_ns in [0, 1_000_000_000] {
            let current_anchor_ns = if persisted_anchor_ns == 0 {
                9_999_999_999
            } else {
                persisted_anchor_ns - 1
            };
            let decision = evaluate_durable_clock(
                Some(PersistedClockState {
                    last_effective_ms: 10_000,
                    monotonic_anchor_ns: persisted_anchor_ns,
                    boot_epoch: Some(EPOCH_A),
                }),
                &PlatformTimeReading {
                    utc_ms: Some(10_000 + two_hours_ms),
                    monotonic_anchor_ns: current_anchor_ns,
                    monotonic_elapsed_ms: 0,
                },
                Some(EPOCH_A),
                MAX_FORWARD_STEP_MS,
            )
            .unwrap();
            assert_eq!(
                decision,
                DurableClockDecision {
                    effective_now_ms: 10_000,
                    condition: DurableClockCondition::ForwardJumpRejected,
                }
            );
        }
    }

    #[test]
    fn durable_clock_preserves_rollback_and_same_process_semantics() {
        let previous = Some(PersistedClockState {
            last_effective_ms: 10_000,
            monotonic_anchor_ns: 1_000_000_000,
            boot_epoch: Some(EPOCH_A),
        });
        assert_eq!(
            evaluate_durable_clock(
                previous,
                &PlatformTimeReading {
                    utc_ms: Some(9_999),
                    monotonic_anchor_ns: 1_050_000_000,
                    monotonic_elapsed_ms: 50,
                },
                Some(EPOCH_A),
                MAX_FORWARD_STEP_MS,
            )
            .unwrap()
            .condition,
            DurableClockCondition::RollbackFrozen
        );
        assert_eq!(
            evaluate_durable_clock(
                previous,
                &PlatformTimeReading {
                    utc_ms: Some(10_050),
                    monotonic_anchor_ns: 1_050_000_000,
                    monotonic_elapsed_ms: 50,
                },
                Some(EPOCH_A),
                MAX_FORWARD_STEP_MS,
            )
            .unwrap(),
            DurableClockDecision {
                effective_now_ms: 10_050,
                condition: DurableClockCondition::Healthy,
            }
        );
    }

    #[test]
    fn durable_clock_retains_larger_sampler_elapsed_remainder() {
        let decision = evaluate_durable_clock(
            Some(PersistedClockState {
                last_effective_ms: 10_000,
                monotonic_anchor_ns: 1_000_000_000,
                boot_epoch: Some(EPOCH_A),
            }),
            &PlatformTimeReading {
                utc_ms: Some(10_002),
                monotonic_anchor_ns: 1_001_500_000,
                monotonic_elapsed_ms: 2,
            },
            Some(EPOCH_A),
            MAX_FORWARD_STEP_MS,
        )
        .unwrap();
        assert_eq!(decision.effective_now_ms, 10_002);
        assert_eq!(decision.condition, DurableClockCondition::Healthy);
    }

    #[test]
    fn durable_clock_reports_monotonic_arithmetic_overflow() {
        let error = evaluate_durable_clock(
            Some(PersistedClockState {
                last_effective_ms: u64::MAX,
                monotonic_anchor_ns: 1,
                boot_epoch: Some(EPOCH_A),
            }),
            &PlatformTimeReading {
                utc_ms: Some(u64::MAX),
                monotonic_anchor_ns: 1_000_001,
                monotonic_elapsed_ms: 1,
            },
            Some(EPOCH_A),
            MAX_FORWARD_STEP_MS,
        )
        .unwrap_err();
        assert_eq!(error, DurableClockError::ArithmeticOverflow);
    }
}
