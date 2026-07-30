//! Platform time sampling pinned by the installer-owned edge manifest.

use std::{
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

/// The compiled forward-jump ceiling required by architecture section 10.3.
pub const MAX_FORWARD_STEP_MS: u64 = 60 * 60 * 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustedTimeSource {
    LinuxChronyNts,
    MacosManagedTimed,
}

impl TrustedTimeSource {
    pub fn for_current_platform(source_id: &str) -> Result<Self, TrustedTimeError> {
        match source_id {
            #[cfg(target_os = "linux")]
            "linux-chrony-nts" => Ok(Self::LinuxChronyNts),
            #[cfg(target_os = "macos")]
            "macos-managed-timed" => Ok(Self::MacosManagedTimed),
            _ => Err(TrustedTimeError::SourceMismatch(source_id.to_owned())),
        }
    }

    pub const fn source_id(self) -> &'static str {
        match self {
            Self::LinuxChronyNts => "linux-chrony-nts",
            Self::MacosManagedTimed => "macos-managed-timed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlatformTimeReading {
    pub utc_ms: Option<u64>,
    pub monotonic_anchor_ns: u64,
    pub monotonic_elapsed_ms: u64,
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

    /// Samples UTC only when the pinned platform source currently reports a
    /// synchronized clock. Monotonic elapsed time remains available during a
    /// source outage so the service can freeze or advance its durable
    /// effective clock according to its own fail-closed policy.
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
        let utc_ms = if source_is_synchronized(self.source) {
            let millis = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| TrustedTimeError::WallClockRange)?
                .as_millis();
            Some(u64::try_from(millis).map_err(|_| TrustedTimeError::WallClockRange)?)
        } else {
            None
        };
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
fn source_is_synchronized(source: TrustedTimeSource) -> bool {
    if source != TrustedTimeSource::LinuxChronyNts {
        return false;
    }
    // SAFETY: `adjtimex` initializes the provided plain C timex structure and
    // does not retain the pointer. A zeroed timex performs a read-only query
    // because `modes` is zero.
    let mut status: libc::timex = unsafe { std::mem::zeroed() };
    // SAFETY: status points to a valid writable timex for the duration of the
    // syscall.
    let result = unsafe { libc::adjtimex(&mut status) };
    result >= 0 && result != libc::TIME_ERROR && status.status & libc::STA_UNSYNC == 0
}

#[cfg(target_os = "macos")]
fn source_is_synchronized(source: TrustedTimeSource) -> bool {
    // macOS `timed` merges several reference-clock technologies and does not
    // expose its trust state through the kernel NTP discipline queried by
    // `ntp_adjtime`. Production services accept this wall clock only while
    // their separate, fresh root-owned platform status attests that automatic
    // network time is enabled and com.apple.timed is loaded.
    source == TrustedTimeSource::MacosManagedTimed
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn source_is_synchronized(_source: TrustedTimeSource) -> bool {
    false
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
    use super::*;

    #[test]
    fn source_id_round_trips() {
        #[cfg(target_os = "linux")]
        let expected = TrustedTimeSource::LinuxChronyNts;
        #[cfg(target_os = "macos")]
        let expected = TrustedTimeSource::MacosManagedTimed;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        return;

        assert_eq!(
            TrustedTimeSource::for_current_platform(expected.source_id()).unwrap(),
            expected
        );
    }

    #[test]
    fn other_platform_or_unknown_source_fails_closed() {
        assert!(TrustedTimeSource::for_current_platform("peer-supplied-time").is_err());
        #[cfg(target_os = "linux")]
        assert!(TrustedTimeSource::for_current_platform("macos-managed-timed").is_err());
        #[cfg(target_os = "macos")]
        assert!(TrustedTimeSource::for_current_platform("linux-chrony-nts").is_err());
    }

    #[test]
    fn samples_never_invent_a_peer_or_fallback_timestamp() {
        #[cfg(target_os = "linux")]
        let source = "linux-chrony-nts";
        #[cfg(target_os = "macos")]
        let source = "macos-managed-timed";
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        return;

        let reading = PlatformTimeSampler::new(source).unwrap().sample().unwrap();
        assert!(reading.monotonic_anchor_ns > 0);
        if let Some(utc_ms) = reading.utc_ms {
            assert!(utc_ms > 0);
        }
    }

    #[test]
    fn absolute_suspend_aware_anchor_is_monotonic_across_concurrent_samples() {
        #[cfg(target_os = "linux")]
        let source = "linux-chrony-nts";
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
}
