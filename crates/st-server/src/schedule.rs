//! Scan schedules: standard 5-field cron expressions, evaluated in UTC.
//!
//! `minute hour day-of-month month day-of-week`, e.g. `0 3 * * *` (daily at 03:00 UTC) or
//! `*/30 * * * 1-5`. Seconds and years are not accepted, and a schedule may not fire more
//! often than every [`MIN_INTERVAL_MINUTES`] minutes: a scan clones and reads a repository.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Duration, TimeZone as _, Utc};
use croner::Cron;
use croner::parser::{CronParser, Seconds, Year};

pub const MAX_LEN: usize = 100;
pub const MIN_INTERVAL_MINUTES: i64 = 5;
/// Gaps checked for the minimum interval; patterns repeat, so the first cluster shows.
const CHECKED_OCCURRENCES: usize = 600;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScheduleError {
    #[error("schedule must be a 5-field cron expression (minute hour day month weekday), at most {MAX_LEN} characters")]
    Syntax,
    #[error("schedule never fires")]
    Never,
    #[error("schedule fires more often than every {MIN_INTERVAL_MINUTES} minutes")]
    TooFrequent,
}

/// A validated schedule. Displays as the expression it was parsed from (trimmed).
#[derive(Clone)]
pub struct Schedule {
    cron: Cron,
    text: String,
}

impl fmt::Debug for Schedule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Schedule").field(&self.text).finish()
    }
}

impl fmt::Display for Schedule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl FromStr for Schedule {
    type Err = ScheduleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Schedule {
    pub fn parse(expr: &str) -> Result<Self, ScheduleError> {
        let text = expr.trim();
        if text.is_empty()
            || text.len() > MAX_LEN
            || !text.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
            || text.split_ascii_whitespace().count() != 5
        {
            return Err(ScheduleError::Syntax);
        }
        let parser = CronParser::builder().seconds(Seconds::Disallowed).year(Year::Disallowed).build();
        let cron = parser.parse(text).map_err(|_| ScheduleError::Syntax)?;
        let schedule = Self { cron, text: text.split_ascii_whitespace().collect::<Vec<_>>().join(" ") };
        schedule.check_interval()?;
        Ok(schedule)
    }

    /// The first firing strictly after `t` (UTC), if the schedule fires again at all.
    #[must_use]
    pub fn next_after(&self, t: DateTime<Utc>) -> Option<DateTime<Utc>> {
        self.cron.find_next_occurrence(&t, false).ok()
    }

    fn check_interval(&self) -> Result<(), ScheduleError> {
        let start = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).single().ok_or(ScheduleError::Never)?;
        let mut prev = self.next_after(start).ok_or(ScheduleError::Never)?;
        for _ in 0..CHECKED_OCCURRENCES {
            let Some(next) = self.next_after(prev) else { break };
            if next - prev < Duration::minutes(MIN_INTERVAL_MINUTES) {
                return Err(ScheduleError::TooFrequent);
            }
            prev = next;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, mo, d, h, mi, 0).single().unwrap_or_else(|| panic!("bad date"))
    }

    #[test]
    fn next_firing_in_utc() {
        let s = Schedule::parse("0 3 * * *").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(s.next_after(at(2026, 11, 19, 2, 59)), Some(at(2026, 11, 19, 3, 0)));
        assert_eq!(s.next_after(at(2026, 11, 19, 3, 0)), Some(at(2026, 11, 20, 3, 0)), "strictly after");
        let weekdays = Schedule::parse("*/30 9-17 * * 1-5").unwrap_or_else(|e| panic!("{e}"));
        // 2026-11-21 is a Saturday.
        assert_eq!(weekdays.next_after(at(2026, 11, 20, 17, 30)), Some(at(2026, 11, 23, 9, 0)));
    }

    #[test]
    fn normalizes_whitespace() {
        let s = Schedule::parse("  0   3 * *  * ").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(s.to_string(), "0 3 * * *");
    }

    #[test]
    fn rejects_bad_syntax() {
        for bad in ["", "0 3 * *", "0 0 3 * * *", "0 3 * * * 2026", "61 * * * *", "a b c d e", "0\t3 * * *", "@daily"] {
            assert_eq!(Schedule::parse(bad).map(|_| ()), Err(ScheduleError::Syntax), "{bad:?}");
        }
        assert_eq!(Schedule::parse(&"0 ".repeat(60)).map(|_| ()), Err(ScheduleError::Syntax));
    }

    #[test]
    fn rejects_too_frequent() {
        for bad in ["* * * * *", "*/2 * * * *", "0,3 * * * *", "* 3 1 1 *"] {
            assert_eq!(Schedule::parse(bad).map(|_| ()), Err(ScheduleError::TooFrequent), "{bad:?}");
        }
        for ok in ["*/5 * * * *", "0 * * * *", "15 2 1 * *"] {
            assert!(Schedule::parse(ok).is_ok(), "{ok:?}");
        }
    }

    #[test]
    fn never_firing() {
        assert_eq!(Schedule::parse("0 0 31 2 *").map(|_| ()), Err(ScheduleError::Never));
    }
}
