use std::{
    collections::{BTreeSet, HashMap},
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

use crate::config::RateLimit;

#[derive(Debug, PartialEq, Eq)]
pub enum Admission {
    Allowed,
    Limited { retry_after: u64 },
    AtCapacity,
}

pub struct RateLimiter {
    config: RateLimit,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    buckets: HashMap<IpAddr, Bucket>,
    idle_at: BTreeSet<(Instant, IpAddr)>,
}

struct Bucket {
    tokens: f64,
    updated_at: Instant,
    full_at: Option<Instant>,
}

impl RateLimiter {
    pub fn new(config: RateLimit) -> Self {
        Self {
            config,
            state: Mutex::default(),
        }
    }

    pub fn check(&self, ip: IpAddr, now: Instant) -> Admission {
        let ip = ip.to_canonical();
        let mut state = self.state.lock().unwrap();
        let burst = f64::from(self.config.burst);
        let rate = self.config.requests_per_second;

        let mut bucket = match state.buckets.remove(&ip) {
            Some(mut bucket) => {
                if let Some(full_at) = bucket.full_at {
                    state.idle_at.remove(&(full_at, ip));
                }
                let elapsed = now.saturating_duration_since(bucket.updated_at);
                bucket.tokens = (bucket.tokens + elapsed.as_secs_f64() * rate).min(burst);
                bucket.updated_at = bucket.updated_at.max(now);
                bucket
            }
            None => {
                if state.buckets.len() >= self.config.max_clients {
                    let Some(&(full_at, idle)) = state.idle_at.first().filter(|(at, _)| *at <= now)
                    else {
                        return Admission::AtCapacity;
                    };
                    state.idle_at.remove(&(full_at, idle));
                    state.buckets.remove(&idle);
                }
                Bucket {
                    tokens: burst,
                    updated_at: now,
                    full_at: None,
                }
            }
        };

        let admission = if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Admission::Allowed
        } else {
            let wait = ((1.0 - bucket.tokens) / rate).ceil();
            Admission::Limited {
                retry_after: wait.max(1.0) as u64,
            }
        };

        // Duration rounds to nanoseconds. Move the deadline up by a tick if it rounds down.
        bucket.full_at = Duration::try_from_secs_f64((burst - bucket.tokens) / rate)
            .ok()
            .and_then(|wait| {
                if bucket.tokens + wait.as_secs_f64() * rate < burst {
                    wait.checked_add(Duration::from_nanos(1))
                } else {
                    Some(wait)
                }
            })
            .and_then(|wait| bucket.updated_at.checked_add(wait));
        if let Some(full_at) = bucket.full_at {
            state.idle_at.insert((full_at, ip));
        }
        state.buckets.insert(ip, bucket);
        admission
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refills_and_preserves_existing_clients_at_capacity() {
        let limiter = RateLimiter::new(RateLimit {
            requests_per_second: 0.5,
            burst: 2,
            max_clients: 1,
        });
        let now = Instant::now();
        let first = "192.0.2.1".parse().unwrap();
        let second = "192.0.2.2".parse().unwrap();
        let mapped_first = "::ffff:192.0.2.1".parse().unwrap();

        assert_eq!(limiter.check(first, now), Admission::Allowed);
        assert_eq!(limiter.check(mapped_first, now), Admission::Allowed);
        assert_eq!(limiter.check(second, now), Admission::AtCapacity);
        assert_eq!(
            limiter.check(first, now),
            Admission::Limited { retry_after: 2 }
        );
        assert_eq!(
            limiter.check(first, now + Duration::from_secs(2)),
            Admission::Allowed
        );
        assert_eq!(
            limiter.check(second, now + Duration::from_secs(5)),
            Admission::AtCapacity
        );
        assert_eq!(
            limiter.check(second, now + Duration::from_secs(6)),
            Admission::Allowed
        );
    }
}
