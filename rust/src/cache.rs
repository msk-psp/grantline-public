//! One complete observation generation per input revision; cached reads never wait on refresh.
use crate::Result;
use std::sync::{
    Mutex, RwLock,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

pub struct Cache<T> {
    value: RwLock<Option<(String, Instant, T)>>,
    refresh: Mutex<()>,
    generation: AtomicU64,
}
impl<T> Default for Cache<T> {
    fn default() -> Self {
        Self {
            value: RwLock::new(None),
            refresh: Mutex::new(()),
            generation: AtomicU64::new(0),
        }
    }
}
impl<T: Clone> Cache<T> {
    pub fn get(
        &self,
        key: &str,
        ttl: Duration,
        force: bool,
        read: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let before = self.generation.load(Ordering::Acquire);
        let cached = |fresh: bool| {
            self.value
                .read()
                .map_err(|_| "Observation cache unavailable".to_owned())
                .map(|v| {
                    v.as_ref()
                        .filter(|(k, ts, _)| k == key && (!fresh || ts.elapsed() < ttl))
                        .map(|(_, _, v)| v.clone())
                })
        };
        if !force && let Some(v) = cached(true)? {
            return Ok(v);
        }
        let _guard = self
            .refresh
            .lock()
            .map_err(|_| "Observation refresh unavailable")?;
        if self.generation.load(Ordering::Acquire) != before
            && let Some(v) = cached(false)?
        {
            return Ok(v);
        }
        if !force && let Some(v) = cached(true)? {
            return Ok(v);
        }
        let value = read()?;
        *self
            .value
            .write()
            .map_err(|_| "Observation cache unavailable")? =
            Some((key.into(), Instant::now(), value.clone()));
        self.generation.fetch_add(1, Ordering::Release);
        Ok(value)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    #[test]
    fn readers_share_generation_and_refresh_does_not_block_cached_reads() {
        let c = Cache::default();
        let calls = AtomicUsize::new(0);
        std::thread::scope(|s| {
            let jobs: Vec<_> = (0..8)
                .map(|_| {
                    s.spawn(|| {
                        c.get("a", Duration::from_secs(60), false, || {
                            calls.fetch_add(1, Ordering::SeqCst);
                            Ok(1)
                        })
                    })
                })
                .collect();
            for j in jobs {
                assert_eq!(j.join().unwrap().unwrap(), 1);
            }
        });
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let lock = c.refresh.lock().unwrap();
        assert_eq!(
            c.get("a", Duration::from_secs(60), false, || panic!(
                "cached reader must not refresh"
            ))
            .unwrap(),
            1
        );
        drop(lock);
        assert_eq!(
            c.get("a", Duration::from_secs(60), true, || Ok(2)).unwrap(),
            2
        );
        assert!(
            c.get("b", Duration::from_secs(60), false, || Err("unread".into()))
                .is_err()
        );
        assert_eq!(
            c.get("a", Duration::from_secs(60), false, || panic!())
                .unwrap(),
            2
        );
        assert_eq!(c.get("a", Duration::ZERO, false, || Ok(3)).unwrap(), 3);
    }
}
