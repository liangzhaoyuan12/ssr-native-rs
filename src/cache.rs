use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::hash::Hash;

pub struct Cache<K, V> {
    data: HashMap<K, (V, Instant)>,
    ttl: Duration,
}

impl<K: Eq + Hash, V> Cache<K, V> {
    pub fn new(ttl_secs: u64) -> Self {
        Cache {
            data: HashMap::new(),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.data.get(key).and_then(|(v, time)| {
            if time.elapsed() < self.ttl {
                Some(v)
            } else {
                None
            }
        })
    }

    pub fn insert(&mut self, key: K, value: V) {
        self.data.insert(key, (value, Instant::now()));
    }

    pub fn remove(&mut self, key: &K) {
        self.data.remove(key);
    }

    pub fn clear(&mut self) {
        self.data.clear();
    }
}
