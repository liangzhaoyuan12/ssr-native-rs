use bloomfilter::Bloom;

pub struct PpBloom {
    bloom: Bloom<[u8]>,
}

impl PpBloom {
    pub fn new(items_count: usize, fp_rate: f64) -> Self {
        PpBloom {
            bloom: Bloom::new_for_fp_rate(items_count, fp_rate),
        }
    }

    pub fn contains(&self, data: &[u8]) -> bool {
        self.bloom.check(data)
    }

    pub fn insert(&mut self, data: &[u8]) {
        self.bloom.set(data);
    }

    pub fn check_and_set(&mut self, data: &[u8]) -> bool {
        let exists = self.bloom.check(data);
        self.bloom.set(data);
        exists
    }

    pub fn clear(&mut self) {
        self.bloom = Bloom::new_for_fp_rate(10000, 0.01);
    }
}
