pub struct Buffer {
    data: Vec<u8>,
}

impl Buffer {
    pub fn new() -> Self {
        Buffer { data: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Buffer { data: Vec::with_capacity(cap) }
    }

    pub fn from(data: Vec<u8>) -> Self {
        Buffer { data }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn clear(&mut self) {
        self.data.clear();
    }

    pub fn append(&mut self, other: &[u8]) {
        self.data.extend_from_slice(other);
    }

    pub fn append_byte(&mut self, byte: u8) {
        self.data.push(byte);
    }

    pub fn insert(&mut self, pos: usize, other: &[u8]) {
        let mut new_data = Vec::with_capacity(self.data.len() + other.len());
        new_data.extend_from_slice(&self.data[..pos]);
        new_data.extend_from_slice(other);
        new_data.extend_from_slice(&self.data[pos..]);
        self.data = new_data;
    }

    pub fn shorten(&mut self, len: usize) {
        if len >= self.data.len() {
            self.data.clear();
        } else {
            self.data.drain(..len);
        }
    }

    pub fn split_off(&mut self, at: usize) -> Vec<u8> {
        let rest = self.data.split_off(at);
        rest
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.data
    }
}

impl Default for Buffer {
    fn default() -> Self {
        Buffer::new()
    }
}

impl From<Vec<u8>> for Buffer {
    fn from(data: Vec<u8>) -> Self {
        Buffer::from(data)
    }
}

impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}
