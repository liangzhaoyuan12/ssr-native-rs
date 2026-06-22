pub struct WebSocketFrame;

impl WebSocketFrame {
    pub fn encode(data: &[u8], opcode: u8) -> Vec<u8> {
        let mask = 0x80u8;
        let mut frame = Vec::new();
        frame.push(0x80 | opcode);
        let len = data.len();
        if len < 126 {
            frame.push(mask | len as u8);
        } else if len < 65536 {
            frame.push(mask | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(mask | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        let mask_key: [u8; 4] = rand::random();
        frame.extend_from_slice(&mask_key);
        for (i, &byte) in data.iter().enumerate() {
            frame.push(byte ^ mask_key[i & 3]);
        }
        frame
    }

    pub fn decode(data: &[u8]) -> Option<(Vec<u8>, usize)> {
        if data.len() < 2 {
            return None;
        }
        let _fin = (data[0] & 0x80) != 0;
        let _opcode = data[0] & 0x0f;
        let masked = (data[1] & 0x80) != 0;
        let mut len = (data[1] & 0x7f) as usize;
        let mut offset = 2;
        if len == 126 {
            if data.len() < 4 { return None; }
            len = u16::from_be_bytes([data[2], data[3]]) as usize;
            offset = 4;
        } else if len == 127 {
            if data.len() < 10 { return None; }
            len = u64::from_be_bytes([
                data[2], data[3], data[4], data[5],
                data[6], data[7], data[8], data[9],
            ]) as usize;
            offset = 10;
        }
        if masked {
            if data.len() < offset + 4 + len { return None; }
            let mask_key = &data[offset..offset + 4];
            offset += 4;
            let mut payload = Vec::with_capacity(len);
            for (i, &byte) in data[offset..offset + len].iter().enumerate() {
                payload.push(byte ^ mask_key[i & 3]);
            }
            Some((payload, offset + len))
        } else {
            if data.len() < offset + len { return None; }
            Some((data[offset..offset + len].to_vec(), offset + len))
        }
    }
}
