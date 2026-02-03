/// Minimal ISO 8583 binary codec matching @tikpay/iso8583-ts format.
///
/// Format: BCD MTI (2 bytes) + binary bitmap (8 bytes) + fields
/// - Numeric fields: BCD-packed
/// - Alpha/AN/ANS fields: ASCII, fixed length
/// - LLVAR: BCD length prefix (1 byte), BCD digits payload
/// - LLLVAR: BCD length prefix (2 bytes), raw bytes payload

/// Field encoding types
enum FieldEncoding {
    /// BCD-packed numeric, fixed length (in digits)
    Bcd(usize),
    /// Fixed-length ASCII
    Ascii(usize),
    /// LLVARn: 1-byte BCD length prefix (digit count), BCD-packed digits
    LlvarBcdDigits,
    /// LLLVARans: 2-byte BCD length prefix (byte count), raw bytes
    LllvarRaw,
}

fn field_encoding(de: u8) -> Option<FieldEncoding> {
    match de {
        2 => Some(FieldEncoding::LlvarBcdDigits),
        4 => Some(FieldEncoding::Bcd(12)),
        11 => Some(FieldEncoding::Bcd(6)),
        12 => Some(FieldEncoding::Bcd(6)),
        13 => Some(FieldEncoding::Bcd(4)),
        38 => Some(FieldEncoding::Ascii(6)),
        39 => Some(FieldEncoding::Ascii(2)),
        41 => Some(FieldEncoding::Ascii(8)),
        42 => Some(FieldEncoding::Ascii(15)),
        55 => Some(FieldEncoding::LllvarRaw),
        62 => Some(FieldEncoding::LllvarRaw),
        _ => None,
    }
}

/// Pack ASCII digits into BCD bytes.
/// E.g. "1234" -> [0x12, 0x34], "123" -> [0x01, 0x23]
fn ascii_to_bcd(digits: &[u8], byte_len: usize) -> Vec<u8> {
    let digit_len = byte_len * 2;
    let mut padded = vec![b'0'; digit_len.saturating_sub(digits.len())];
    padded.extend_from_slice(digits);

    let mut out = Vec::with_capacity(byte_len);
    for i in (0..padded.len()).step_by(2) {
        let hi = padded[i].wrapping_sub(b'0');
        let lo = if i + 1 < padded.len() {
            padded[i + 1].wrapping_sub(b'0')
        } else {
            0
        };
        out.push((hi << 4) | lo);
    }
    out
}

/// Unpack BCD bytes to ASCII digit string.
fn bcd_to_ascii(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 2);
    for &b in data {
        out.push(b'0' + (b >> 4));
        out.push(b'0' + (b & 0x0F));
    }
    out
}

/// Encode a number as BCD with a given number of digits (for length headers).
fn encode_bcd_len(value: usize, digits: usize) -> Vec<u8> {
    let s = format!("{:0>width$}", value, width = digits);
    let byte_len = (digits + 1) / 2;
    ascii_to_bcd(s.as_bytes(), byte_len)
}

/// Decode a BCD length header.
fn decode_bcd_len(data: &[u8], digits: usize) -> usize {
    let ascii = bcd_to_ascii(data);
    // Take the last `digits` characters
    let start = ascii.len().saturating_sub(digits);
    let s = std::str::from_utf8(&ascii[start..]).unwrap_or("0");
    s.parse().unwrap_or(0)
}

pub struct Iso8583Message {
    pub mti: String,
    pub fields: std::collections::HashMap<u8, Vec<u8>>,
}

impl Iso8583Message {
    pub fn new(mti: &str) -> Self {
        Iso8583Message {
            mti: mti.to_string(),
            fields: std::collections::HashMap::new(),
        }
    }

    /// Set a field with raw bytes value.
    pub fn set_field(&mut self, de: u8, value: Vec<u8>) {
        self.fields.insert(de, value);
    }

    /// Set a field from an ASCII string (for ASCII-type fields).
    pub fn set_field_ascii(&mut self, de: u8, value: &str) {
        self.fields.insert(de, value.as_bytes().to_vec());
    }

    /// Set a BCD numeric field from a digit string.
    pub fn set_field_bcd(&mut self, de: u8, digits: &str) {
        if let Some(FieldEncoding::Bcd(digit_len)) = field_encoding(de) {
            let byte_len = (digit_len + 1) / 2;
            self.fields
                .insert(de, ascii_to_bcd(digits.as_bytes(), byte_len));
        }
    }

    /// Set DE2 (PAN) from a digit string. LLVAR BCD encoding.
    pub fn set_pan(&mut self, digits: &str) {
        // Store raw ASCII digits; serialize will BCD-pack them
        self.fields.insert(2, digits.as_bytes().to_vec());
    }

    /// Serialize to binary. Returns Err if a field has no known encoding.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // MTI: BCD encoded (4 digits -> 2 bytes)
        let mti_bytes = ascii_to_bcd(self.mti.as_bytes(), 2);
        out.extend_from_slice(&mti_bytes);

        // Build bitmap (8 bytes binary) — only include fields with known encodings
        let mut bitmap = [0u8; 8];
        for &de in self.fields.keys() {
            if de >= 1 && de <= 64 && field_encoding(de).is_some() {
                let idx = (de - 1) as usize;
                bitmap[idx / 8] |= 1 << (7 - (idx % 8));
            }
        }
        out.extend_from_slice(&bitmap);

        // Fields in order
        let mut des: Vec<u8> = self.fields.keys().copied().collect();
        des.sort();

        for de in des {
            let enc = match field_encoding(de) {
                Some(e) => e,
                None => continue,
            };
            let value = &self.fields[&de];
            match enc {
                FieldEncoding::Bcd(_) => {
                    // Value is already BCD-packed bytes
                    out.extend_from_slice(value);
                }
                FieldEncoding::Ascii(len) => {
                    // Right-pad or truncate to fixed length
                    let mut buf = vec![b' '; len];
                    let copy_len = value.len().min(len);
                    buf[..copy_len].copy_from_slice(&value[..copy_len]);
                    out.extend_from_slice(&buf);
                }
                FieldEncoding::LlvarBcdDigits => {
                    // value = ASCII digits
                    // Length prefix: BCD 2-digit (1 byte) = digit count
                    let digit_count = value.len();
                    out.extend_from_slice(&encode_bcd_len(digit_count, 2));
                    // Payload: BCD-packed digits
                    let byte_len = (digit_count + 1) / 2;
                    out.extend_from_slice(&ascii_to_bcd(value, byte_len));
                }
                FieldEncoding::LllvarRaw => {
                    // Length prefix: BCD 3-digit (2 bytes) = byte count
                    out.extend_from_slice(&encode_bcd_len(value.len(), 3));
                    out.extend_from_slice(value);
                }
            }
        }

        out
    }

    /// Deserialize from binary.
    pub fn deserialize(data: &[u8]) -> Result<Self, String> {
        if data.len() < 10 {
            return Err("Message too short".to_string());
        }

        // MTI: BCD 2 bytes -> 4 ASCII digits
        let mti_ascii = bcd_to_ascii(&data[0..2]);
        let mti = String::from_utf8(mti_ascii).map_err(|_| "Invalid MTI")?;

        let bitmap = &data[2..10];

        let mut msg = Iso8583Message::new(&mti);
        let mut pos = 10;

        for bit in 0..64u8 {
            let de = bit + 1;
            if bitmap[bit as usize / 8] & (1 << (7 - (bit % 8))) == 0 {
                continue;
            }

            let enc = match field_encoding(de) {
                Some(e) => e,
                None => {
                    // Skip unknown DEs — cannot determine length, so stop parsing
                    break;
                }
            };

            match enc {
                FieldEncoding::Bcd(digit_len) => {
                    let byte_len = (digit_len + 1) / 2;
                    if pos + byte_len > data.len() {
                        return Err(format!("DE{}: truncated", de));
                    }
                    msg.fields.insert(de, data[pos..pos + byte_len].to_vec());
                    pos += byte_len;
                }
                FieldEncoding::Ascii(len) => {
                    if pos + len > data.len() {
                        return Err(format!("DE{}: truncated", de));
                    }
                    msg.fields.insert(de, data[pos..pos + len].to_vec());
                    pos += len;
                }
                FieldEncoding::LlvarBcdDigits => {
                    // 1-byte BCD length prefix (2 digits) = digit count
                    if pos + 1 > data.len() {
                        return Err(format!("DE{}: truncated length", de));
                    }
                    let digit_count = decode_bcd_len(&data[pos..pos + 1], 2);
                    pos += 1;
                    let byte_len = (digit_count + 1) / 2;
                    if pos + byte_len > data.len() {
                        return Err(format!("DE{}: truncated value", de));
                    }
                    let bcd_bytes = &data[pos..pos + byte_len];
                    let ascii_digits = bcd_to_ascii(bcd_bytes);
                    let start = ascii_digits.len().saturating_sub(digit_count);
                    msg.fields.insert(de, ascii_digits[start..].to_vec());
                    pos += byte_len;
                }
                FieldEncoding::LllvarRaw => {
                    // 2-byte BCD length prefix (3 digits) = byte count
                    if pos + 2 > data.len() {
                        return Err(format!("DE{}: truncated length", de));
                    }
                    let len = decode_bcd_len(&data[pos..pos + 2], 3);
                    pos += 2;
                    if pos + len > data.len() {
                        return Err(format!("DE{}: truncated value", de));
                    }
                    msg.fields.insert(de, data[pos..pos + len].to_vec());
                    pos += len;
                }
            }
        }

        Ok(msg)
    }

    /// Get a field as ASCII string.
    pub fn get_field_ascii(&self, de: u8) -> Option<String> {
        self.fields
            .get(&de)
            .and_then(|v| String::from_utf8(v.clone()).ok())
            .map(|s| s.trim().to_string())
    }

    /// Get raw field bytes.
    pub fn get_field(&self, de: u8) -> Option<&Vec<u8>> {
        self.fields.get(&de)
    }
}
