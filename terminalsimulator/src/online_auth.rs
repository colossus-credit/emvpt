use crate::iso8583::Iso8583Message;
use base64::Engine;
use emvpt::EmvConnection;
use log::{debug, info, warn};
use std::fs;
use std::path::Path;

pub struct ArpcResponse {
    pub approved: bool,
    pub auth_id: Option<String>,
    pub tag_91: Option<Vec<u8>>,
}

/// Build TLV (tag + length + value) for a single tag.
fn build_tlv(tag: &str, value: &[u8]) -> Vec<u8> {
    let tag_bytes = hex::decode(tag).unwrap();
    let mut out = Vec::new();
    out.extend_from_slice(&tag_bytes);
    // BER-TLV length encoding
    if value.len() < 128 {
        out.push(value.len() as u8);
    } else if value.len() < 256 {
        out.push(0x81);
        out.push(value.len() as u8);
    } else {
        out.push(0x82);
        out.push((value.len() >> 8) as u8);
        out.push(value.len() as u8);
    }
    out.extend_from_slice(value);
    out
}

/// Extract tag 91 from DE55 TLV data.
fn extract_tag_91(data: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;
    while pos < data.len() {
        // Parse tag
        let tag_start = pos;
        if pos >= data.len() {
            break;
        }
        let first = data[pos];
        pos += 1;
        // Multi-byte tag
        if first & 0x1F == 0x1F {
            while pos < data.len() && data[pos] & 0x80 != 0 {
                pos += 1;
            }
            if pos < data.len() {
                pos += 1;
            }
        }
        let tag_bytes = &data[tag_start..pos];

        // Parse length
        if pos >= data.len() {
            break;
        }
        let len_byte = data[pos];
        pos += 1;
        let length: usize;
        if len_byte < 0x80 {
            length = len_byte as usize;
        } else if len_byte == 0x81 {
            if pos >= data.len() {
                break;
            }
            length = data[pos] as usize;
            pos += 1;
        } else if len_byte == 0x82 {
            if pos + 1 >= data.len() {
                break;
            }
            length = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
            pos += 2;
        } else {
            break;
        }

        if pos + length > data.len() {
            break;
        }

        // Check if tag is 91
        if tag_bytes == [0x91] {
            return Some(data[pos..pos + length].to_vec());
        }

        pos += length;
    }
    None
}

pub fn send_arqc_to_switch(
    connection: &EmvConnection,
    switch_url: &str,
    icc_public_key_path: &str,
) -> Result<ArpcResponse, String> {
    let mut msg = Iso8583Message::new("0100");

    // DE2: PAN from tag 5A
    if let Some(pan_bytes) = connection.get_tag_value("5A") {
        let pan_hex = hex::encode_upper(pan_bytes);
        // Strip trailing 'F' padding
        let pan = pan_hex.trim_end_matches('F').to_string();
        msg.set_pan(&pan);
    } else {
        return Err("Tag 5A (PAN) not found".to_string());
    }

    // DE4: Amount from tag 9F02
    if let Some(amount_bytes) = connection.get_tag_value("9F02") {
        // Already BCD-packed 6 bytes
        msg.set_field(4, amount_bytes.clone());
    }

    // DE11: Random STAN
    let stan: u32 = rand_stan();
    msg.set_field_bcd(11, &format!("{:06}", stan));

    // DE12: Current time HHMMSS
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let secs_today = now % 86400;
    let hh = secs_today / 3600;
    let mm = (secs_today % 3600) / 60;
    let ss = secs_today % 60;
    msg.set_field_bcd(12, &format!("{:02}{:02}{:02}", hh, mm, ss));

    // DE13: Current date MMDD
    // Simple conversion from epoch
    let days = (now / 86400) as i64;
    let (month, day) = epoch_days_to_mmdd(days);
    msg.set_field_bcd(13, &format!("{:02}{:02}", month, day));

    // DE41: Terminal ID
    msg.set_field_ascii(41, "TERM0001");

    // DE42: Merchant ID
    msg.set_field_ascii(42, "MERCHANT0000001");

    // DE55: EMV data TLV
    let emv_tags = [
        "9F02", "9F03", "9F1A", "95", "5F2A", "9A", "9C", "9F37", "82", "9F36", "9F26", "9F27",
        "9F10", "9F33", "9F34",
    ];
    let mut de55 = Vec::new();
    for tag in &emv_tags {
        if let Some(val) = connection.get_tag_value(tag) {
            de55.extend_from_slice(&build_tlv(tag, val));
        }
    }
    msg.set_field(55, de55);

    // DE62: ICC public key data (TLV with DF01/DF02/DF03, then base64-encoded)
    let key_path = Path::new(icc_public_key_path);
    let mut de62_tlv = Vec::new();

    let modulus_path = key_path.join("icc_modulus.bin");
    let exponent_path = key_path.join("icc_exponent.bin");

    if modulus_path.exists() {
        let modulus = fs::read(&modulus_path).map_err(|e| format!("Read icc_modulus.bin: {}", e))?;
        de62_tlv.extend_from_slice(&build_tlv("DF01", &modulus));
    }
    if exponent_path.exists() {
        let exponent =
            fs::read(&exponent_path).map_err(|e| format!("Read icc_exponent.bin: {}", e))?;
        de62_tlv.extend_from_slice(&build_tlv("DF02", &exponent));
    }
    // DF03: CDA signature (tag 9F4B) from GENERATE AC - used by on-chain validator
    if let Some(sig_9f4b) = connection.get_tag_value("9F4B") {
        de62_tlv.extend_from_slice(&build_tlv("DF03", sig_9f4b));
    } else {
        warn!("Tag 9F4B (Signed Dynamic Application Data) not found - on-chain validation will fail");
    }

    if !de62_tlv.is_empty() {
        let b64 = base64::engine::general_purpose::STANDARD.encode(&de62_tlv);
        msg.set_field(62, b64.into_bytes());
    }

    // Serialize and send
    let payload = msg.serialize();
    info!(
        "Sending ISO 8583 0100 to {}/arqc ({} bytes)",
        switch_url,
        payload.len()
    );
    debug!("ISO 8583 payload hex: {}", hex::encode(&payload));

    let url = format!("{}/arqc", switch_url.trim_end_matches('/'));
    let arqc_start = std::time::Instant::now();
    let result = ureq::post(&url)
        .set("Content-Type", "application/octet-stream")
        .send_bytes(&payload);

    let (status, body) = match result {
        Ok(resp) => {
            let status = resp.status();
            let mut body = Vec::new();
            resp.into_reader()
                .read_to_end(&mut body)
                .map_err(|e| format!("Read response body: {}", e))?;
            (status, body)
        }
        Err(ureq::Error::Status(code, resp)) => {
            let mut body = Vec::new();
            resp.into_reader()
                .read_to_end(&mut body)
                .map_err(|e| format!("Read error response body: {}", e))?;
            (code, body)
        }
        Err(e) => return Err(format!("HTTP POST failed: {}", e)),
    };
    let arqc_elapsed = arqc_start.elapsed();

    info!(
        "Received response: HTTP {}, {} bytes (ARQC round-trip: {:.0?})",
        status,
        body.len(),
        arqc_elapsed
    );
    debug!("Response hex: {}", hex::encode(&body));

    // Parse ISO 8583 0110 response
    let resp_msg = Iso8583Message::deserialize(&body)?;

    let response_code = resp_msg.get_field_ascii(39).unwrap_or_default();
    let auth_id = resp_msg.get_field_ascii(38);
    let approved = response_code == "00";

    info!(
        "ARPC response: code={}, auth_id={:?}, approved={}",
        response_code, auth_id, approved
    );

    // Extract tag 91 from DE55
    let tag_91 = resp_msg
        .get_field(55)
        .and_then(|de55_data| extract_tag_91(de55_data));

    if let Some(ref t91) = tag_91 {
        info!("Tag 91 (Issuer Authentication Data): {}", hex::encode(t91));
    } else {
        warn!("No tag 91 found in ARPC response DE55");
    }

    // If declined, try to decode private-use fields as error detail
    if !approved {
        for de in &[55u8, 62, 63] {
            if let Some(data) = resp_msg.get_field(*de) {
                // Try direct UTF-8
                if let Ok(text) = std::str::from_utf8(data) {
                    if !text.is_empty() {
                        // Check if it's hex-encoded ASCII
                        let mut logged = false;
                        if text.chars().all(|c| c.is_ascii_hexdigit()) && text.len() % 2 == 0 {
                            if let Ok(decoded) = hex::decode(text) {
                                if let Ok(s) = std::str::from_utf8(&decoded) {
                                    warn!("Switch DE{} error: {}", de, s);
                                    logged = true;
                                }
                            }
                        }
                        if !logged {
                            warn!("Switch DE{} error: {}", de, text);
                        }
                        break;
                    }
                }
            }
        }
    }

    Ok(ArpcResponse {
        approved,
        auth_id,
        tag_91,
    })
}

fn rand_stan() -> u32 {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros();
    (t % 1_000_000) as u32
}

/// Convert epoch days to (month, day) - approximate, good enough for DE13
fn epoch_days_to_mmdd(days: i64) -> (u32, u32) {
    // Days since 1970-01-01
    let mut y = 1970i64;
    let mut remaining = days;
    loop {
        let days_in_year = if is_leap(y) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        y += 1;
    }
    let leap = is_leap(y);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u32;
    for &md in &month_days {
        if remaining < md {
            break;
        }
        remaining -= md;
        month += 1;
    }
    (month, remaining as u32 + 1)
}

fn is_leap(y: i64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

use std::io::Read;
