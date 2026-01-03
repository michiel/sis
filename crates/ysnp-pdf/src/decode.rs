use std::io::Read;

use anyhow::{anyhow, Result};

use crate::object::{PdfAtom, PdfDict, PdfName, PdfStream};

#[derive(Debug, Clone)]
pub struct DecodedStream {
    pub data: Vec<u8>,
    pub truncated: bool,
    pub filters: Vec<String>,
    pub input_len: usize,
}

pub fn decode_stream(bytes: &[u8], stream: &PdfStream<'_>, max_out: usize) -> Result<DecodedStream> {
    let span = stream.data_span;
    let start = span.start as usize;
    let end = span.end as usize;
    if start >= end || end > bytes.len() {
        return Err(anyhow!("invalid stream span"));
    }
    let mut data = bytes[start..end].to_vec();
    let mut truncated = false;
    let filters = stream_filters(&stream.dict);
    for filter in &filters {
        let decoded = decode_filter(&data, filter, max_out)?;
        data = decoded.0;
        if decoded.1 {
            truncated = true;
            break;
        }
    }
    if data.len() > max_out {
        data.truncate(max_out);
        truncated = true;
    }
    Ok(DecodedStream {
        data,
        truncated,
        filters,
        input_len: end - start,
    })
}

pub fn stream_filters(dict: &PdfDict<'_>) -> Vec<String> {
    let mut out = Vec::new();
    let (_, obj) = match dict.get_first(b"/Filter") {
        Some(v) => v,
        None => return out,
    };
    match &obj.atom {
        PdfAtom::Name(n) => out.push(name_to_string(n)),
        PdfAtom::Array(arr) => {
            for o in arr {
                if let PdfAtom::Name(n) = &o.atom {
                    out.push(name_to_string(n));
                }
            }
        }
        _ => {}
    }
    out
}

fn name_to_string(n: &PdfName<'_>) -> String {
    String::from_utf8_lossy(&n.decoded).to_string()
}

fn decode_filter(data: &[u8], filter: &str, max_out: usize) -> Result<(Vec<u8>, bool)> {
    match filter {
        "/FlateDecode" | "/Fl" => decode_flate(data, max_out),
        "/ASCIIHexDecode" | "/AHx" => Ok((decode_ascii_hex(data), false)),
        "/ASCII85Decode" | "/A85" => decode_ascii85(data),
        "/RunLengthDecode" | "/RL" => Ok((decode_run_length(data), false)),
        "/LZWDecode" | "/LZW" => decode_lzw(data, max_out),
        other => Err(anyhow!("unsupported filter {}", other)),
    }
}

fn decode_flate(data: &[u8], max_out: usize) -> Result<(Vec<u8>, bool)> {
    let mut decoder = flate2::read::ZlibDecoder::new(data);
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    let mut truncated = false;
    loop {
        let n = decoder.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if out.len() + n > max_out {
            let remaining = max_out.saturating_sub(out.len());
            out.extend_from_slice(&buf[..remaining]);
            truncated = true;
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok((out, truncated))
}

fn decode_lzw(data: &[u8], max_out: usize) -> Result<(Vec<u8>, bool)> {
    let mut decoder = weezl::decode::Decoder::new(weezl::BitOrder::Msb, 8);
    let mut out = Vec::new();
    let mut input = data;
    let mut truncated = false;
    loop {
        let res = decoder.decode_bytes(input, &mut out);
        let consumed = res.consumed_in;
        input = &input[consumed..];
        if res.status.is_ok() {
            break;
        }
        if out.len() > max_out {
            out.truncate(max_out);
            truncated = true;
            break;
        }
        if input.is_empty() {
            break;
        }
    }
    if out.len() > max_out {
        out.truncate(max_out);
        truncated = true;
    }
    Ok((out, truncated))
}

pub fn decode_ascii_hex(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = Vec::new();
    for &b in data {
        if b == b'>' {
            break;
        }
        if b.is_ascii_whitespace() {
            continue;
        }
        buf.push(b);
    }
    let mut i = 0;
    while i < buf.len() {
        let hi = hex_val(buf[i]);
        let lo = if i + 1 < buf.len() { hex_val(buf[i + 1]) } else { Some(0) };
        if let (Some(h), Some(l)) = (hi, lo) {
            out.push((h << 4) | l);
        }
        i += 2;
    }
    out
}

fn decode_ascii85(data: &[u8]) -> Result<(Vec<u8>, bool)> {
    let mut out = Vec::new();
    let mut tuple = Vec::new();
    let mut i = 0usize;
    while i < data.len() {
        let b = data[i];
        if b == b'~' && i + 1 < data.len() && data[i + 1] == b'>' {
            break;
        }
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if b == b'z' && tuple.is_empty() {
            out.extend_from_slice(&[0, 0, 0, 0]);
            i += 1;
            continue;
        }
        if b < b'!' || b > b'u' {
            i += 1;
            continue;
        }
        tuple.push(b);
        if tuple.len() == 5 {
            let mut value: u32 = 0;
            for &c in &tuple {
                value = value * 85 + (c - 33) as u32;
            }
            out.extend_from_slice(&value.to_be_bytes());
            tuple.clear();
        }
        i += 1;
    }
    if !tuple.is_empty() {
        let mut value: u32 = 0;
        let padding = 5 - tuple.len();
        for &c in &tuple {
            value = value * 85 + (c - 33) as u32;
        }
        for _ in 0..padding {
            value = value * 85 + 84;
        }
        let bytes = value.to_be_bytes();
        out.extend_from_slice(&bytes[..4 - padding]);
    }
    Ok((out, false))
}

fn decode_run_length(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < data.len() {
        let n = data[i];
        i += 1;
        if n == 128 {
            break;
        } else if n <= 127 {
            let count = (n as usize) + 1;
            if i + count > data.len() {
                break;
            }
            out.extend_from_slice(&data[i..i + count]);
            i += count;
        } else {
            let count = 257 - (n as usize);
            if i >= data.len() {
                break;
            }
            let b = data[i];
            out.extend(std::iter::repeat(b).take(count));
            i += 1;
        }
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + b - b'a'),
        b'A'..=b'F' => Some(10 + b - b'A'),
        _ => None,
    }
}
