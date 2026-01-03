use anyhow::{anyhow, Result};

use crate::lexer::{is_delim, is_whitespace, Cursor};
use crate::object::{PdfAtom, PdfDict, PdfName, PdfObj, PdfStr, PdfStream};
use crate::span::Span;
use crate::graph::ObjEntry;

pub struct Parser<'a> {
    cur: Cursor<'a>,
}

impl<'a> Parser<'a> {
    pub fn new(bytes: &'a [u8], pos: usize) -> Self {
        Self {
            cur: Cursor { bytes, pos },
        }
    }

    pub fn position(&self) -> usize {
        self.cur.pos
    }

    pub fn set_position(&mut self, pos: usize) {
        self.cur.pos = pos;
    }

    pub fn skip_ws_and_comments(&mut self) {
        self.cur.skip_ws_and_comments();
    }

    pub fn consume_keyword(&mut self, kw: &[u8]) -> bool {
        self.cur.consume_keyword(kw)
    }

    pub fn parse_object(&mut self) -> Result<PdfObj<'a>> {
        self.cur.skip_ws_and_comments();
        let start = self.cur.pos;
        let b = self.cur.peek().ok_or_else(|| anyhow!("eof"))?;
        let obj = match b {
            b'/' => self.parse_name().map(|n| PdfAtom::Name(n))?,
            b'<' => {
                if self.cur.peek_n(1) == Some(b'<') {
                    let dict = self.parse_dict()?;
                    if self.try_parse_stream(&dict)? {
                        let stream = self.parse_stream(dict)?;
                        PdfAtom::Stream(stream)
                    } else {
                        PdfAtom::Dict(dict)
                    }
                } else {
                    let s = self.parse_hex_string()?;
                    PdfAtom::Str(s)
                }
            }
            b'(' => {
                let s = self.parse_literal_string()?;
                PdfAtom::Str(s)
            }
            b'[' => {
                let arr = self.parse_array()?;
                PdfAtom::Array(arr)
            }
            b't' => {
                if self.cur.consume_keyword(b"true") {
                    PdfAtom::Bool(true)
                } else {
                    return Err(anyhow!("unexpected token"));
                }
            }
            b'f' => {
                if self.cur.consume_keyword(b"false") {
                    PdfAtom::Bool(false)
                } else {
                    return Err(anyhow!("unexpected token"));
                }
            }
            b'n' => {
                if self.cur.consume_keyword(b"null") {
                    PdfAtom::Null
                } else {
                    return Err(anyhow!("unexpected token"));
                }
            }
            b'+' | b'-' | b'.' | b'0'..=b'9' => {
                self.parse_number_or_ref()?
            }
            _ => return Err(anyhow!("unexpected byte {:x}", b)),
        };
        let end = self.cur.pos;
        Ok(PdfObj {
            span: Span {
                start: start as u64,
                end: end as u64,
            },
            atom: obj,
        })
    }

    fn parse_number_or_ref(&mut self) -> Result<PdfAtom<'a>> {
        let (_, num1_str) = self.read_number_token()?;
        let num1 = parse_number(&num1_str)?;
        let after_first = self.cur.pos;

        self.cur.skip_ws_and_comments();
        let second_mark = self.cur.mark();
        if let Ok((_, num2_str)) = self.read_number_token() {
            self.cur.skip_ws_and_comments();
            if self.cur.consume_keyword(b"R") {
                if let (Some(obj), Some(gen)) = (num1.as_i64(), parse_number(&num2_str)?.as_i64())
                {
                    if obj >= 0 && gen >= 0 {
                        return Ok(PdfAtom::Ref {
                            obj: obj as u32,
                            gen: gen as u16,
                        });
                    }
                }
            }
        }
        self.cur.restore(second_mark);
        self.cur.restore(after_first);
        Ok(match num1 {
            PdfNumber::Int(i) => PdfAtom::Int(i),
            PdfNumber::Real(f) => PdfAtom::Real(f),
        })
    }

    fn parse_array(&mut self) -> Result<Vec<PdfObj<'a>>> {
        let mut out = Vec::new();
        let _ = self.cur.consume();
        loop {
            self.cur.skip_ws_and_comments();
            if self.cur.peek() == Some(b']') {
                self.cur.consume();
                break;
            }
            if self.cur.eof() {
                break;
            }
            out.push(self.parse_object()?);
        }
        Ok(out)
    }

    fn parse_dict(&mut self) -> Result<PdfDict<'a>> {
        let start = self.cur.pos;
        self.cur.consume_keyword(b"<<");
        let mut entries = Vec::new();
        loop {
            self.cur.skip_ws_and_comments();
            if self.cur.consume_keyword(b">>") {
                break;
            }
            if self.cur.eof() {
                break;
            }
            let name = self.parse_name()?;
            self.cur.skip_ws_and_comments();
            if self.cur.peek() == Some(b'>') {
                break;
            }
            if let Ok(val) = self.parse_object() {
                entries.push((name, val));
            } else {
                entries.push((
                    name,
                    PdfObj {
                        span: Span {
                            start: self.cur.pos as u64,
                            end: self.cur.pos as u64,
                        },
                        atom: PdfAtom::Null,
                    },
                ));
            }
        }
        let end = self.cur.pos;
        Ok(PdfDict {
            span: Span {
                start: start as u64,
                end: end as u64,
            },
            entries,
        })
    }

    fn parse_name(&mut self) -> Result<PdfName<'a>> {
        let start = self.cur.pos;
        let _ = self.cur.consume();
        let raw_start = self.cur.pos;
        while let Some(b) = self.cur.peek() {
            if is_whitespace(b) || is_delim(b) {
                break;
            }
            self.cur.pos += 1;
        }
        let raw_end = self.cur.pos;
        let raw = &self.cur.bytes[start..raw_end];
        let decoded = decode_name(&self.cur.bytes[raw_start..raw_end]);
        Ok(PdfName {
            span: Span {
                start: start as u64,
                end: raw_end as u64,
            },
            raw,
            decoded,
        })
    }

    fn parse_literal_string(&mut self) -> Result<PdfStr<'a>> {
        let start = self.cur.pos;
        let _ = self.cur.consume();
        let mut depth = 1;
        let mut out = Vec::new();
        while let Some(b) = self.cur.consume() {
            match b {
                b'(' => {
                    depth += 1;
                    out.push(b);
                }
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                    out.push(b);
                }
                b'\\' => {
                    if let Some(next) = self.cur.consume() {
                        match next {
                            b'n' => out.push(b'\n'),
                            b'r' => out.push(b'\r'),
                            b't' => out.push(b'\t'),
                            b'b' => out.push(0x08),
                            b'f' => out.push(0x0c),
                            b'(' | b')' | b'\\' => out.push(next),
                            b'\n' | b'\r' => {
                                if next == b'\r' && self.cur.peek() == Some(b'\n') {
                                    self.cur.consume();
                                }
                            }
                            b'0'..=b'7' => {
                                let mut oct = vec![next];
                                for _ in 0..2 {
                                    if let Some(d) = self.cur.peek() {
                                        if (b'0'..=b'7').contains(&d) {
                                            oct.push(d);
                                            self.cur.consume();
                                        } else {
                                            break;
                                        }
                                    }
                                }
                                let val = oct
                                    .iter()
                                    .fold(0u8, |acc, d| acc * 8 + (d - b'0'));
                                out.push(val);
                            }
                            other => out.push(other),
                        }
                    }
                }
                _ => out.push(b),
            }
        }
        let end = self.cur.pos;
        Ok(PdfStr::Literal {
            span: Span {
                start: start as u64,
                end: end as u64,
            },
            raw: &self.cur.bytes[start..end],
            decoded: out,
        })
    }

    fn parse_hex_string(&mut self) -> Result<PdfStr<'a>> {
        let start = self.cur.pos;
        let _ = self.cur.consume();
        let mut out = Vec::new();
        let mut buf = Vec::new();
        while let Some(b) = self.cur.consume() {
            if b == b'>' {
                break;
            }
            if is_whitespace(b) {
                continue;
            }
            buf.push(b);
        }
        let mut i = 0;
        while i < buf.len() {
            let hi = buf[i];
            let lo = if i + 1 < buf.len() { buf[i + 1] } else { b'0' };
            if let (Some(h), Some(l)) = (hex_val(hi), hex_val(lo)) {
                out.push((h << 4) | l);
            }
            i += 2;
        }
        let end = self.cur.pos;
        Ok(PdfStr::Hex {
            span: Span {
                start: start as u64,
                end: end as u64,
            },
            raw: &self.cur.bytes[start..end],
            decoded: out,
        })
    }

    fn read_number_token(&mut self) -> Result<(Span, String)> {
        let start = self.cur.pos;
        let mut out = Vec::new();
        if let Some(b) = self.cur.peek() {
            if b == b'+' || b == b'-' || b == b'.' || (b'0'..=b'9').contains(&b) {
                out.push(b);
                self.cur.consume();
            } else {
                return Err(anyhow!("not a number"));
            }
        }
        while let Some(b) = self.cur.peek() {
            if (b'0'..=b'9').contains(&b) || b == b'.' {
                out.push(b);
                self.cur.consume();
            } else {
                break;
            }
        }
        let end = self.cur.pos;
        Ok((
            Span {
                start: start as u64,
                end: end as u64,
            },
            String::from_utf8_lossy(&out).to_string(),
        ))
    }

    fn try_parse_stream(&mut self, _dict: &PdfDict<'a>) -> Result<bool> {
        let mark = self.cur.mark();
        self.cur.skip_ws_and_comments();
        if self.cur.consume_keyword(b"stream") {
            self.cur.restore(mark);
            return Ok(true);
        }
        self.cur.restore(mark);
        Ok(false)
    }

    fn parse_stream(&mut self, dict: PdfDict<'a>) -> Result<PdfStream<'a>> {
        self.cur.skip_ws_and_comments();
        self.cur.consume_keyword(b"stream");
        if self.cur.peek() == Some(b'\r') {
            self.cur.consume();
            if self.cur.peek() == Some(b'\n') {
                self.cur.consume();
            }
        } else if self.cur.peek() == Some(b'\n') {
            self.cur.consume();
        }
        let data_start = self.cur.pos;
        let length = stream_length_from_dict(&dict);
        let data_end = if let Some(len) = length {
            let end = data_start.saturating_add(len as usize);
            end.min(self.cur.bytes.len())
        } else {
            find_endstream(self.cur.bytes, data_start).unwrap_or(self.cur.bytes.len())
        };
        self.cur.pos = data_end;
        let _ = consume_endstream(self.cur.bytes, &mut self.cur.pos);
        Ok(PdfStream {
            dict,
            data_span: Span {
                start: data_start as u64,
                end: data_end as u64,
            },
        })
    }
}

#[derive(Debug)]
enum PdfNumber {
    Int(i64),
    Real(f64),
}

impl PdfNumber {
    fn as_i64(&self) -> Option<i64> {
        match self {
            PdfNumber::Int(i) => Some(*i),
            PdfNumber::Real(_) => None,
        }
    }
}

fn parse_number(s: &str) -> Result<PdfNumber> {
    if s.contains('.') {
        Ok(PdfNumber::Real(s.parse::<f64>()?))
    } else {
        Ok(PdfNumber::Int(s.parse::<i64>()?))
    }
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + b - b'a'),
        b'A'..=b'F' => Some(10 + b - b'A'),
        _ => None,
    }
}

fn decode_name(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + 1);
    out.push(b'/');
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'#' && i + 2 < raw.len() {
            if let (Some(h), Some(l)) = (hex_val(raw[i + 1]), hex_val(raw[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(raw[i]);
        i += 1;
    }
    out
}

fn stream_length_from_dict(dict: &PdfDict<'_>) -> Option<u64> {
    let (_, obj) = dict.get_first(b"/Length")?;
    match &obj.atom {
        PdfAtom::Int(i) if *i >= 0 => Some(*i as u64),
        _ => None,
    }
}

fn find_endstream(bytes: &[u8], start: usize) -> Option<usize> {
    let needle = b"endstream";
    let mut i = start;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn consume_endstream(bytes: &[u8], pos: &mut usize) -> bool {
    let needle = b"endstream";
    if *pos + needle.len() <= bytes.len() && &bytes[*pos..*pos + needle.len()] == needle {
        *pos += needle.len();
        true
    } else {
        false
    }
}

pub fn parse_indirect_object_at<'a>(
    bytes: &'a [u8],
    offset: usize,
) -> Result<(ObjEntry<'a>, usize)> {
    let mut p = Parser::new(bytes, offset);
    p.cur.skip_ws_and_comments();
    let header_start = p.cur.pos;
    let (_, obj_str) = p.read_number_token()?;
    p.cur.skip_ws_and_comments();
    let (_, gen_str) = p.read_number_token()?;
    p.cur.skip_ws_and_comments();
    if !p.cur.consume_keyword(b"obj") {
        return Err(anyhow!("missing obj keyword"));
    }
    let header_end = p.cur.pos;
    let obj_num = obj_str.parse::<u32>()?;
    let gen_num = gen_str.parse::<u16>()?;
    p.cur.skip_ws_and_comments();
    let body_start = p.cur.pos;
    let obj = p.parse_object()?;
    let body_end = p.cur.pos;
    p.cur.skip_ws_and_comments();
    if !p.cur.consume_keyword(b"endobj") {
        if let Some(pos) = memchr::memmem::find(&bytes[p.cur.pos..], b"endobj") {
            p.cur.pos += pos + "endobj".len();
        }
    }
    let full_end = p.cur.pos;
    let entry = ObjEntry {
        obj: obj_num,
        gen: gen_num,
        atom: obj.atom,
        header_span: Span {
            start: header_start as u64,
            end: header_end as u64,
        },
        body_span: Span {
            start: body_start as u64,
            end: body_end as u64,
        },
        full_span: Span {
            start: header_start as u64,
            end: full_end as u64,
        },
    };
    Ok((entry, full_end))
}

pub fn scan_indirect_objects<'a>(bytes: &'a [u8]) -> Vec<ObjEntry<'a>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 7 < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let mark = i;
        if let Ok((entry, end_pos)) = parse_indirect_object_at(bytes, i) {
            out.push(entry);
            i = end_pos;
        } else {
            i = mark + 1;
        }
    }
    out
}
