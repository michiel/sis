use crate::decode::decode_stream;
use crate::graph::ObjEntry;
use crate::object::{PdfAtom, PdfDict};
use crate::parser::Parser;
use crate::span::Span;

const MAX_OBJSTM_COUNT: usize = 100;

pub struct ObjStmExpansion<'a> {
    pub objects: Vec<ObjEntry<'a>>,
}

pub fn expand_objstm<'a>(
    bytes: &'a [u8],
    objects: &[ObjEntry<'a>],
    strict: bool,
    max_objstm_bytes: usize,
    max_objects_total: usize,
    max_total_decoded_bytes: usize,
) -> ObjStmExpansion<'a> {
    let mut out = Vec::new();
    let mut decoded_total = 0usize;
    let mut objstm_count = 0usize;
    let mut warned_total = false;
    for entry in objects {
        if max_objects_total > 0 && objects.len() + out.len() >= max_objects_total {
            eprintln!(
                "security_boundary: objstm expansion halted; max_objects_total {} reached",
                max_objects_total
            );
            break;
        }
        let st = match &entry.atom {
            PdfAtom::Stream(st) => st,
            _ => continue,
        };
        if !st.dict.has_name(b"/Type", b"/ObjStm") {
            continue;
        }
        objstm_count += 1;
        if objstm_count == 11 {
            eprintln!(
                "security_boundary: high ObjStm count detected ({} so far)",
                objstm_count
            );
        }
        if objstm_count > MAX_OBJSTM_COUNT {
            eprintln!(
                "security_boundary: objstm expansion halted; max ObjStm count {} exceeded",
                MAX_OBJSTM_COUNT
            );
            break;
        }
        let n = match dict_int(&st.dict, b"/N") {
            Some(v) => v as usize,
            None => continue,
        };
        let first = match dict_int(&st.dict, b"/First") {
            Some(v) => v as usize,
            None => continue,
        };
        if max_total_decoded_bytes > 0 {
            if decoded_total >= max_total_decoded_bytes {
                eprintln!(
                    "security_boundary: objstm expansion halted; total decoded budget {} reached",
                    max_total_decoded_bytes
                );
                break;
            }
            if decoded_total.saturating_add(max_objstm_bytes) > max_total_decoded_bytes {
                eprintln!(
                    "security_boundary: objstm expansion halted; decoding next ObjStm would exceed budget ({} + {} > {})",
                    decoded_total,
                    max_objstm_bytes,
                    max_total_decoded_bytes
                );
                break;
            }
        }
        let decoded = match decode_stream(bytes, st, max_objstm_bytes) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if max_total_decoded_bytes > 0 {
            decoded_total = decoded_total.saturating_add(decoded.data.len());
            if !warned_total && decoded_total > 100 * 1024 * 1024 {
                warned_total = true;
                eprintln!(
                    "security_boundary: ObjStm decoded bytes exceed 100MB (total={})",
                    decoded_total
                );
            }
            if decoded_total > max_total_decoded_bytes {
                eprintln!(
                    "security_boundary: objstm expansion halted; decoded bytes {} exceeded budget {}",
                    decoded_total,
                    max_total_decoded_bytes
                );
                break;
            }
        }
        if decoded.data.len() <= first {
            continue;
        }
        let data = decoded.data;
        let header = &data[..first];
        let tokens = parse_header_tokens(header, n * 2);
        if tokens.len() < n * 2 {
            continue;
        }
        for idx in 0..n {
            if max_objects_total > 0 && objects.len() + out.len() >= max_objects_total {
                eprintln!(
                    "security_boundary: objstm expansion halted; max_objects_total {} reached",
                    max_objects_total
                );
                break;
            }
            let obj_num = tokens[idx * 2] as u32;
            if obj_num == entry.obj {
                eprintln!(
                    "security_boundary: detected recursive ObjStm reference to {}",
                    obj_num
                );
                continue;
            }
            let offset = tokens[idx * 2 + 1] as usize;
            let obj_start = first.saturating_add(offset);
            if obj_start >= data.len() {
                continue;
            }
            let mut parser = Parser::new(&data, obj_start, strict);
            let parsed = match parser.parse_object() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let parsed = own_obj(parsed);
            if let PdfAtom::Stream(st) = &parsed.atom {
                if st.dict.has_name(b"/Type", b"/ObjStm") {
                    eprintln!(
                        "security_boundary: ObjStm entry {} references another ObjStm object",
                        obj_num
                    );
                    continue;
                }
            }
            let obj_end = parser.position();
            let span = Span {
                start: st.data_span.start,
                end: st.data_span.end,
            };
            out.push(ObjEntry {
                obj: obj_num,
                gen: 0,
                atom: crate::object::PdfObj {
                    span,
                    atom: parsed.atom,
                }
                .atom,
                header_span: span,
                body_span: span,
                full_span: span,
            });
            let _ = obj_end;
        }
    }
    ObjStmExpansion { objects: out }
}

fn dict_int(dict: &PdfDict<'_>, key: &[u8]) -> Option<u64> {
    let (_, obj) = dict.get_first(key)?;
    match &obj.atom {
        PdfAtom::Int(i) if *i >= 0 => Some(*i as u64),
        _ => None,
    }
}

fn parse_header_tokens(bytes: &[u8], max: usize) -> Vec<u64> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() && out.len() < max {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if start == i {
            break;
        }
        if let Ok(v) = std::str::from_utf8(&bytes[start..i]) {
            if let Ok(num) = v.parse::<u64>() {
                out.push(num);
            }
        }
    }
    out
}

fn own_obj(obj: crate::object::PdfObj<'_>) -> crate::object::PdfObj<'static> {
    use crate::object::{PdfAtom, PdfDict, PdfName, PdfObj, PdfStr, PdfStream};
    use std::borrow::Cow;

    fn own_name(name: PdfName<'_>) -> PdfName<'static> {
        PdfName {
            span: name.span,
            raw: Cow::Owned(name.raw.into_owned()),
            decoded: name.decoded,
        }
    }

    fn own_str(s: PdfStr<'_>) -> PdfStr<'static> {
        match s {
            PdfStr::Literal { span, raw, decoded } => PdfStr::Literal {
                span,
                raw: Cow::Owned(raw.into_owned()),
                decoded,
            },
            PdfStr::Hex { span, raw, decoded } => PdfStr::Hex {
                span,
                raw: Cow::Owned(raw.into_owned()),
                decoded,
            },
        }
    }

    fn own_dict(dict: PdfDict<'_>) -> PdfDict<'static> {
        let entries = dict
            .entries
            .into_iter()
            .map(|(k, v)| (own_name(k), own_obj(v)))
            .collect();
        PdfDict {
            span: dict.span,
            entries,
        }
    }

    fn own_stream(stream: PdfStream<'_>) -> PdfStream<'static> {
        PdfStream {
            dict: own_dict(stream.dict),
            data_span: stream.data_span,
        }
    }

    let atom = match obj.atom {
        PdfAtom::Null => PdfAtom::Null,
        PdfAtom::Bool(v) => PdfAtom::Bool(v),
        PdfAtom::Int(v) => PdfAtom::Int(v),
        PdfAtom::Real(v) => PdfAtom::Real(v),
        PdfAtom::Ref { obj, gen } => PdfAtom::Ref { obj, gen },
        PdfAtom::Name(name) => PdfAtom::Name(own_name(name)),
        PdfAtom::Str(s) => PdfAtom::Str(own_str(s)),
        PdfAtom::Array(arr) => PdfAtom::Array(arr.into_iter().map(own_obj).collect()),
        PdfAtom::Dict(d) => PdfAtom::Dict(own_dict(d)),
        PdfAtom::Stream(st) => PdfAtom::Stream(own_stream(st)),
    };
    PdfObj {
        span: obj.span,
        atom,
    }
}
