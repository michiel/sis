use std::collections::HashMap;
use std::sync::Mutex;

use ysnp_pdf::decode::{decode_stream, DecodedStream};
use ysnp_pdf::object::PdfStream;
use ysnp_pdf::span::Span;
use ysnp_pdf::ObjectGraph;

#[derive(Debug, Clone, Copy)]
pub struct ScanOptions {
    pub deep: bool,
    pub max_decode_bytes: usize,
    pub recover_xref: bool,
    pub parallel: bool,
}

pub struct ScanContext<'a> {
    pub bytes: &'a [u8],
    pub graph: ObjectGraph<'a>,
    pub decoded: DecodedCache,
    pub options: ScanOptions,
}

#[derive(Debug)]
pub struct DecodedCache {
    max_decode_bytes: usize,
    cache: Mutex<HashMap<(u64, u64), DecodedStream>>,
}

impl DecodedCache {
    pub fn new(max_decode_bytes: usize) -> Self {
        Self {
            max_decode_bytes,
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn get_or_decode(
        &self,
        bytes: &[u8],
        stream: &PdfStream<'_>,
    ) -> anyhow::Result<DecodedStream> {
        let key = (stream.data_span.start, stream.data_span.end);
        if let Some(v) = self.cache.lock().ok().and_then(|c| c.get(&key).cloned()) {
            return Ok(v);
        }
        let decoded = decode_stream(bytes, stream, self.max_decode_bytes)?;
        if let Ok(mut c) = self.cache.lock() {
            c.insert(key, decoded.clone());
        }
        Ok(decoded)
    }
}

pub fn span_to_evidence(span: Span, note: &str) -> crate::model::EvidenceSpan {
    crate::model::EvidenceSpan {
        source: crate::model::EvidenceSource::File,
        offset: span.start,
        length: span.len().min(u64::from(u32::MAX)) as u32,
        origin: None,
        note: Some(note.to_string()),
    }
}
