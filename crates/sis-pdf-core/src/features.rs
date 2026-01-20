use std::collections::HashMap;

use crate::page_tree::build_page_tree;
use crate::scan::{ScanContext, ScanOptions};
use image_analysis::ImageDynamicOptions;
use sis_pdf_pdf::classification::ObjectRole;
use sis_pdf_pdf::decode::{decode_stream_with_meta, DecodeLimits};
use sis_pdf_pdf::graph::ObjEntry;
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj, PdfStr, PdfStream};
use sis_pdf_pdf::typed_graph::EdgeType;
use sis_pdf_pdf::{parse_pdf, ParseOptions};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct GeneralFeatures {
    pub file_size: usize,
    pub file_entropy: f64,
    pub binary_ratio: f64,
    pub object_count: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct StructuralFeatures {
    pub startxref_count: usize,
    pub trailer_count: usize,
    pub objstm_count: usize,
    pub linearized_present: bool,
    pub max_object_id: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct BehavioralFeatures {
    pub action_count: usize,
    pub js_object_count: usize,
    pub js_entropy_avg: f64,
    pub js_eval_count: usize,
    pub js_suspicious_api_count: usize,
    pub time_api_count: usize,
    pub env_probe_count: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct ContentFeatures {
    pub embedded_file_count: usize,
    pub rich_media_count: usize,
    pub annotation_count: usize,
    pub page_count: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct ImageFeatures {
    pub image_count: usize,
    pub jbig2_count: usize,
    pub jpx_count: usize,
    pub jpeg_count: usize,
    pub png_count: usize,
    pub ccitt_count: usize,
    pub risky_image_count: usize,
    pub malformed_image_count: usize,
    pub max_image_width: u32,
    pub max_image_height: u32,
    pub max_image_pixels: u64,
    pub total_image_pixels: u64,
    pub avg_image_entropy: f64,
    pub extreme_dimensions_count: usize,
    pub multi_filter_count: usize,
    pub xfa_image_count: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct GraphFeatures {
    pub total_edges: usize,
    pub open_action_edges: usize,
    pub js_payload_edges: usize,
    pub uri_target_edges: usize,
    pub launch_target_edges: usize,
    pub suspicious_edge_count: usize,
    pub action_chain_count: usize,
    pub max_chain_length: usize,
    pub automatic_chain_count: usize,
    pub js_chain_count: usize,
    pub external_chain_count: usize,
    pub max_graph_depth: usize,
    pub avg_graph_depth: f64,
    pub catalog_to_js_paths: usize,
    pub multi_stage_indicators: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FeatureVector {
    pub general: GeneralFeatures,
    pub structural: StructuralFeatures,
    pub behavioral: BehavioralFeatures,
    pub content: ContentFeatures,
    pub graph: GraphFeatures,
    pub images: ImageFeatures,
}

impl FeatureVector {
    pub fn as_f32_vec(&self) -> Vec<f32> {
        vec![
            self.general.file_size as f32,
            self.general.file_entropy as f32,
            self.general.binary_ratio as f32,
            self.general.object_count as f32,
            self.structural.startxref_count as f32,
            self.structural.trailer_count as f32,
            self.structural.objstm_count as f32,
            bool_to_f32(self.structural.linearized_present),
            self.structural.max_object_id as f32,
            self.behavioral.action_count as f32,
            self.behavioral.js_object_count as f32,
            self.behavioral.js_entropy_avg as f32,
            self.behavioral.js_eval_count as f32,
            self.behavioral.js_suspicious_api_count as f32,
            self.behavioral.time_api_count as f32,
            self.behavioral.env_probe_count as f32,
            self.content.embedded_file_count as f32,
            self.content.rich_media_count as f32,
            self.content.annotation_count as f32,
            self.content.page_count as f32,
            self.graph.total_edges as f32,
            self.graph.open_action_edges as f32,
            self.graph.js_payload_edges as f32,
            self.graph.uri_target_edges as f32,
            self.graph.launch_target_edges as f32,
            self.graph.suspicious_edge_count as f32,
            self.graph.action_chain_count as f32,
            self.graph.max_chain_length as f32,
            self.graph.automatic_chain_count as f32,
            self.graph.js_chain_count as f32,
            self.graph.external_chain_count as f32,
            self.graph.max_graph_depth as f32,
            self.graph.avg_graph_depth as f32,
            self.graph.catalog_to_js_paths as f32,
            self.graph.multi_stage_indicators as f32,
            self.images.image_count as f32,
            self.images.jbig2_count as f32,
            self.images.jpx_count as f32,
            self.images.jpeg_count as f32,
            self.images.png_count as f32,
            self.images.ccitt_count as f32,
            self.images.risky_image_count as f32,
            self.images.malformed_image_count as f32,
            self.images.max_image_width as f32,
            self.images.max_image_height as f32,
            self.images.max_image_pixels as f32,
            self.images.total_image_pixels as f32,
            self.images.avg_image_entropy as f32,
            self.images.extreme_dimensions_count as f32,
            self.images.multi_filter_count as f32,
            self.images.xfa_image_count as f32,
        ]
    }
}

pub fn feature_names() -> Vec<&'static str> {
    vec![
        "general.file_size",
        "general.file_entropy",
        "general.binary_ratio",
        "general.object_count",
        "structural.startxref_count",
        "structural.trailer_count",
        "structural.objstm_count",
        "structural.linearized_present",
        "structural.max_object_id",
        "behavior.action_count",
        "behavior.js_object_count",
        "behavior.js_entropy_avg",
        "behavior.js_eval_count",
        "behavior.js_suspicious_api_count",
        "behavior.time_api_count",
        "behavior.env_probe_count",
        "content.embedded_file_count",
        "content.rich_media_count",
        "content.annotation_count",
        "content.page_count",
        "graph.total_edges",
        "graph.open_action_edges",
        "graph.js_payload_edges",
        "graph.uri_target_edges",
        "graph.launch_target_edges",
        "graph.suspicious_edge_count",
        "graph.action_chain_count",
        "graph.max_chain_length",
        "graph.automatic_chain_count",
        "graph.js_chain_count",
        "graph.external_chain_count",
        "graph.max_graph_depth",
        "graph.avg_graph_depth",
        "graph.catalog_to_js_paths",
        "graph.multi_stage_indicators",
        "images.image_count",
        "images.jbig2_count",
        "images.jpx_count",
        "images.jpeg_count",
        "images.png_count",
        "images.ccitt_count",
        "images.risky_image_count",
        "images.malformed_image_count",
        "images.max_image_width",
        "images.max_image_height",
        "images.max_image_pixels",
        "images.total_image_pixels",
        "images.avg_image_entropy",
        "images.extreme_dimensions_count",
        "images.multi_filter_count",
        "images.xfa_image_count",
    ]
}

pub struct FeatureExtractor;

impl FeatureExtractor {
    pub fn extract(ctx: &ScanContext) -> FeatureVector {
        let graph = &ctx.graph;
        let bytes = ctx.bytes;
        let file_entropy = shannon_entropy(bytes);
        let binary_ratio = binary_ratio(bytes);
        let max_object_id = graph.objects.iter().map(|e| e.obj).max().unwrap_or(0);

        let objstm_count = graph
            .objects
            .iter()
            .filter(|e| {
                entry_dict(e)
                    .map(|d| d.has_name(b"/Type", b"/ObjStm"))
                    .unwrap_or(false)
            })
            .count();

        let linearized_present = graph.objects.iter().any(|e| {
            entry_dict(e)
                .and_then(|d| d.get_first(b"/Linearized"))
                .is_some()
        });

        let mut action_count = 0usize;
        let mut js_object_count = 0usize;
        let mut embedded_file_count = 0usize;
        let mut rich_media_count = 0usize;
        let mut annotation_count = 0usize;
        let mut js_payloads = Vec::new();

        for entry in &graph.objects {
            if let Some(dict) = entry_dict(entry) {
                if let Some((_, s)) = dict.get_first(b"/S") {
                    if let Some(name) = name_bytes(s) {
                        if name.eq_ignore_ascii_case(b"/JavaScript")
                            || name.eq_ignore_ascii_case(b"/Launch")
                            || name.eq_ignore_ascii_case(b"/URI")
                            || name.eq_ignore_ascii_case(b"/GoToR")
                            || name.eq_ignore_ascii_case(b"/SubmitForm")
                        {
                            action_count += 1;
                        }
                    }
                }
                if dict.get_first(b"/JS").is_some() || dict.has_name(b"/S", b"/JavaScript") {
                    js_object_count += 1;
                    if let Some((_, obj)) = dict.get_first(b"/JS") {
                        if let Some(bytes) = resolve_obj_bytes(ctx, obj, 512 * 1024) {
                            js_payloads.push(bytes);
                        }
                    }
                }
                if dict.has_name(b"/Type", b"/Filespec")
                    || dict.has_name(b"/Type", b"/EmbeddedFile")
                    || dict.get_first(b"/EF").is_some()
                {
                    embedded_file_count += 1;
                }
                if dict.has_name(b"/Subtype", b"/RichMedia")
                    || dict.has_name(b"/Subtype", b"/3D")
                    || dict.has_name(b"/Subtype", b"/Sound")
                    || dict.has_name(b"/Subtype", b"/Movie")
                {
                    rich_media_count += 1;
                }
                if dict.get_first(b"/Subtype").is_some() && dict.get_first(b"/Rect").is_some() {
                    annotation_count += 1;
                }
            }
        }

        let (
            js_entropy_avg,
            js_eval_count,
            js_suspicious_api_count,
            time_api_count,
            env_probe_count,
        ) = summarize_js_payloads(&js_payloads);

        let page_count = build_page_tree(graph).pages.len();

        let image_features = extract_image_features(ctx);

        // Extract graph-based features using TypedGraph infrastructure
        let graph_features = extract_graph_features(ctx);

        FeatureVector {
            general: GeneralFeatures {
                file_size: bytes.len(),
                file_entropy,
                binary_ratio,
                object_count: graph.objects.len(),
            },
            structural: StructuralFeatures {
                startxref_count: graph.startxrefs.len(),
                trailer_count: graph.trailers.len(),
                objstm_count,
                linearized_present,
                max_object_id,
            },
            behavioral: BehavioralFeatures {
                action_count,
                js_object_count,
                js_entropy_avg,
                js_eval_count,
                js_suspicious_api_count,
                time_api_count,
                env_probe_count,
            },
            content: ContentFeatures {
                embedded_file_count,
                rich_media_count,
                annotation_count,
                page_count,
            },
            graph: graph_features,
            images: image_features,
        }
    }

    pub fn extract_from_bytes(bytes: &[u8], opts: &ScanOptions) -> anyhow::Result<FeatureVector> {
        let graph = parse_pdf(
            bytes,
            ParseOptions {
                recover_xref: opts.recover_xref,
                deep: opts.deep,
                strict: opts.strict,
                max_objstm_bytes: opts.max_decode_bytes,
                max_objects: opts.max_objects,
                max_objstm_total_bytes: opts.max_total_decoded_bytes,
                carve_stream_objects: false,
                max_carved_objects: 0,
                max_carved_bytes: 0,
            },
        )?;
        let ctx = ScanContext::new(bytes, graph, opts.clone());
        Ok(Self::extract(&ctx))
    }
}

fn bool_to_f32(v: bool) -> f32 {
    if v {
        1.0
    } else {
        0.0
    }
}

fn entry_dict<'a>(entry: &'a ObjEntry<'a>) -> Option<&'a PdfDict<'a>> {
    match &entry.atom {
        PdfAtom::Dict(d) => Some(d),
        PdfAtom::Stream(st) => Some(&st.dict),
        _ => None,
    }
}

fn name_bytes<'a>(obj: &'a PdfObj<'a>) -> Option<&'a [u8]> {
    match &obj.atom {
        PdfAtom::Name(n) => Some(&n.decoded),
        _ => None,
    }
}

fn resolve_obj_bytes(ctx: &ScanContext, obj: &PdfObj<'_>, max_len: usize) -> Option<Vec<u8>> {
    match &obj.atom {
        PdfAtom::Str(s) => Some(string_bytes(s)),
        PdfAtom::Stream(st) => decoded_stream_bytes(ctx, st, max_len),
        PdfAtom::Ref { .. } => {
            let entry = ctx.graph.resolve_ref(obj)?;
            match &entry.atom {
                PdfAtom::Str(s) => Some(string_bytes(s)),
                PdfAtom::Stream(st) => decoded_stream_bytes(ctx, st, max_len),
                _ => None,
            }
        }
        _ => None,
    }
}

fn decoded_stream_bytes(ctx: &ScanContext, st: &PdfStream<'_>, max_len: usize) -> Option<Vec<u8>> {
    match ctx.decoded.get_or_decode(ctx.bytes, st) {
        Ok(decoded) => Some(decoded.data.into_iter().take(max_len).collect()),
        Err(_) => None,
    }
}

fn string_bytes(s: &PdfStr<'_>) -> Vec<u8> {
    match s {
        PdfStr::Literal { decoded, .. } => decoded.clone(),
        PdfStr::Hex { decoded, .. } => decoded.clone(),
    }
}

fn summarize_js_payloads(payloads: &[Vec<u8>]) -> (f64, usize, usize, usize, usize) {
    if payloads.is_empty() {
        return (0.0, 0, 0, 0, 0);
    }
    let mut ent_total = 0.0;
    let mut eval_count = 0usize;
    let mut suspicious_api_count = 0usize;
    let mut time_api_count = 0usize;
    let mut env_probe_count = 0usize;

    for data in payloads {
        ent_total += shannon_entropy(data);
        if contains_token(data, b"eval") {
            eval_count += 1;
        }
        if contains_any(
            data,
            &[
                b"app.launchURL",
                b"submitForm",
                b"getURL",
                b"app.execMenuItem",
            ],
        ) {
            suspicious_api_count += 1;
        }
        if contains_any(
            data,
            &[b"setTimeout", b"setInterval", b"Date(", b"performance.now"],
        ) {
            time_api_count += 1;
        }
        if contains_any(
            data,
            &[
                b"app.viewerType",
                b"app.viewerVersion",
                b"app.platform",
                b"navigator.userAgent",
                b"screen.height",
                b"screen.width",
            ],
        ) {
            env_probe_count += 1;
        }
    }

    let avg_entropy = ent_total / payloads.len() as f64;
    (
        avg_entropy,
        eval_count,
        suspicious_api_count,
        time_api_count,
        env_probe_count,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImageFormat {
    JBIG2,
    JPX,
    JPEG,
    PNG,
    CCITT,
    TIFF,
    Unknown,
}

fn extract_image_features(ctx: &ScanContext) -> ImageFeatures {
    let mut features = ImageFeatures::default();
    let mut entropy_total = 0.0;
    let mut entropy_count = 0usize;

    for entry in &ctx.graph.objects {
        let Some(dict) = entry_dict(entry) else {
            continue;
        };
        if !is_image_xobject(dict) {
            continue;
        }
        features.image_count += 1;
        let format = detect_image_format(ctx, entry, dict);
        match format {
            ImageFormat::JBIG2 => {
                features.jbig2_count += 1;
                features.risky_image_count += 1;
            }
            ImageFormat::JPX => {
                features.jpx_count += 1;
                features.risky_image_count += 1;
            }
            ImageFormat::JPEG => features.jpeg_count += 1,
            ImageFormat::PNG => features.png_count += 1,
            ImageFormat::CCITT => {
                features.ccitt_count += 1;
                features.risky_image_count += 1;
            }
            ImageFormat::TIFF => {}
            ImageFormat::Unknown => {}
        }

        if has_multi_filter(dict) {
            features.multi_filter_count += 1;
        }

        if let Some((width, height)) = image_dimensions(dict) {
            features.max_image_width = features.max_image_width.max(width);
            features.max_image_height = features.max_image_height.max(height);
            let pixels = width as u64 * height as u64;
            features.max_image_pixels = features.max_image_pixels.max(pixels);
            features.total_image_pixels += pixels;
            if width == 1 || height == 1 {
                features.extreme_dimensions_count += 1;
            }
        }

        if let Some(data) = image_stream_bytes(ctx, entry, 512 * 1024) {
            entropy_total += shannon_entropy(&data);
            entropy_count += 1;
        }
    }

    if entropy_count > 0 {
        features.avg_image_entropy = entropy_total / entropy_count as f64;
    }

    features.xfa_image_count = count_xfa_images(ctx);
    features.malformed_image_count = count_malformed_images(ctx);

    features
}

fn is_image_xobject(dict: &PdfDict<'_>) -> bool {
    dict.has_name(b"/Subtype", b"/Image")
}

fn image_dimensions(dict: &PdfDict<'_>) -> Option<(u32, u32)> {
    let width = dict_u32(dict, b"/Width")?;
    let height = dict_u32(dict, b"/Height")?;
    Some((width, height))
}

fn dict_u32(dict: &PdfDict<'_>, key: &[u8]) -> Option<u32> {
    let (_, obj) = dict.get_first(key)?;
    match &obj.atom {
        PdfAtom::Int(v) => (*v).try_into().ok(),
        PdfAtom::Real(v) => {
            if *v >= 0.0 {
                (*v as u64).try_into().ok()
            } else {
                None
            }
        }
        PdfAtom::Str(s) => {
            let bytes = string_bytes(s);
            let text = String::from_utf8_lossy(&bytes);
            text.trim().parse::<u32>().ok()
        }
        _ => None,
    }
}

fn has_multi_filter(dict: &PdfDict<'_>) -> bool {
    let Some((_, filter)) = dict.get_first(b"/Filter") else {
        return false;
    };
    match &filter.atom {
        PdfAtom::Array(values) => values.len() > 1,
        _ => false,
    }
}

fn detect_image_format(
    ctx: &ScanContext,
    entry: &ObjEntry<'_>,
    dict: &PdfDict<'_>,
) -> ImageFormat {
    if let Some(filters) = image_filters(dict) {
        for filter in filters {
            if filter.eq_ignore_ascii_case(b"/JBIG2Decode") {
                return ImageFormat::JBIG2;
            }
            if filter.eq_ignore_ascii_case(b"/JPXDecode") {
                return ImageFormat::JPX;
            }
            if filter.eq_ignore_ascii_case(b"/CCITTFaxDecode") {
                return ImageFormat::CCITT;
            }
            if filter.eq_ignore_ascii_case(b"/DCTDecode") || filter.eq_ignore_ascii_case(b"/DCT") {
                return ImageFormat::JPEG;
            }
        }
    }
    if let Some(data) = image_stream_bytes(ctx, entry, 64) {
        if data.starts_with(b"\xFF\xD8") {
            return ImageFormat::JPEG;
        }
        if data.starts_with(b"\x89PNG\r\n\x1a\n") {
            return ImageFormat::PNG;
        }
        if data.starts_with(b"II*\x00") || data.starts_with(b"MM\x00*") {
            return ImageFormat::TIFF;
        }
    }
    ImageFormat::Unknown
}

fn image_filters(dict: &PdfDict<'_>) -> Option<Vec<Vec<u8>>> {
    let (_, filter) = dict.get_first(b"/Filter")?;
    match &filter.atom {
        PdfAtom::Name(name) => Some(vec![name.decoded.clone()]),
        PdfAtom::Array(items) => {
            let mut out = Vec::new();
            for item in items {
                if let PdfAtom::Name(name) = &item.atom {
                    out.push(name.decoded.clone());
                }
            }
            Some(out)
        }
        _ => None,
    }
}

fn image_stream_bytes(ctx: &ScanContext, entry: &ObjEntry<'_>, max_len: usize) -> Option<Vec<u8>> {
    let PdfAtom::Stream(stream) = &entry.atom else {
        return None;
    };
    let span = stream.data_span;
    let start = span.start as usize;
    let end = span.end as usize;
    if start >= end || end > ctx.bytes.len() {
        return None;
    }
    let data = &ctx.bytes[start..end];
    if max_len > 0 {
        Some(data[..data.len().min(max_len)].to_vec())
    } else {
        Some(data.to_vec())
    }
}

fn count_xfa_images(ctx: &ScanContext) -> usize {
    let mut count = 0usize;
    let limits = DecodeLimits {
        max_decoded_bytes: ctx.options.image_analysis.max_xfa_decode_bytes,
        max_filter_chain_depth: ctx.options.image_analysis.max_filter_chain_depth,
    };
    for entry in &ctx.graph.objects {
        let dict = match &entry.atom {
            PdfAtom::Dict(dict) => dict,
            PdfAtom::Stream(stream) => &stream.dict,
            _ => continue,
        };
        let Some((_, xfa_obj)) = dict.get_first(b"/XFA") else {
            continue;
        };
        for payload in xfa_payloads_from_obj(&ctx.graph, xfa_obj, limits) {
            count += sis_pdf_pdf::xfa::extract_xfa_image_payloads(&payload).len();
        }
    }
    count
}

fn count_malformed_images(ctx: &ScanContext) -> usize {
    if !ctx.options.image_analysis.enabled
        || !ctx.options.deep
        || !ctx.options.image_analysis.dynamic_enabled
    {
        return 0;
    }
    let opts = ImageDynamicOptions {
        max_pixels: ctx.options.image_analysis.max_pixels,
        max_decode_bytes: ctx.options.image_analysis.max_decode_bytes,
        timeout_ms: ctx.options.image_analysis.timeout_ms,
    };
    let dynamic = image_analysis::dynamic::analyze_dynamic_images(&ctx.graph, &opts);
    dynamic
        .findings
        .iter()
        .filter(|f| {
            matches!(
                f.kind.as_str(),
                "image.decode_failed"
                    | "image.jbig2_malformed"
                    | "image.jpx_malformed"
                    | "image.jpeg_malformed"
                    | "image.ccitt_malformed"
                    | "image.xfa_decode_failed"
            )
        })
        .count()
}

fn xfa_payloads_from_obj(
    graph: &sis_pdf_pdf::ObjectGraph<'_>,
    obj: &PdfObj<'_>,
    limits: DecodeLimits,
) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    match &obj.atom {
        PdfAtom::Array(items) => {
            let mut iter = items.iter().peekable();
            while let Some(item) = iter.next() {
                match &item.atom {
                    PdfAtom::Name(_) | PdfAtom::Str(_) => {
                        if let Some(next) = iter.next() {
                            out.extend(resolve_xfa_payload(graph, next, limits));
                        }
                    }
                    _ => {
                        out.extend(resolve_xfa_payload(graph, item, limits));
                    }
                }
            }
        }
        _ => out.extend(resolve_xfa_payload(graph, obj, limits)),
    }
    out
}

fn resolve_xfa_payload(
    graph: &sis_pdf_pdf::ObjectGraph<'_>,
    obj: &PdfObj<'_>,
    limits: DecodeLimits,
) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    match &obj.atom {
        PdfAtom::Str(s) => out.push(string_bytes(s)),
        PdfAtom::Stream(stream) => {
            let result = decode_stream_with_meta(graph.bytes, stream, limits);
            if let Some(data) = result.data {
                out.push(data);
            }
        }
        PdfAtom::Ref { .. } => {
            if let Some(entry) = graph.resolve_ref(obj) {
                match &entry.atom {
                    PdfAtom::Stream(stream) => {
                        let result = decode_stream_with_meta(graph.bytes, stream, limits);
                        if let Some(data) = result.data {
                            out.push(data);
                        }
                    }
                    PdfAtom::Str(s) => out.push(string_bytes(s)),
                    _ => {}
                }
            }
        }
        _ => {}
    }
    out
}

fn contains_any(data: &[u8], needles: &[&[u8]]) -> bool {
    needles.iter().any(|n| contains_token(data, n))
}

fn contains_token(data: &[u8], token: &[u8]) -> bool {
    data.windows(token.len()).any(|w| w == token)
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut ent = 0.0;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        ent -= p * p.log2();
    }
    ent
}

fn binary_ratio(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let binary = data
        .iter()
        .filter(|&&b| !(b == b'\n' || b == b'\r' || b == b'\t' || (b >= 0x20 && b <= 0x7e)))
        .count();
    binary as f64 / data.len() as f64
}

/// Extract graph-based features using TypedGraph and PathFinder infrastructure
fn extract_graph_features(ctx: &ScanContext) -> GraphFeatures {
    // Build typed graph and get classifications
    let typed_graph = ctx.build_typed_graph();
    let classifications = ctx.classifications();

    // Count edges by type
    let total_edges = typed_graph.edges.len();
    let mut open_action_edges = 0;
    let mut js_payload_edges = 0;
    let mut uri_target_edges = 0;
    let mut launch_target_edges = 0;
    let mut suspicious_edge_count = 0;

    for edge in &typed_graph.edges {
        if edge.suspicious {
            suspicious_edge_count += 1;
        }
        match edge.edge_type {
            EdgeType::OpenAction => open_action_edges += 1,
            EdgeType::JavaScriptPayload | EdgeType::JavaScriptNames => js_payload_edges += 1,
            EdgeType::UriTarget => uri_target_edges += 1,
            EdgeType::LaunchTarget => launch_target_edges += 1,
            _ => {}
        }
    }

    // Analyze action chains using PathFinder
    let path_finder = typed_graph.path_finder();
    let chains = path_finder.find_all_action_chains();

    let action_chain_count = chains.len();
    let max_chain_length = chains.iter().map(|c| c.length()).max().unwrap_or(0);
    let automatic_chain_count = chains.iter().filter(|c| c.automatic).count();
    let js_chain_count = chains.iter().filter(|c| c.involves_js).count();
    let external_chain_count = chains.iter().filter(|c| c.involves_external).count();

    // Calculate graph depth metrics
    let depths = path_finder.catalog_depths();
    let max_graph_depth = depths.values().max().copied().unwrap_or(0);
    let avg_graph_depth = if !depths.is_empty() {
        depths.values().sum::<usize>() as f64 / depths.len() as f64
    } else {
        0.0
    };

    // Count paths from catalog to JavaScript objects
    let js_sources = path_finder.find_javascript_sources();
    let catalog_to_js_paths = js_sources
        .iter()
        .filter(|src| path_finder.is_reachable_from_catalog(**src))
        .count();

    // Detect multi-stage attack indicators (JS + embedded + external)
    let has_js = js_payload_edges > 0;
    let has_embedded = classifications
        .iter()
        .any(|(_, c)| c.has_role(ObjectRole::EmbeddedFile));
    let has_external = uri_target_edges > 0 || launch_target_edges > 0;
    let multi_stage_indicators = if has_js && has_embedded && has_external {
        1
    } else {
        0
    };

    GraphFeatures {
        total_edges,
        open_action_edges,
        js_payload_edges,
        uri_target_edges,
        launch_target_edges,
        suspicious_edge_count,
        action_chain_count,
        max_chain_length,
        automatic_chain_count,
        js_chain_count,
        external_chain_count,
        max_graph_depth,
        avg_graph_depth,
        catalog_to_js_paths,
        multi_stage_indicators,
    }
}

#[allow(dead_code)]
fn build_feature_map(fv: &FeatureVector) -> HashMap<String, f64> {
    let mut out = HashMap::new();
    out.insert("general.file_size".into(), fv.general.file_size as f64);
    out.insert("general.file_entropy".into(), fv.general.file_entropy);
    out.insert("general.binary_ratio".into(), fv.general.binary_ratio);
    out.insert(
        "general.object_count".into(),
        fv.general.object_count as f64,
    );
    out.insert(
        "structural.startxref_count".into(),
        fv.structural.startxref_count as f64,
    );
    out.insert(
        "structural.trailer_count".into(),
        fv.structural.trailer_count as f64,
    );
    out.insert(
        "structural.objstm_count".into(),
        fv.structural.objstm_count as f64,
    );
    out.insert(
        "structural.linearized_present".into(),
        if fv.structural.linearized_present {
            1.0
        } else {
            0.0
        },
    );
    out.insert(
        "structural.max_object_id".into(),
        fv.structural.max_object_id as f64,
    );
    out.insert(
        "behavior.action_count".into(),
        fv.behavioral.action_count as f64,
    );
    out.insert(
        "behavior.js_object_count".into(),
        fv.behavioral.js_object_count as f64,
    );
    out.insert(
        "behavior.js_entropy_avg".into(),
        fv.behavioral.js_entropy_avg,
    );
    out.insert(
        "behavior.js_eval_count".into(),
        fv.behavioral.js_eval_count as f64,
    );
    out.insert(
        "behavior.js_suspicious_api_count".into(),
        fv.behavioral.js_suspicious_api_count as f64,
    );
    out.insert(
        "behavior.time_api_count".into(),
        fv.behavioral.time_api_count as f64,
    );
    out.insert(
        "behavior.env_probe_count".into(),
        fv.behavioral.env_probe_count as f64,
    );
    out.insert(
        "content.embedded_file_count".into(),
        fv.content.embedded_file_count as f64,
    );
    out.insert(
        "content.rich_media_count".into(),
        fv.content.rich_media_count as f64,
    );
    out.insert(
        "content.annotation_count".into(),
        fv.content.annotation_count as f64,
    );
    out.insert("content.page_count".into(), fv.content.page_count as f64);
    out
}
