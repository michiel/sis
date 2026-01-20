use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfStr};

pub(crate) fn dict_u32(dict: &PdfDict<'_>, key: &[u8]) -> Option<u32> {
    let (_, obj) = dict.get_first(key)?;
    match &obj.atom {
        PdfAtom::Int(value) => u32::try_from(*value).ok(),
        PdfAtom::Real(value) => {
            if *value < 0.0 {
                None
            } else {
                Some(*value as u32)
            }
        }
        _ => None,
    }
}

pub(crate) fn string_bytes(value: &PdfStr<'_>) -> Vec<u8> {
    match value {
        PdfStr::Literal { decoded, .. } => decoded.clone(),
        PdfStr::Hex { decoded, .. } => decoded.clone(),
    }
}
