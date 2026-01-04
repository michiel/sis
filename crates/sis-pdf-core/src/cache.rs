use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::report::Report;
use crate::features::FeatureVector;

const CACHE_VERSION: u32 = 1;
const MAX_CACHE_BYTES: u64 = 50 * 1024 * 1024;

#[derive(Debug, Serialize)]
struct CacheEntry<'a> {
    version: u32,
    file_hash: String,
    report: &'a Report,
}

#[derive(Debug, Deserialize)]
struct CacheEntryOwned {
    version: u32,
    file_hash: String,
    report: Report,
}

#[derive(Debug, Serialize)]
struct FeatureEntry<'a> {
    version: u32,
    file_hash: String,
    features: &'a FeatureVector,
}

#[derive(Debug, Deserialize)]
struct FeatureEntryOwned {
    version: u32,
    file_hash: String,
    features: FeatureVector,
}

pub trait AnalysisCache {
    fn load_report(&self, hash: &str) -> Option<Report>;
    fn store_report(&self, hash: &str, report: &Report) -> Result<()>;
    fn load_features(&self, hash: &str) -> Option<FeatureVector>;
    fn store_features(&self, hash: &str, features: &FeatureVector) -> Result<()>;
}

#[derive(Debug)]
pub struct ScanCache {
    dir: PathBuf,
}

impl ScanCache {
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn load(&self, hash: &str) -> Option<Report> {
        let safe_hash = sanitize_hash(hash)?;
        let path = self.path_for(&safe_hash);
        if let Ok(meta) = fs::metadata(&path) {
            if meta.len() > MAX_CACHE_BYTES {
                eprintln!(
                    "security_boundary: cache entry too large ({} bytes)",
                    meta.len()
                );
                return None;
            }
        }
        let data = fs::read(path).ok()?;
        let entry: CacheEntryOwned = serde_json::from_slice(&data).ok()?;
        if entry.version != CACHE_VERSION {
            return None;
        }
        if entry.file_hash != safe_hash {
            eprintln!(
                "security_boundary: cache hash mismatch (requested={} cached={})",
                safe_hash, entry.file_hash
            );
            return None;
        }
        Some(entry.report)
    }

    pub fn store(&self, hash: &str, report: &Report) -> Result<()> {
        let safe_hash = sanitize_hash(hash)
            .ok_or_else(|| anyhow::anyhow!("invalid cache hash"))?;
        let path = self.path_for(&safe_hash);
        let entry = CacheEntry {
            version: CACHE_VERSION,
            file_hash: safe_hash,
            report,
        };
        let data = serde_json::to_vec(&entry)?;
        fs::write(path, data)?;
        Ok(())
    }

    pub fn load_features(&self, hash: &str) -> Option<FeatureVector> {
        let safe_hash = sanitize_hash(hash)?;
        let path = self.feature_path_for(&safe_hash);
        if let Ok(meta) = fs::metadata(&path) {
            if meta.len() > MAX_CACHE_BYTES {
                eprintln!(
                    "security_boundary: cache feature entry too large ({} bytes)",
                    meta.len()
                );
                return None;
            }
        }
        let data = fs::read(path).ok()?;
        let entry: FeatureEntryOwned = serde_json::from_slice(&data).ok()?;
        if entry.version != CACHE_VERSION {
            return None;
        }
        if entry.file_hash != safe_hash {
            eprintln!(
                "security_boundary: cache feature hash mismatch (requested={} cached={})",
                safe_hash, entry.file_hash
            );
            return None;
        }
        Some(entry.features)
    }

    pub fn store_features(&self, hash: &str, features: &FeatureVector) -> Result<()> {
        let safe_hash = sanitize_hash(hash)
            .ok_or_else(|| anyhow::anyhow!("invalid cache hash"))?;
        let path = self.feature_path_for(&safe_hash);
        let entry = FeatureEntry {
            version: CACHE_VERSION,
            file_hash: safe_hash,
            features,
        };
        let data = serde_json::to_vec(&entry)?;
        fs::write(path, data)?;
        Ok(())
    }

    fn path_for(&self, hash: &str) -> PathBuf {
        self.dir.join(format!("{}.json", hash))
    }

    fn feature_path_for(&self, hash: &str) -> PathBuf {
        self.dir.join(format!("{}_features.json", hash))
    }
}

impl AnalysisCache for ScanCache {
    fn load_report(&self, hash: &str) -> Option<Report> {
        self.load(hash)
    }

    fn store_report(&self, hash: &str, report: &Report) -> Result<()> {
        self.store(hash, report)
    }

    fn load_features(&self, hash: &str) -> Option<FeatureVector> {
        self.load_features(hash)
    }

    fn store_features(&self, hash: &str, features: &FeatureVector) -> Result<()> {
        self.store_features(hash, features)
    }
}

pub fn cache_dir_from_path(path: &Path) -> PathBuf {
    path.to_path_buf()
}

fn sanitize_hash(hash: &str) -> Option<String> {
    if hash.len() != 64 {
        eprintln!(
            "security_boundary: cache hash rejected (len={}, expected 64)",
            hash.len()
        );
        return None;
    }
    if !hash.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
        eprintln!("security_boundary: cache hash rejected (non-hex chars)");
        return None;
    }
    Some(hash.to_string())
}
