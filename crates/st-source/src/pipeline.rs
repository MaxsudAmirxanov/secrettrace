//! Source → extractor on a worker pool.

use std::num::NonZeroUsize;
use std::ops::ControlFlow;
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::thread;

use serde::Serialize;
use st_extract::{Candidate, Extractor};

use crate::{Document, Locator, SourceError, Stats, TextEncoding, Visit};

/// Candidates of one document. Spans refer to the decoded text.
#[derive(Debug, Serialize)]
pub struct DocumentFindings {
    #[serde(flatten)]
    pub locator: Locator,
    pub encoding: TextEncoding,
    /// Results are partial: content cut at the size cap, or extractor limits hit.
    pub truncated: bool,
    pub candidates: Vec<Candidate>,
}

#[derive(Debug, Default)]
pub struct Report {
    /// Documents with candidates or partial results, in source order.
    pub documents: Vec<DocumentFindings>,
    pub stats: Stats,
}

impl Report {
    #[must_use]
    pub fn candidates(&self) -> usize {
        self.documents.iter().map(|d| d.candidates.len()).sum()
    }
}

/// Run `produce` (a source walk) and extract candidates from every document it yields,
/// on `jobs` threads. Results do not depend on `jobs`.
pub fn scan<F>(extractor: &Extractor, jobs: NonZeroUsize, produce: F) -> Result<Report, SourceError>
where
    F: FnOnce(&mut Visit<'_>) -> Result<Stats, SourceError>,
{
    let mut found = Vec::new();
    let mut stats = if jobs.get() == 1 {
        let mut seq = 0u64;
        produce(&mut |doc| {
            if let Some(f) = process(extractor, doc) {
                found.push((seq, f));
            }
            seq += 1;
            ControlFlow::Continue(())
        })?
    } else {
        parallel(extractor, jobs.get(), produce, &mut found)?
    };

    found.sort_unstable_by_key(|(seq, _)| *seq);
    let documents: Vec<_> = found.into_iter().map(|(_, f)| f).collect();
    stats.truncated = u64::try_from(documents.iter().filter(|d| d.truncated).count()).unwrap_or(u64::MAX);
    Ok(Report { documents, stats })
}

fn parallel<F>(
    extractor: &Extractor,
    jobs: usize,
    produce: F,
    found: &mut Vec<(u64, DocumentFindings)>,
) -> Result<Stats, SourceError>
where
    F: FnOnce(&mut Visit<'_>) -> Result<Stats, SourceError>,
{
    let results = Mutex::new(Vec::new());
    let stats = thread::scope(|s| {
        // Bounded: the walker cannot read ahead of extraction by more than a few documents.
        let (tx, rx) = mpsc::sync_channel::<(u64, Document)>(jobs * 2);
        // Only workers own the receiver: if they all die, `send` fails instead of blocking.
        let rx = Arc::new(Mutex::new(rx));
        for _ in 0..jobs {
            let rx = Arc::clone(&rx);
            let results = &results;
            s.spawn(move || {
                loop {
                    let next = rx.lock().unwrap_or_else(PoisonError::into_inner).recv();
                    let Ok((seq, doc)) = next else { break };
                    if let Some(f) = process(extractor, doc) {
                        results.lock().unwrap_or_else(PoisonError::into_inner).push((seq, f));
                    }
                }
            });
        }
        drop(rx);
        let mut seq = 0u64;
        let stats = produce(&mut |doc| {
            let sent = tx.send((seq, doc));
            seq += 1;
            if sent.is_ok() { ControlFlow::Continue(()) } else { ControlFlow::Break(()) }
        });
        drop(tx);
        stats
    });
    found.append(&mut results.into_inner().unwrap_or_else(PoisonError::into_inner));
    stats
}

fn process(extractor: &Extractor, doc: Document) -> Option<DocumentFindings> {
    let result = extractor.extract(&doc.text);
    let truncated = doc.truncated || result.truncated;
    // `doc.text` is zeroized when `doc` drops here.
    (truncated || !result.candidates.is_empty()).then_some(DocumentFindings {
        locator: doc.locator,
        encoding: doc.encoding,
        truncated,
        candidates: result.candidates,
    })
}
