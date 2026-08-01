//! Process-side cache of extracted hash lines.
//!
//! Some formats embed the entire source file in the hash line (e.g. Monero), so
//! the line can be hundreds of MB. Shipping it into the webview and back out on
//! export is slow enough to freeze the UI. Instead, inspection keeps the full
//! line here keyed by a short opaque token and sends only a small preview to
//! the UI; the export command writes the cached line straight to disk without
//! round-tripping it through the webview.

use std::collections::VecDeque;
use std::sync::Mutex;

use crate::models::{FileMeta, HashResult, InspectResult};

/// How many recent lines to keep. One per inspected source is enough; the cap
/// bounds memory if a user inspects many large files in one session.
const MAX_ENTRIES: usize = 8;

/// Lines above this many bytes are kept in the cache and replaced in the IPC
/// payload by a short preview. Matches the UI's copy cutoff (256 KiB) — above
/// this the UI only ever previews/exports, never copies inline.
const LARGE_HASH_THRESHOLD: usize = 256 * 1024;

/// Preview head/tail character counts (kept in sync with the UI).
const PREVIEW_HEAD: usize = 100;
const PREVIEW_TAIL: usize = 24;
const PREVIEW_ELLIPSIS: &str = "......";

struct Entry {
    token: String,
    line: String,
}

static CACHE: Mutex<Option<VecDeque<Entry>>> = Mutex::new(None);

fn with_store<R>(f: impl FnOnce(&mut VecDeque<Entry>) -> R) -> R {
    let mut guard = CACHE.lock().expect("hash cache poisoned");
    if guard.is_none() {
        *guard = Some(VecDeque::with_capacity(MAX_ENTRIES));
    }
    f(guard.as_mut().unwrap())
}

fn next_token(counter: u64) -> String {
    // Opaque, non-guessable enough for a local single-user cache.
    format!("h{counter:x}")
}

/// Store a full hash line and return the token the UI uses to export it.
pub fn insert(line: String) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let token = next_token(COUNTER.fetch_add(1, Ordering::Relaxed));
    with_store(|store| {
        if store.len() == MAX_ENTRIES {
            store.pop_front();
        }
        store.push_back(Entry {
            token: token.clone(),
            line,
        });
    });
    token
}

/// Look up a cached hash line by token, with a trailing newline appended for
/// the `.hash` file.
pub fn get_line(token: &str) -> Option<String> {
    with_store(|store| {
        store
            .iter()
            .find(|e| e.token == token)
            .map(|e| format!("{}\n", e.line))
    })
}

/// Build the `InspectResult` for an extraction: cache the full hash line behind
/// a short export token, and replace the line with a small preview in the IPC
/// payload when it is large so the webview never holds/serializes hundreds of
/// MB.
pub fn finalize(meta: FileMeta, mut hash: HashResult) -> InspectResult {
    let full_line = std::mem::take(&mut hash.hash_line);
    hash.hash_line_bytes = full_line.len() as u64;

    let payload_line = if full_line.len() > LARGE_HASH_THRESHOLD {
        make_preview(&full_line)
    } else {
        full_line.clone()
    };
    let export_token = insert(full_line);

    hash.hash_line = payload_line;
    InspectResult {
        meta,
        hash,
        export_token,
    }
}

/// Truncate a long line to `head......tail` on char boundaries.
fn make_preview(line: &str) -> String {
    let count = line.chars().count();
    let take_head = PREVIEW_HEAD.min(count);
    let take_tail = PREVIEW_TAIL.min(count.saturating_sub(take_head));
    let head: String = line.chars().take(take_head).collect();
    let tail: String = line
        .chars()
        .skip(count - take_tail)
        .take(take_tail)
        .collect();
    format!("{head}{PREVIEW_ELLIPSIS}{tail}")
}
