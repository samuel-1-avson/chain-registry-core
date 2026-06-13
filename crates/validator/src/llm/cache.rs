use super::LlmReview;

pub(super) struct SemanticCache;

impl SemanticCache {
    pub(super) fn snippet_hash(code_snippet: &str) -> u64 {
        super::content_hash(code_snippet)
    }

    pub(super) fn get_snippet(hash: u64) -> Option<u8> {
        super::LLM_CACHE
            .lock()
            .ok()
            .and_then(|cache| cache.get(&hash).copied())
    }

    pub(super) fn put_snippet(hash: u64, score: u8) {
        super::cache_score(hash, score);
    }

    pub(super) fn get_review(content_hash: &str) -> Option<LlmReview> {
        super::REVIEW_CACHE
            .lock()
            .ok()
            .and_then(|cache| cache.get(content_hash).cloned())
    }

    pub(super) fn put_review(content_hash: &str, review: &LlmReview) {
        if let Ok(mut cache) = super::REVIEW_CACHE.lock() {
            if cache.len() > 5_000 {
                cache.clear();
            }
            cache.insert(content_hash.to_string(), review.clone());
        }
    }
}
