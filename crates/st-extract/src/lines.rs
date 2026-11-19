/// Byte offset → (line, column) lookup, built once per scanned document.
#[derive(Debug)]
pub(crate) struct LineIndex {
    starts: Vec<usize>,
}

impl LineIndex {
    pub fn new(text: &str) -> Self {
        let mut starts = vec![0];
        starts.extend(text.bytes().enumerate().filter(|&(_, b)| b == b'\n').map(|(i, _)| i + 1));
        Self { starts }
    }

    /// 1-based line and byte column of `offset`.
    pub fn position(&self, offset: usize) -> (u32, u32) {
        let line = self.starts.partition_point(|&s| s <= offset).max(1);
        let start = self.starts[line - 1];
        let clamp = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        (clamp(line), clamp(offset - start + 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positions() {
        let idx = LineIndex::new("ab\ncd\n\nef");
        assert_eq!(idx.position(0), (1, 1));
        assert_eq!(idx.position(1), (1, 2));
        assert_eq!(idx.position(3), (2, 1));
        assert_eq!(idx.position(6), (3, 1));
        assert_eq!(idx.position(8), (4, 2));
    }
}
