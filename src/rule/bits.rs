/// A fixed-size set of rule indices.
#[derive(Debug, Clone)]
pub(super) struct Bits(Vec<u64>);

impl Bits {
    pub(super) fn new(len: usize) -> Self {
        Self(vec![0; len.div_ceil(64)])
    }

    pub(super) fn insert(&mut self, idx: usize) {
        self.0[idx / 64] |= 1 << (idx % 64);
    }

    pub(super) fn is_empty(&self) -> bool {
        self.0.iter().all(|&w| w == 0)
    }

    /// Do the two sets share a member?
    pub(super) fn intersects(&self, other: &Bits) -> bool {
        self.0.iter().zip(&other.0).any(|(a, b)| a & b != 0)
    }

    /// Keep only the members also in `other`. Returns whether any are left.
    pub(super) fn intersect(&mut self, other: &Bits) -> bool {
        let mut any = 0;
        for (a, b) in self.0.iter_mut().zip(&other.0) {
            *a &= b;
            any |= *a;
        }
        any != 0
    }

    pub(super) fn first(&self) -> Option<usize> {
        self.0
            .iter()
            .position(|&w| w != 0)
            .map(|i| i * 64 + self.0[i].trailing_zeros() as usize)
    }
}
