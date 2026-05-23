pub const REPLAY_WINDOW_SIZE: u64 = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayWindow {
    highest: u64,
    bitmap: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayDecision {
    Fresh,
    Replay,
    TooOld,
    Zero,
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            highest: 0,
            bitmap: 0,
        }
    }

    pub fn highest(&self) -> u64 {
        self.highest
    }

    pub fn check(&self, sequence_number: u64) -> ReplayDecision {
        if sequence_number == 0 {
            return ReplayDecision::Zero;
        }

        if sequence_number > self.highest {
            return ReplayDecision::Fresh;
        }

        let distance = self.highest - sequence_number;
        if distance >= REPLAY_WINDOW_SIZE {
            return ReplayDecision::TooOld;
        }

        if self.bitmap & (1u64 << distance) != 0 {
            ReplayDecision::Replay
        } else {
            ReplayDecision::Fresh
        }
    }

    pub fn accept(&mut self, sequence_number: u64) -> ReplayDecision {
        let decision = self.check(sequence_number);
        if decision != ReplayDecision::Fresh {
            return decision;
        }

        if sequence_number > self.highest {
            let shift = sequence_number - self.highest;
            if shift >= REPLAY_WINDOW_SIZE {
                self.bitmap = 1;
            } else {
                self.bitmap = (self.bitmap << shift) | 1;
            }
            self.highest = sequence_number;
        } else {
            let distance = self.highest - sequence_number;
            self.bitmap |= 1u64 << distance;
        }

        ReplayDecision::Fresh
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_in_order_sequences() {
        let mut window = ReplayWindow::new();

        assert_eq!(window.accept(1), ReplayDecision::Fresh);
        assert_eq!(window.accept(2), ReplayDecision::Fresh);
        assert_eq!(window.highest(), 2);
    }

    #[test]
    fn rejects_replay_inside_window() {
        let mut window = ReplayWindow::new();

        assert_eq!(window.accept(10), ReplayDecision::Fresh);
        assert_eq!(window.accept(9), ReplayDecision::Fresh);
        assert_eq!(window.accept(9), ReplayDecision::Replay);
    }

    #[test]
    fn accepts_out_of_order_once_inside_window() {
        let mut window = ReplayWindow::new();

        assert_eq!(window.accept(10), ReplayDecision::Fresh);
        assert_eq!(window.accept(8), ReplayDecision::Fresh);
        assert_eq!(window.accept(8), ReplayDecision::Replay);
    }

    #[test]
    fn rejects_too_old_sequences() {
        let mut window = ReplayWindow::new();

        assert_eq!(window.accept(100), ReplayDecision::Fresh);
        assert_eq!(window.accept(35), ReplayDecision::TooOld);
    }

    #[test]
    fn rejects_zero_sequence() {
        let mut window = ReplayWindow::new();

        assert_eq!(window.accept(0), ReplayDecision::Zero);
    }
}
