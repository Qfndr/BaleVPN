//! Bounded RFC 6184 packetization-mode=1 receiver for the isolated video probe.
//! Incomplete/lost access units are discarded; this is not a reliability layer.
const MAX_AU: usize = 64 * 1024;
const MAX_NAL: usize = 32 * 1024;
const MAX_PACKETS: usize = 128;
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidVideoRtp;
#[derive(Default)]
pub struct AccessUnit {
    timestamp: Option<u32>,
    next: u16,
    packets: usize,
    size: usize,
    nals: Vec<Vec<u8>>,
    fragment: Option<Vec<u8>>,
    damaged: bool,
}
impl AccessUnit {
    fn nal(&mut self, nal: &[u8]) -> Result<(), InvalidVideoRtp> {
        if nal.is_empty()
            || nal[0] & 0x80 != 0
            || !(1..=23).contains(&(nal[0] & 31))
            || nal.len() > MAX_NAL
            || self.nals.len() >= 32
            || self.size + nal.len() > MAX_AU
        {
            return Err(InvalidVideoRtp);
        }
        self.size += nal.len();
        self.nals.push(nal.to_vec());
        Ok(())
    }
    fn packet(&mut self, p: &[u8]) -> Result<(), InvalidVideoRtp> {
        let header = *p.first().ok_or(InvalidVideoRtp)?;
        if header & 0x80 != 0 {
            return Err(InvalidVideoRtp);
        }
        match header & 31 {
            1..=23 => {
                if self.fragment.is_some() {
                    return Err(InvalidVideoRtp);
                }
                self.nal(p)
            }
            24 => {
                if self.fragment.is_some() {
                    return Err(InvalidVideoRtp);
                }
                let mut at = 1;
                while at < p.len() {
                    let length = p.get(at..at + 2).ok_or(InvalidVideoRtp)?;
                    let length = u16::from_be_bytes([length[0], length[1]]) as usize;
                    at += 2;
                    self.nal(p.get(at..at + length).ok_or(InvalidVideoRtp)?)?;
                    at += length;
                }
                if at == 1 {
                    return Err(InvalidVideoRtp);
                }
                Ok(())
            }
            28 => {
                if p.len() < 3 {
                    return Err(InvalidVideoRtp);
                }
                let fu = p[1];
                let start = fu & 128 != 0;
                let end = fu & 64 != 0;
                if fu & 32 != 0 || !(1..=23).contains(&(fu & 31)) || start && end {
                    return Err(InvalidVideoRtp);
                }
                let original = (header & 0xe0) | (fu & 31);
                if start {
                    if self.fragment.is_some() {
                        return Err(InvalidVideoRtp);
                    }
                    self.fragment = Some(vec![original]);
                }
                let fragment = self.fragment.as_mut().ok_or(InvalidVideoRtp)?;
                if fragment[0] != original
                    || fragment.len() + p.len() - 2 > MAX_NAL
                    || self.size + fragment.len() + p.len() - 2 > MAX_AU
                {
                    return Err(InvalidVideoRtp);
                }
                fragment.extend_from_slice(&p[2..]);
                if end {
                    let nal = self.fragment.take().ok_or(InvalidVideoRtp)?;
                    self.nal(&nal)?;
                }
                Ok(())
            }
            _ => Err(InvalidVideoRtp),
        }
    }
    pub fn push(
        &mut self,
        sequence: u16,
        timestamp: u32,
        marker: bool,
        payload: &[u8],
    ) -> Result<Option<Vec<Vec<u8>>>, InvalidVideoRtp> {
        if self.timestamp != Some(timestamp) {
            // A missing previous marker must never merge two access units.
            *self = Self::default();
            self.timestamp = Some(timestamp);
            self.next = sequence;
        }
        self.packets = self.packets.saturating_add(1).min(MAX_PACKETS + 1);
        if sequence != self.next || self.packets > MAX_PACKETS || self.packet(payload).is_err() {
            self.damaged = true;
            self.nals.clear();
            self.fragment = None;
        }
        self.next = sequence.wrapping_add(1);
        if !marker {
            return Ok(None);
        }
        let valid = !self.damaged && self.fragment.is_none() && !self.nals.is_empty();
        let nals = std::mem::take(&mut self.nals);
        *self = Self::default();
        if valid {
            Ok(Some(nals))
        } else {
            Err(InvalidVideoRtp)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reassembles_fu_and_stap_and_sequence_wrap_only_at_marker() {
        let mut au = AccessUnit::default();
        assert_eq!(
            au.push(65534, 90, false, &[24, 0, 2, 0x67, 1, 0, 2, 0x68, 2]),
            Ok(None)
        );
        assert_eq!(au.push(65535, 90, false, &[28, 0x86, 3, 4]), Ok(None));
        assert_eq!(au.push(0, 90, false, &[28, 0x46, 5]), Ok(None));
        assert_eq!(
            au.push(1, 90, true, &[0x65, 6]),
            Ok(Some(vec![
                vec![0x67, 1],
                vec![0x68, 2],
                vec![6, 3, 4, 5],
                vec![0x65, 6]
            ]))
        );
    }
    #[test]
    fn loss_incomplete_markers_and_timestamp_change_never_deliver_partial_data() {
        let mut au = AccessUnit::default();
        assert_eq!(au.push(1, 1, false, &[28, 0x86, 1]), Ok(None));
        assert_eq!(au.push(3, 1, true, &[28, 0x46, 2]), Err(InvalidVideoRtp));
        assert_eq!(au.push(4, 2, true, &[28, 0x86, 1]), Err(InvalidVideoRtp));
        assert_eq!(au.push(5, 3, false, &[6, 9]), Ok(None));
        assert_eq!(
            au.push(6, 4, true, &[0x65, 7]),
            Ok(Some(vec![vec![0x65, 7]]))
        );
    }
    #[test]
    fn rejects_illegal_fragmentation_nested_stap_and_memory_flood() {
        for bytes in [
            vec![28, 0xc6, 1],
            vec![28, 0x66, 1],
            vec![24, 0, 1, 24],
            vec![24, 0, 3, 6, 1],
            vec![0x86, 1],
            vec![29, 1],
        ] {
            assert_eq!(
                AccessUnit::default().push(0, 0, true, &bytes),
                Err(InvalidVideoRtp)
            );
        }
        let mut au = AccessUnit::default();
        for n in 0..MAX_PACKETS {
            assert_eq!(au.push(n as u16, 0, false, &[6, 1]), Ok(None));
        }
        assert_eq!(
            au.push(MAX_PACKETS as u16, 0, true, &[6, 1]),
            Err(InvalidVideoRtp)
        );
        assert_eq!(
            AccessUnit::default().push(0, 0, true, &vec![6; MAX_NAL + 1]),
            Err(InvalidVideoRtp)
        );
    }
}
