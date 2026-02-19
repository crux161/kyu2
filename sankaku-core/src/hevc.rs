/// Start code used by the iOS capture stream (`00 00 00 01`).
const ANNEX_B_START_CODE: [u8; 4] = [0x00, 0x00, 0x00, 0x01];

/// HEVC SAO parameters extracted from slice-level syntax.
///
/// `#[repr(C)]` keeps this layout C-FFI friendly for OpenZL interop.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SaoParameters {
    pub ctu_x: u16,
    pub ctu_y: u16,
    /// 0 = not applied, 1 = band offset, 2 = edge offset
    pub sao_type_idx: u8,
    pub band_position: u8,
    pub offset: [i8; 4],
}

/// Zero-copy iterator over Annex B NAL units.
///
/// Each yielded item excludes the `00 00 00 01` start code and borrows from
/// the original byte slice.
pub struct AnnexBNalIter<'a> {
    data: &'a [u8],
    cursor: usize,
}

impl<'a> AnnexBNalIter<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, cursor: 0 }
    }
}

impl<'a> Iterator for AnnexBNalIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        while self.cursor < self.data.len() {
            let start = find_start_code(self.data, self.cursor)?;
            let nal_start = start + ANNEX_B_START_CODE.len();

            let next_start = find_start_code(self.data, nal_start);
            let nal_end = next_start.unwrap_or(self.data.len());
            self.cursor = next_start.unwrap_or(self.data.len());

            if nal_start < nal_end {
                return Some(&self.data[nal_start..nal_end]);
            }
        }
        None
    }
}

/// Creates a zero-copy iterator over Annex B NAL units.
pub fn annex_b_nal_units(data: &[u8]) -> AnnexBNalIter<'_> {
    AnnexBNalIter::new(data)
}

/// Extracts HEVC NAL unit type from the first NAL header byte.
///
/// Formula: `(nal_header_byte_0 >> 1) & 0x3F`
pub fn nal_unit_type(nal_unit: &[u8]) -> Option<u8> {
    let header_byte = *nal_unit.first()?;
    Some((header_byte >> 1) & 0x3F)
}

/// SAO extraction stub for VCL NAL units.
///
/// Returns `None` for non-VCL units (types 32..63).
/// Returns a placeholder `SaoParameters` for VCL units (types 0..31).
pub fn extract_sao_parameters(nal_unit: &[u8]) -> Option<SaoParameters> {
    let nal_type = nal_unit_type(nal_unit)?;
    if nal_type > 31 {
        return None;
    }

    // TODO(hevc/sao):
    // 1) Convert Annex B payload to RBSP by removing emulation-prevention bytes
    //    (`00 00 03`) starting after the 2-byte HEVC NAL header.
    // 2) Parse the slice header with a bit reader (ue(v)/se(v)/fixed bits):
    //    - first_slice_segment_in_pic_flag
    //    - dependent_slice_segment_flag
    //    - slice_segment_address -> derive CTU location
    //    - sao_luma_flag / sao_chroma_flag
    //    - sao_type_idx_luma/chroma
    //    - sao_offset_abs / sao_offset_sign / band_position (or edge class)
    // 3) Populate `SaoParameters` from decoded syntax elements.
    //
    // Current iteration intentionally stops at VCL identification to keep the
    // parser zero-copy and integration-ready.
    Some(SaoParameters::default())
}

fn find_start_code(data: &[u8], from: usize) -> Option<usize> {
    if from >= data.len() {
        return None;
    }
    data[from..]
        .windows(ANNEX_B_START_CODE.len())
        .position(|window| window == ANNEX_B_START_CODE)
        .map(|relative| from + relative)
}

#[cfg(test)]
mod tests {
    use super::{annex_b_nal_units, extract_sao_parameters, nal_unit_type};

    #[test]
    fn annex_b_splitter_and_nal_type_scanner_work() {
        let data = [
            0x00, 0x00, 0x00, 0x01, // start
            0x40, 0x01, 0xAA, 0xBB, // nal type 32 (VPS)
            0x00, 0x00, 0x00, 0x01, // start
            0x02, 0x01, 0xCC, // nal type 1 (VCL)
        ];

        let units: Vec<&[u8]> = annex_b_nal_units(&data).collect();
        assert_eq!(units.len(), 2);

        let first_type = nal_unit_type(units[0]).expect("first unit should have header");
        let second_type = nal_unit_type(units[1]).expect("second unit should have header");
        assert_eq!(first_type, 32);
        assert_eq!(second_type, 1);

        assert!(
            extract_sao_parameters(units[0]).is_none(),
            "non-VCL unit should not return SAO"
        );
        assert!(
            extract_sao_parameters(units[1]).is_some(),
            "VCL unit should pass SAO scanner gate"
        );
    }
}
