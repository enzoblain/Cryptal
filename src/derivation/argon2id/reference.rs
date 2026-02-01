//! Reference block position computation for Argon2.
//!
//! When filling a block at position (lane, index), Argon2 needs to select
//! a reference block to mix with the previous block. The selection algorithm
//! uses pseudo-random values J1 and J2 to determine which block to reference,
//! with constraints to ensure the referenced block has already been computed.

use super::memory::MemoryLayout;

/// Computes the reference block position for the Argon2 filling algorithm.
///
/// Given the current position and pseudo-random values J1, J2, this function
/// determines which previously-computed block should be used as the second
/// input to the compression function G.
///
/// The algorithm (RFC 9106 §3.4.1.3) ensures that:
/// - On the first pass, first slice: only earlier blocks in the same lane
/// - Otherwise: blocks from any lane, but respecting slice boundaries
///
/// The mapping uses a non-uniform distribution (phi function) that biases
/// toward more recently computed blocks, improving cache locality.
///
/// # Returns
///
/// A tuple `(reference_lane, reference_index)` identifying the block to use.
pub(crate) fn compute_reference_position(
    pass: u32,
    slice: u32,
    lane: u32,
    index_in_segment: u32,
    layout: &MemoryLayout,
    j1: u32,
    j2: u32,
) -> (u32, u32) {
    let segment_len = layout.segment_len;
    let lane_len = layout.lane_len;
    let lanes = layout.lanes;

    let ref_lane = if pass == 0 && slice == 0 {
        lane
    } else {
        j2 % lanes
    };

    let same_lane = ref_lane == lane;

    let reference_area_size = if pass == 0 {
        if slice == 0 {
            index_in_segment.saturating_sub(1)
        } else if same_lane {
            slice * segment_len + index_in_segment - 1
        } else {
            let base = slice * segment_len;
            if index_in_segment == 0 {
                base.saturating_sub(1)
            } else {
                base
            }
        }
    } else if same_lane {
        lane_len - segment_len + index_in_segment - 1
    } else {
        let base = lane_len - segment_len;
        if index_in_segment == 0 {
            base.saturating_sub(1)
        } else {
            base
        }
    };

    if reference_area_size == 0 {
        return (ref_lane, 0);
    }

    // Phi function: x = J1² / 2³², relative_position = W - 1 - (W × x / 2³²)
    let j1_64 = j1 as u64;
    let x = (j1_64 * j1_64) >> 32;
    let relative_position = (reference_area_size as u64)
        .saturating_sub(1)
        .saturating_sub(((reference_area_size as u64) * x) >> 32)
        as u32;

    let start_position = if pass == 0 || slice == 3 {
        0
    } else {
        (slice + 1) * segment_len
    };

    let ref_index = (start_position + relative_position) % lane_len;

    (ref_lane, ref_index)
}
