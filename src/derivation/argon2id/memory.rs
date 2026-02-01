//! Memory organization and filling algorithm for Argon2.
//!
//! This module implements the core memory-filling loop of Argon2. Memory
//! is organized as a matrix of lanes (rows) and columns, with each cell
//! containing a 1024-byte block. Lanes can be processed independently
//! within each slice, enabling parallelism.

use super::block::Block;
use super::params::Argon2Params;
use super::reference::compute_reference_position;

/// Memory layout parameters for Argon2.
///
/// The memory is organized as follows:
/// - Total memory is divided into `lanes` independent rows.
/// - Each lane contains `lane_len` blocks.
/// - Each lane is divided into 4 slices (sync points).
/// - Each slice contains `segment_len` blocks.
#[derive(Debug, Clone)]
pub(crate) struct MemoryLayout {
    pub lanes: u32,
    pub lane_len: u32,
    pub segment_len: u32,
    pub total_blocks: u32,
}

impl MemoryLayout {
    pub(crate) fn new(params: &Argon2Params) -> Self {
        let sync_points = 4;
        let lanes = params.lanes;
        let total_blocks = (params.mem_kib / (sync_points * lanes)) * (sync_points * lanes);
        let lane_len = total_blocks / lanes;
        let segment_len = lane_len / sync_points;

        Self {
            lanes,
            lane_len,
            segment_len,
            total_blocks,
        }
    }

    #[inline]
    pub(crate) fn index(&self, lane: u32, index_in_lane: u32) -> usize {
        (lane * self.lane_len + index_in_lane) as usize
    }

    /// Fills all memory blocks over the specified number of passes.
    ///
    /// Each pass iterates through all 4 slices in order. Within each slice,
    /// all lanes are processed. The slice boundaries act as synchronization
    /// points: a lane can only reference blocks from other lanes that were
    /// completed in previous slices of the current pass.
    pub(crate) fn fill(&self, memory: &mut [Block], time: u32) {
        for pass in 0..time {
            for slice in 0..4u32 {
                for lane in 0..self.lanes {
                    self.fill_segment(memory, pass, slice, lane, time);
                }
            }
        }
    }

    /// Fills one segment (portion of a lane within a slice).
    ///
    /// For each block position, this function:
    /// 1. Determines J1, J2 values (from address block or previous block)
    /// 2. Computes the reference block position using J1, J2
    /// 3. Computes the new block as G(previous, reference) [⊕ existing on pass > 0]
    fn fill_segment(&self, memory: &mut [Block], pass: u32, slice: u32, lane: u32, time: u32) {
        // Argon2id uses data-independent addressing for first pass, slices 0-1
        let data_independent = pass == 0 && slice < 2;

        let mut addr_block = Block::ZERO;
        let mut address_counter = 0u32;

        if data_independent {
            address_counter += 1;
            addr_block = Block::generate_address_block(
                pass,
                lane,
                slice,
                self.total_blocks,
                time,
                address_counter,
            );
        }

        let start_idx = if pass == 0 && slice == 0 { 2 } else { 0 };

        for i in start_idx..self.segment_len {
            let index_in_lane = slice * self.segment_len + i;

            let prev_idx = if index_in_lane == 0 {
                self.lane_len - 1
            } else {
                index_in_lane - 1
            };

            let (j1, j2) = if data_independent {
                if i != 0 && i % 128 == 0 {
                    address_counter += 1;
                    addr_block = Block::generate_address_block(
                        pass,
                        lane,
                        slice,
                        self.total_blocks,
                        time,
                        address_counter,
                    );
                }
                let word = addr_block.0[(i % 128) as usize];
                (word as u32, (word >> 32) as u32)
            } else {
                let word = memory[self.index(lane, prev_idx)].0[0];
                (word as u32, (word >> 32) as u32)
            };

            let (ref_lane, ref_idx) =
                compute_reference_position(pass, slice, lane, i, self, j1, j2);

            let cur = self.index(lane, index_in_lane);
            let prev = self.index(lane, prev_idx);
            let reference = self.index(ref_lane, ref_idx);

            let compressed = Block::compress(&memory[prev], &memory[reference]);

            if pass == 0 {
                memory[cur] = compressed;
            } else {
                memory[cur].in_place_xor(&compressed);
            }
        }
    }
}
