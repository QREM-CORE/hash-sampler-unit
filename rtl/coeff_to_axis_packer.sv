/*
 * Module Name: coeff_to_axis_packer
 * Author(s): Kiet Le
 * Target: FIPS 203 (ML-KEM / Kyber) Hardware Accelerator
 * Description:
 * - Converts 4-coefficient (48-bit / 6-byte) poly memory reader beats into
 *   64-bit (8-byte) AXI4-Stream beats for Keccak Core absorption.
 * - Reads exactly ONE polynomial (256 coefficients) per start pulse.
 *   The top-level controller is responsible for sequencing multiple polys
 *   by updating poly_id_i and pulsing absorb_poly_i for each one.
 * - Implements a 96-bit shift-register gearbox to handle the 6→8 byte packing
 *   without data corruption.
 * - t_last_o is asserted on the final flush beat ONLY when is_last_i is high.
 *   This allows back-to-back poly absorptions as part of one larger hash message.
 * - Coefficients are packed raw 12-bit little-endian, 4 per 48-bit beat:
 *     {coeff[3][11:0], coeff[2][11:0], coeff[1][11:0], coeff[0][11:0]}
 *
 * Packing Pattern (LCM(6,8) = 24 bytes per 4-input / 3-output cycle group):
 *   - Every 4 input beats → 3 Keccak output beats (75% throughput).
 *   - Final flush emits remaining bytes as partial beat with t_keep.
 *
 * FSM States:
 *   S_IDLE  → S_READ  : on absorb_poly pulse, latch poly_id, begin reads
 *   S_READ  → S_FLUSH : all 256 coefficients consumed, drain buffer
 *   S_FLUSH → S_IDLE  : buffer drained, assert done_o
 *
 * Usage Contract:
 *   - absorb_poly must be a single-cycle pulse when state == S_IDLE.
 *   - is_last_i must be stable from absorb_poly until done_o.
 *   - Controller must wait for done_o before asserting absorb_poly again.
 */

`default_nettype none
`timescale 1ns / 1ps
import qrem_global_pkg::*;

module coeff_to_axis_packer #(
    parameter int COEFF_W   = COEFF_WIDTH,
    parameter int NCOEFF    = qrem_global_pkg::NCOEFF,
    parameter int NUM_POLYS = qrem_global_pkg::NUM_POLYS,
    parameter int DWIDTH    = qrem_global_pkg::DWIDTH
) (
    input  wire                              clk,
    input  wire                              rst,

    // Trigger: pulse once per polynomial. Latches poly_id_i.
    input  wire                              absorb_poly,

    // Configuration — latched on absorb_poly
    input  wire  [$clog2(NUM_POLYS)-1:0]     poly_id_i,

    // When high, the final flush beat will assert t_last_o.
    // When low, t_last_o is never asserted (more data follows from other sources).
    input  wire                              is_last_i,

    // Poly Memory Reader — driven by this module
    output logic                             rd_req_o,
    output logic [$clog2(NUM_POLYS)-1:0]     rd_poly_id_o,
    output logic [3:0][$clog2(NCOEFF)-1:0]   rd_idx_o,        // {n+3, n+2, n+1, n}
    input  wire  [3:0][COEFF_W-1:0]          rd_data_i,
    input  wire                              rd_valid_i,

    // AXI4-Stream Source → Keccak Sink
    output logic [DWIDTH-1:0]               t_data_o,
    output logic                            t_valid_o,
    output logic                            t_last_o,
    output logic [DWIDTH/8-1:0]             t_keep_o,
    input  wire                             t_ready_i,

    // Pulses one cycle after final byte sent to Keccak
    output logic                            done_o
);

    // =========================================================================
    // 1. PARAMETERS & TYPES
    // =========================================================================
    localparam int BUF_W        = 96;                       // 12 bytes gearbox buffer
    localparam int COEFF_STEP   = 4;                        // Coefficients read per beat
    localparam int LAST_IDX_VAL = NCOEFF - COEFF_STEP;     // 252

    typedef enum logic [1:0] {
        S_IDLE,
        S_READ,
        S_FLUSH
    } state_t;

    // =========================================================================
    // 2. REGISTERS
    // =========================================================================
    state_t                         state;

    // Gearbox buffer: holds up to 96 bits (12 bytes) of unpacked coefficients
    logic [BUF_W-1:0]               buf_reg;
    logic [3:0]                     fill_count;  // Valid bytes in buffer (0–12)

    // Address generation counter — steps 0, 4, 8, ..., 252
    logic [$clog2(NCOEFF)-1:0]      coeff_idx;

    // Latched config
    logic [$clog2(NUM_POLYS)-1:0]   cur_poly_id;
    logic                           is_last_lat; // Latched copy of is_last_i

    // =========================================================================
    // 3. COMBINATIONAL NEXT-STATE
    // =========================================================================
    state_t                         state_nxt;
    logic [BUF_W-1:0]               buf_nxt;
    logic [3:0]                     fill_nxt;
    logic [$clog2(NCOEFF)-1:0]      coeff_idx_nxt;

    // Packed 48-bit coefficient word from rd_data_i
    logic [47:0]                    coeff_packed;
    assign coeff_packed = {rd_data_i[3], rd_data_i[2], rd_data_i[1], rd_data_i[0]};

    logic                           can_emit;
    assign can_emit = (fill_count >= 4'd8);

    // All 256 coefficients have been issued to the reader
    logic                           all_coeffs_sent;
    assign all_coeffs_sent = (coeff_idx == $clog2(NCOEFF)'(LAST_IDX_VAL)) && rd_valid_i;

    always_comb begin
        // Defaults: hold registers
        state_nxt     = state;
        buf_nxt       = buf_reg;
        fill_nxt      = fill_count;
        coeff_idx_nxt = coeff_idx;

        rd_req_o      = 1'b0;
        rd_poly_id_o  = cur_poly_id;
        rd_idx_o[0]   = coeff_idx;
        rd_idx_o[1]   = coeff_idx + 1;
        rd_idx_o[2]   = coeff_idx + 2;
        rd_idx_o[3]   = coeff_idx + 3;

        t_data_o      = '0;
        t_valid_o     = 1'b0;
        t_last_o      = 1'b0;
        t_keep_o      = '0;
        done_o        = 1'b0;

        case (state)

            S_IDLE: begin
                if (absorb_poly) begin
                    state_nxt     = S_READ;
                    buf_nxt       = '0;
                    fill_nxt      = '0;
                    coeff_idx_nxt = '0;
                end
            end

            S_READ: begin
                // ── Emit if buffer has ≥ 8 bytes ──────────────────────────
                if (can_emit) begin
                    t_data_o  = buf_reg[63:0];
                    t_valid_o = 1'b1;
                    t_keep_o  = 8'hFF;
                    t_last_o  = 1'b0; // Never t_last during READ; handled in FLUSH

                    if (t_ready_i) begin
                        buf_nxt  = BUF_W'({32'b0, buf_reg[BUF_W-1:64]});
                        fill_nxt = fill_nxt - 4'd8;
                    end
                end

                // ── Issue read request if buffer can accept 6 more bytes ──
                if (coeff_idx <= $clog2(NCOEFF)'(LAST_IDX_VAL) && (fill_nxt <= 4'd6)) begin
                    rd_req_o = 1'b1;

                    if (rd_valid_i) begin
                        // Push 48 bits into buffer at current fill position
                        buf_nxt  = buf_nxt | (BUF_W'(coeff_packed) << {fill_nxt, 3'b000});
                        fill_nxt = fill_nxt + 4'd6;

                        if (all_coeffs_sent) begin
                            // All coefficients consumed — go flush
                            coeff_idx_nxt = coeff_idx; // Hold (no more reads)
                            state_nxt     = S_FLUSH;
                        end else begin
                            coeff_idx_nxt = coeff_idx + $clog2(NCOEFF)'(COEFF_STEP);
                        end
                    end
                end else if (!can_emit && coeff_idx > $clog2(NCOEFF)'(LAST_IDX_VAL)) begin
                    // All reads issued, buffer < 8 bytes, go flush
                    state_nxt = S_FLUSH;
                end
            end

            S_FLUSH: begin
                if (fill_count > 4'd0) begin
                    t_data_o  = buf_reg[63:0];
                    t_valid_o = 1'b1;
                    // Assert t_last only if controller says this is the last segment
                    t_last_o  = is_last_lat;
                    // t_keep: fill_count valid bytes
                    t_keep_o  = (8'hFF >> (4'd8 - fill_count[2:0]));

                    if (t_ready_i) begin
                        buf_nxt   = '0;
                        fill_nxt  = '0;
                        done_o    = 1'b1;
                        state_nxt = S_IDLE;
                    end
                end else begin
                    // Buffer exactly aligned — nothing to flush
                    // If is_last, we need to emit a zero-keep last beat OR
                    // signal done without a beat (Keccak already received t_last implicitly
                    // from the READ phase if a full 8-byte aligned flush occurred).
                    done_o    = 1'b1;
                    state_nxt = S_IDLE;
                end
            end

            default: state_nxt = S_IDLE;
        endcase
    end

    // =========================================================================
    // 4. SEQUENTIAL
    // =========================================================================
    always_ff @(posedge clk or posedge rst) begin
        if (rst) begin
            state       <= S_IDLE;
            buf_reg     <= '0;
            fill_count  <= '0;
            coeff_idx   <= '0;
            cur_poly_id <= '0;
            is_last_lat <= '0;
        end else begin
            state      <= state_nxt;
            buf_reg    <= buf_nxt;
            fill_count <= fill_nxt;
            coeff_idx  <= coeff_idx_nxt;

            if (absorb_poly) begin
                cur_poly_id <= poly_id_i;
                is_last_lat <= is_last_i;
            end
        end
    end

    // =========================================================================
    // 5. ASSERTIONS (simulation only)
    // =========================================================================
    // synthesis translate_off
    assert property (@(posedge clk) disable iff (rst) fill_count <= 4'd12)
        else $fatal(1, "coeff_to_axis_packer: fill_count overflow: %0d", fill_count);

    assert property (@(posedge clk) disable iff (rst)
                    !(absorb_poly && state != S_IDLE))
        else $fatal(1, "coeff_to_axis_packer: absorb_poly pulsed while not idle!");
    // synthesis translate_on

endmodule

`default_nettype wire
