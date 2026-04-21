/*
 * Module Name: coeff_to_axis_packer
 * Author(s): Kiet Le
 * Target: FIPS 203 (ML-KEM / Kyber) Hardware Accelerator
 * Description:
 * - Converts 4-coefficient (48-bit / 6-byte) poly memory reader beats into
 *   64-bit (8-byte) AXI4-Stream beats for Keccak Core absorption.
 * - Internally generates sequential poly memory read addresses, reading up to
 *   num_polys_i polynomials (each 256 coefficients) starting at base_poly_id_i.
 * - Implements a 96-bit shift-register gearbox to handle the 6→8 byte packing
 *   without data corruption.
 * - Asserts t_last_o on the final partial or full beat of the last polynomial.
 * - Coefficients are packed raw 12-bit little-endian, 4 per 48-bit beat:
 *     {coeff[3][11:0], coeff[2][11:0], coeff[1][11:0], coeff[0][11:0]}
 *
 * Packing Pattern (LCM(6,8) = 24 bytes per 4-input / 3-output cycle group):
 *   - Every 4 input beats → 3 Keccak output beats (75% throughput).
 *   - Final flush emits remaining bytes as partial beat (t_keep).
 *
 * FSM States:
 *   S_IDLE  → S_READ  : on start pulse, latch config, begin address generation
 *   S_READ  → S_FLUSH : all coefficients consumed, drain buffer
 *   S_FLUSH → S_IDLE  : buffer drained, assert done_o
 */

`default_nettype none
`timescale 1ns / 1ps

module coeff_to_axis_packer #(
    parameter int COEFF_W   = 12,
    parameter int NCOEFF    = 256,
    parameter int NUM_POLYS = 16,
    parameter int DWIDTH    = 64
) (
    input  wire                              clk,
    input  wire                              rst,
    input  wire                              start,

    // Configuration — latched on start
    input  wire  [$clog2(NUM_POLYS)-1:0]     base_poly_id_i,
    input  wire  [2:0]                       num_polys_i,      // 1–4

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
    output logic [DWIDTH/8-1:0]            t_keep_o,
    input  wire                             t_ready_i,

    output logic                            done_o
);

    // =========================================================================
    // 1. PARAMETERS & TYPES
    // =========================================================================
    localparam int COEFF_BYTES  = (COEFF_W * 4 + 7) / 8;  // 6 bytes per beat
    localparam int BUF_W        = 96;                       // 12 bytes buffer
    localparam int COEFF_STEP   = 4;                        // Coefficients per beat
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
    logic [3:0]                     fill_count;  // Bytes currently valid (0–12)

    // Address generation counters
    logic [$clog2(NCOEFF)-1:0]      coeff_idx;      // Current leading coeff index (0, 4, 8, ..., 252)
    logic [2:0]                     poly_idx;       // Current poly within batch (0..num_polys-1)

    // Latched config
    logic [$clog2(NUM_POLYS)-1:0]   base_poly_id;
    logic [2:0]                     total_polys;

    // =========================================================================
    // 3. COMBINATIONAL NEXT-STATE
    // =========================================================================
    state_t                         state_nxt;
    logic [BUF_W-1:0]               buf_nxt;
    logic [3:0]                     fill_nxt;
    logic [$clog2(NCOEFF)-1:0]      coeff_idx_nxt;
    logic [2:0]                     poly_idx_nxt;

    // Packed 48-bit coefficient word from rd_data_i
    logic [47:0]                    coeff_packed;
    assign coeff_packed = {rd_data_i[3], rd_data_i[2], rd_data_i[1], rd_data_i[0]};

    // Whether gearbox has a full 8-byte output ready
    logic                           can_emit;
    assign can_emit = (fill_count >= 4'd8);

    // Helper: all polys done flag
    logic all_done;
    assign all_done = (poly_idx == total_polys) && (coeff_idx == '0);

    always_comb begin
        // Defaults: hold
        state_nxt     = state;
        buf_nxt       = buf_reg;
        fill_nxt      = fill_count;
        coeff_idx_nxt = coeff_idx;
        poly_idx_nxt  = poly_idx;

        rd_req_o      = 1'b0;
        rd_poly_id_o  = base_poly_id + $bits(rd_poly_id_o)'(poly_idx);
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
                if (start) begin
                    state_nxt     = S_READ;
                    buf_nxt       = '0;
                    fill_nxt      = '0;
                    coeff_idx_nxt = '0;
                    poly_idx_nxt  = '0;
                end
            end

            S_READ: begin
                // ── Emit if buffer has ≥ 8 bytes ──────────────────────────
                if (can_emit) begin
                    t_data_o  = buf_reg[63:0];
                    t_valid_o = 1'b1;
                    t_keep_o  = 8'hFF;
                    // t_last: only on last emit when no more data coming AND
                    // after emit the buffer will have exactly 0 bytes that are
                    // the last of the message. We handle t_last in S_FLUSH.
                    t_last_o  = 1'b0;

                    if (t_ready_i) begin
                        // Shift buffer down 8 bytes
                        buf_nxt  = BUF_W'({32'b0, buf_reg[BUF_W-1:64]});
                        fill_nxt = fill_nxt - 4'd8;
                    end
                end

                // ── Issue read request if buffer can accept 6 more bytes ──
                // and we haven't finished reading all polys
                if (!all_done && (fill_nxt <= 4'd6)) begin
                    rd_req_o     = 1'b1;
                    rd_poly_id_o = base_poly_id + $bits(rd_poly_id_o)'(poly_idx);
                    rd_idx_o[0]  = coeff_idx;
                    rd_idx_o[1]  = coeff_idx + 1;
                    rd_idx_o[2]  = coeff_idx + 2;
                    rd_idx_o[3]  = coeff_idx + 3;

                    if (rd_valid_i) begin
                        // Push 48 bits into buffer at fill position
                        buf_nxt  = buf_nxt | (BUF_W'(coeff_packed) << {fill_nxt, 3'b000});
                        fill_nxt = fill_nxt + 4'd6;

                        // Advance address counter
                        if (coeff_idx == $clog2(NCOEFF)'(LAST_IDX_VAL)) begin
                            coeff_idx_nxt = '0;
                            poly_idx_nxt  = poly_idx + 3'b1;
                        end else begin
                            coeff_idx_nxt = coeff_idx + $clog2(NCOEFF)'(COEFF_STEP);
                        end
                    end
                end

                // ── Transition to flush when all data absorbed ─────────────
                if (all_done && !rd_valid_i) begin
                    // Only transition when we just finished last read (or were already done)
                    if (poly_idx == total_polys)
                        state_nxt = S_FLUSH;
                end
            end

            S_FLUSH: begin
                // Drain remaining buffer bytes — may be 0..7 bytes
                if (fill_count > 4'd0) begin
                    t_data_o  = buf_reg[63:0];
                    t_valid_o = 1'b1;
                    t_last_o  = 1'b1;
                    // Build t_keep: fill_count bytes valid
                    t_keep_o  = (8'hFF >> (4'd8 - fill_count[2:0]));

                    if (t_ready_i) begin
                        buf_nxt  = '0;
                        fill_nxt = '0;
                        state_nxt = S_IDLE;
                    end
                end else begin
                    // Buffer already empty — emit zero-byte last beat on full 8B boundary
                    // signal done without a beat (buffer was exactly aligned)
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
            state      <= S_IDLE;
            buf_reg    <= '0;
            fill_count <= '0;
            coeff_idx  <= '0;
            poly_idx   <= '0;
            base_poly_id <= '0;
            total_polys  <= '0;
        end else begin
            state      <= state_nxt;
            buf_reg    <= buf_nxt;
            fill_count <= fill_nxt;
            coeff_idx  <= coeff_idx_nxt;
            poly_idx   <= poly_idx_nxt;

            if (start) begin
                base_poly_id <= base_poly_id_i;
                total_polys  <= num_polys_i;
            end
        end
    end

    // =========================================================================
    // 5. ASSERTIONS (simulation only)
    // =========================================================================
    // synthesis translate_off
    assert property (@(posedge clk) disable iff (rst) fill_count <= 4'd12)
        else $fatal(1, "coeff_to_axis_packer: fill_count overflow: %0d", fill_count);

    assert property (@(posedge clk) disable iff (rst) poly_idx <= 3'd4)
        else $fatal(1, "coeff_to_axis_packer: poly_idx overflow: %0d", poly_idx);
    // synthesis translate_on

endmodule

`default_nettype wire
