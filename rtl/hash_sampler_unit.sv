/*
 * Module Name: hash_sampler_unit
 * Author(s): Kiet Le
 * Target: FIPS 203 (ML-KEM / Kyber) Hardware Accelerator
 * Description:
 * - Unified Hashing and Sampling Unit (HSU) for ML-KEM (Kyber) Hardware Accelerators.
 * - Encapsulates a high-performance Keccak Core and various ML-KEM Samplers.
 * - Routes the 64-bit AXI4-Stream output of the Keccak Core either directly to the
 *   top-level (Bypass Mode) or through specialized Rejection (NTT) and CBD samplers.
 * - Features a dynamic demux/mux routing architecture controlled by the 'hsu_mode_i' enum.
 *
 * Performance & Latency:
 * - Direct Hashing: Latency depends solely on Keccak Core (24 cycles per 1600-bit permutation).
 * - NTT Sampling: Produces exactly 256 coefficients; latency varies due to rejection logic.
 * - CBD Sampling: Produces exactly 256 coefficients; deterministic latency based on η (eta).
 *
 * Usage Contract:
 * - 'hsu_mode_i' and 'is_eta3_i' must be stable when 'start_i' is pulsed for exactly one cycle.
 * - Input/Output data follows standard AXI4-Stream (t_data, t_valid, t_ready, t_last, t_keep) protocols.
 * - 'xof_len_i' defines the total output length in bytes for Keccak XOF modes (0 = infinite).
 *
 * Mode Summary (hsu_mode_i):
 * -----------------------------------------------------------------------------
 * | Enum Name          | Keccak Mode | Sampler Layer | Security (η) | Target  |
 * |--------------------|-------------|---------------|--------------|---------|
 * | MODE_SAMPLE_NTT    | SHAKE128    | Rejection     | N/A          | Mat A   |
 * | MODE_SAMPLE_CBD    | SHAKE256    | CBD           | η=2 or η=3   | s, e    |
 * | MODE_HASH_SHA3_256 | SHA3-256    | Bypass        | N/A          | H(p,m,c)|
 * | MODE_HASH_SHA3_512 | SHA3-512    | Bypass        | N/A          | G(d,m,h)|
 * | MODE_HASH_SHAKE256 | SHAKE256    | Bypass        | N/A          | J(z, c) |
 * -----------------------------------------------------------------------------
 *
 * Interface Notes:
 * - 48-bit sampler outputs are zero-padded to 64-bit 't_data_o' {16'b0, data[47:0]}.
 * - 't_keep_o' reflects valid 6-byte chunks (6'h3F) for sampler outputs.
 */

`default_nettype none
`timescale 1ns / 1ps

import hash_sample_pkg::*;

module hash_sampler_unit (
    input  wire                                 clk,
    input  wire                                 rst,

    // Control
    input  wire                                 start_i,
    input  wire hs_mode_t                       hsu_mode_i,
    input  wire [XOF_LEN_WIDTH-1:0]             xof_len_i,  // Keccak XOF length (in bytes)
    input  wire                                 is_eta3_i,  // 1 = ML-KEM-768/1024 (η=3), 0 = ML-KEM-512 (η=2)

    // AXI4-Stream Sink
    input  wire [HSU_IN_DWIDTH-1:0]             t_data_i,
    input  wire                                 t_valid_i,
    input  wire                                 t_last_i,
    input  wire [HSU_IN_KEEP_WIDTH-1:0]         t_keep_i,
    output logic                                t_ready_o,

    // AXI4-Stream Source
    output logic [HSU_OUT_DWIDTH-1:0]           t_data_o,
    output logic                                t_valid_o,
    output logic                                t_last_o,
    output logic [HSU_OUT_KEEP_WIDTH-1:0]       t_keep_o,
    input  wire                                 t_ready_i
);

    // ==========================================================
    // Interconnection Signals
    // ==========================================================

    // Keccak Core Logic
    logic                                       keccak_start;
    keccak_mode                                 keccak_mode_sel;
    logic                                       keccak_stop;
    logic [XOF_LEN_WIDTH-1:0]                   keccak_xof_len;

    logic [63:0]                                keccak_t_data_i; // Keccak is exactly 64-bits
    logic                                       keccak_t_valid_i;
    logic                                       keccak_t_last_i;
    logic [7:0]                                 keccak_t_keep_i;
    logic                                       keccak_t_ready_o;

    logic [63:0]                                keccak_t_data_o;
    logic                                       keccak_t_valid_o;
    logic                                       keccak_t_last_o;
    logic [7:0]                                 keccak_t_keep_o;
    logic                                       keccak_t_ready_i;

    // Sample NTT Logic
    logic                                       sample_ntt_start;

    logic [63:0]                                sample_ntt_t_data_i;
    logic                                       sample_ntt_t_valid_i;
    logic                                       sample_ntt_t_last_i;
    logic [7:0]                                 sample_ntt_t_keep_i;
    logic                                       sample_ntt_t_ready_o;

    logic [47:0]                                sample_ntt_t_data_o;
    logic                                       sample_ntt_t_valid_o;
    logic                                       sample_ntt_t_last_o;
    logic [5:0]                                 sample_ntt_t_keep_o;
    logic                                       sample_ntt_t_ready_i;

    // Sample CBD Logic
    logic                                       sample_cbd_start;
    logic                                       sample_cbd_is_eta3;

    logic [63:0]                                sample_cbd_t_data_i;
    logic                                       sample_cbd_t_valid_i;
    logic                                       sample_cbd_t_last_i;
    logic [7:0]                                 sample_cbd_t_keep_i;
    logic                                       sample_cbd_t_ready_o;

    logic [47:0]                                sample_cbd_t_data_o;
    logic                                       sample_cbd_t_valid_o;
    logic                                       sample_cbd_t_last_o;
    logic [5:0]                                 sample_cbd_t_keep_o;
    logic                                       sample_cbd_t_ready_i;


    // ==========================================================
    // Module Instantiations
    // ==========================================================

    // --- Keccak Core ---
    keccak_core keccak_core_inst (
        .clk              (clk),
        .rst              (rst),

        .start_i          (keccak_start),
        .keccak_mode_i    (keccak_mode_sel),
        .xof_len_i        (keccak_xof_len),
        .stop_i           (keccak_stop),

        .s_axis_tdata     (keccak_t_data_i),
        .s_axis_tvalid    (keccak_t_valid_i),
        .s_axis_tlast     (keccak_t_last_i),
        .s_axis_tkeep     (keccak_t_keep_i),
        .s_axis_tready    (keccak_t_ready_o),

        .m_axis_tdata     (keccak_t_data_o),
        .m_axis_tvalid    (keccak_t_valid_o),
        .m_axis_tlast     (keccak_t_last_o),
        .m_axis_tkeep     (keccak_t_keep_o),
        .m_axis_tready    (keccak_t_ready_i)
    );

    // Keccak Sink Input
    assign keccak_start     = start_i;
    assign keccak_stop      = 1'b0;
    assign keccak_xof_len   = xof_len_i;
    assign keccak_t_data_i  = t_data_i[63:0]; // Truncates if HSU_IN_DWIDTH is 256
    assign keccak_t_valid_i = t_valid_i;
    assign keccak_t_last_i  = t_last_i;
    assign keccak_t_keep_i  = t_keep_i[7:0];

    assign t_ready_o        = keccak_t_ready_o;

    // --- Sample NTT Module ---
    sample_ntt sample_ntt_inst (
        .clk        (clk),
        .rst        (rst),
        .start      (sample_ntt_start),

        .t_data_i   (sample_ntt_t_data_i),
        .t_valid_i  (sample_ntt_t_valid_i),
        .t_last_i   (sample_ntt_t_last_i),
        .t_keep_i   (sample_ntt_t_keep_i),
        .t_ready_o  (sample_ntt_t_ready_o),

        .t_data_o   (sample_ntt_t_data_o),
        .t_valid_o  (sample_ntt_t_valid_o),
        .t_last_o   (sample_ntt_t_last_o),
        .t_keep_o   (sample_ntt_t_keep_o),
        .t_ready_i  (sample_ntt_t_ready_i)
    );

    // NTT Sink Data (Always physically connected, Valid signal is gated below)
    assign sample_ntt_start    = start_i;
    assign sample_ntt_t_data_i = keccak_t_data_o;
    assign sample_ntt_t_last_i = keccak_t_last_o;
    assign sample_ntt_t_keep_i = keccak_t_keep_o;

    // --- Sample CBD Module ---
    sample_poly_cbd sample_cbd_inst (
        .clk        (clk),
        .rst        (rst),
        .start      (sample_cbd_start),
        .is_eta3    (sample_cbd_is_eta3),

        .t_data_i   (sample_cbd_t_data_i),
        .t_valid_i  (sample_cbd_t_valid_i),
        .t_last_i   (sample_cbd_t_last_i),
        .t_keep_i   (sample_cbd_t_keep_i),
        .t_ready_o  (sample_cbd_t_ready_o),

        .t_data_o   (sample_cbd_t_data_o),
        .t_valid_o  (sample_cbd_t_valid_o),
        .t_last_o   (sample_cbd_t_last_o),
        .t_keep_o   (sample_cbd_t_keep_o),
        .t_ready_i  (sample_cbd_t_ready_i)
    );

    // CBD Sink Data (Always physically connected, Valid signal is gated below)
    assign sample_cbd_start    = start_i;
    assign sample_cbd_is_eta3  = is_eta3_i;
    assign sample_cbd_t_data_i = keccak_t_data_o;
    assign sample_cbd_t_last_i = keccak_t_last_o;
    assign sample_cbd_t_keep_i = keccak_t_keep_o;


    // ==========================================================
    // Top-Level Control Logic (Demux / Mux Routing)
    // ==========================================================

    always_comb begin
        // ------------------------------------------------------
        // Default Assignments (Prevents Latches)
        // ------------------------------------------------------
        keccak_mode_sel      = SHA3_256;

        // Downstream Valid Gates (Demux)
        sample_ntt_t_valid_i = 1'b0;
        sample_cbd_t_valid_i = 1'b0;
        keccak_t_ready_i     = 1'b0;

        // Top Level Outputs (Mux)
        t_data_o             = '0;
        t_valid_o            = 1'b0;
        t_last_o             = 1'b0;
        t_keep_o             = '0;

        // Upstream Ready Gates
        sample_ntt_t_ready_i = 1'b0;
        sample_cbd_t_ready_i = 1'b0;

        // ------------------------------------------------------
        // Routing based on active hs_mode_t
        // ------------------------------------------------------
        unique case (hsu_mode_i)

            MODE_SAMPLE_NTT: begin
                keccak_mode_sel      = SHAKE128;

                // Route Keccak -> NTT
                sample_ntt_t_valid_i = keccak_t_valid_o;
                keccak_t_ready_i     = sample_ntt_t_ready_o;

                // Route NTT -> Top Level (Pad 48-bit to 64-bit)
                t_data_o             = {16'b0, sample_ntt_t_data_o};
                t_keep_o             = {2'b0,  sample_ntt_t_keep_o};
                t_valid_o            = sample_ntt_t_valid_o;
                t_last_o             = sample_ntt_t_last_o;

                sample_ntt_t_ready_i = t_ready_i;
            end

            MODE_SAMPLE_CBD: begin
                keccak_mode_sel      = SHAKE256;

                // Route Keccak -> CBD
                sample_cbd_t_valid_i = keccak_t_valid_o;
                keccak_t_ready_i     = sample_cbd_t_ready_o;

                // Route CBD -> Top Level (Pad 48-bit to 64-bit)
                t_data_o             = {16'b0, sample_cbd_t_data_o};
                t_keep_o             = {2'b0,  sample_cbd_t_keep_o};
                t_valid_o            = sample_cbd_t_valid_o;
                t_last_o             = sample_cbd_t_last_o;

                sample_cbd_t_ready_i = t_ready_i;
            end

            MODE_HASH_SHA3_256: begin
                keccak_mode_sel      = SHA3_256;

                // Route Keccak directly to output
                t_data_o             = keccak_t_data_o;
                t_keep_o             = keccak_t_keep_o;
                t_valid_o            = keccak_t_valid_o;
                t_last_o             = keccak_t_last_o;

                keccak_t_ready_i     = t_ready_i;
            end

            MODE_HASH_SHA3_512: begin
                keccak_mode_sel      = SHA3_512;

                // Route Keccak directly to output
                t_data_o             = keccak_t_data_o;
                t_keep_o             = keccak_t_keep_o;
                t_valid_o            = keccak_t_valid_o;
                t_last_o             = keccak_t_last_o;

                keccak_t_ready_i     = t_ready_i;
            end

            MODE_HASH_SHAKE256: begin
                keccak_mode_sel      = SHAKE256;

                // Route Keccak directly to output
                t_data_o             = keccak_t_data_o;
                t_keep_o             = keccak_t_keep_o;
                t_valid_o            = keccak_t_valid_o;
                t_last_o             = keccak_t_last_o;

                keccak_t_ready_i     = t_ready_i;
            end
        endcase
    end

endmodule

`default_nettype wire
