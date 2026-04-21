/*
 * Module Name: hash_sampler_unit
 * Author(s): Kiet Le
 * Target: FIPS 203 (ML-KEM / Kyber) Hardware Accelerator
 * Description:
 * - Unified Hashing and Sampling Unit (HSU) for ML-KEM (Kyber) Hardware Accelerators.
 * - Encapsulates a high-performance Keccak Core and various ML-KEM Samplers.
 * - Routes the 64-bit AXI4-Stream output of Keccak Core either directly to Seed Memory
 *   (Bypass/Absorb Modes) or through specialized Rejection (NTT) and CBD samplers.
 *
 * Multi-Phase Absorption Protocol (MODE_ABSORB_POLY + Seed):
 * --------------------------------------------------------------------------
 * A single SHA3-256 hash can absorb an arbitrary sequence of data segments
 * sourced from either Poly Memory (coefficients) or Seed Memory. The top-level
 * controller orchestrates this via:
 *
 *   start_i       : Pulse once to start a new hash operation (resets Keccak state).
 *   absorb_poly_i : Pulse once per polynomial to absorb. Triggers the packer.
 *                   Must not be pulsed again until packer_done_o is high.
 *   absorb_last_i : Must be high on the LAST segment (poly or seed) before squeeze.
 *                   Gates t_last into Keccak. Low for all intermediate segments.
 *   input_sel_i   : 0 = Seed Memory feed, 1 = Poly Memory Reader (via packer).
 *
 * Example: H(t_hat[0] || t_hat[1] || rho)
 *   1. start_i=1, hsu_mode_i=MODE_ABSORB_POLY
 *   2. input_sel_i=1, poly_id_i=0, absorb_poly_i=1, absorb_last_i=0 → wait packer_done_o
 *   3. input_sel_i=1, poly_id_i=1, absorb_poly_i=1, absorb_last_i=0 → wait packer_done_o
 *   4. input_sel_i=0, absorb_last_i=1 → drive rho via seed_rdata_i → Keccak squeezes
 *
 * Mode Summary (hsu_mode_i):
 * -----------------------------------------------------------------------------------------
 * | Enum Name          | Keccak Mode | Input Source       | Sampler Layer | Target        |
 * |--------------------|-------------|--------------------|---------------|---------------|
 * | MODE_SAMPLE_NTT    | SHAKE128    | Seed Mem           | Rejection     | Mat A         |
 * | MODE_SAMPLE_CBD    | SHAKE256    | Seed Mem           | CBD           | s, e          |
 * | MODE_HASH_SHA3_256 | SHA3-256    | Seed Mem           | Bypass        | H(p,m,c)      |
 * | MODE_HASH_SHA3_512 | SHA3-512    | Seed Mem           | Bypass        | G(d,m,h)      |
 * | MODE_HASH_SHAKE256 | SHAKE256    | Seed Mem           | Bypass        | J(z, c)       |
 * | MODE_ABSORB_POLY   | SHA3-256    | Poly Mem Rd / Seed | Bypass        | H(poly||seed) |
 * -----------------------------------------------------------------------------------------
 */

`default_nettype none
`timescale 1ns / 1ps

import hash_sample_pkg::*;

module hash_sampler_unit #(
    parameter int COEFF_W     = 12,
    parameter int NCOEFF      = 256,
    parameter int NUM_POLYS   = 16,
    parameter int NUM_SEEDS   = 8,
    parameter int SEED_W      = 64,
    parameter int SEED_BEATS  = 4
) (
    input  wire                                 clk,
    input  wire                                 rst,

    // ── Control ──────────────────────────────────────────────────────────────
    input  wire                                 start_i,        // Pulse to start new hash op
    input  wire hs_mode_t                       hsu_mode_i,
    input  wire [XOF_LEN_WIDTH-1:0]             xof_len_i,
    input  wire                                 is_eta3_i,

    input  wire [$clog2(NUM_POLYS)-1:0]         poly_id_i,
    input  wire [$clog2(NUM_SEEDS)-1:0]         seed_id_i,

    // Selects Keccak input source: 0 = Seed Memory, 1 = Poly Memory Reader
    input  wire                                 input_sel_i,

    // Pulse once per poly to absorb (MODE_ABSORB_POLY). Decoupled from start_i.
    // Must be idle (packer_done_o or no active packer op) before pulsing again.
    input  wire                                 absorb_poly_i,

    // High on the last absorption segment before squeeze (poly or seed).
    // Gates t_last into Keccak. Must be stable from absorb trigger until packer_done_o/seed_last.
    input  wire                                 absorb_last_i,

    // ── Poly Memory Writer Output (sampler modes: NTT, CBD) ──────────────────
    output logic                                hsu_req_o,
    output logic [$clog2(NUM_POLYS)-1:0]        hsu_poly_id_o,
    output logic [3:0]                          hsu_wr_en_o,
    output logic [3:0][$clog2(NCOEFF)-1:0]      hsu_wr_idx_o,
    output logic [3:0][COEFF_W-1:0]             hsu_wr_data_o,
    input  wire                                 hsu_stall_i,
    output logic                                hsu_done_o,

    // ── Poly Memory Reader Input (MODE_ABSORB_POLY) ───────────────────────────
    output logic                                hsu_rd_req_o,
    output logic [$clog2(NUM_POLYS)-1:0]        hsu_rd_poly_id_o,
    output logic [3:0][$clog2(NCOEFF)-1:0]      hsu_rd_idx_o,
    input  wire  [3:0][COEFF_W-1:0]             hsu_rd_data_i,
    input  wire                                 hsu_rd_valid_i,

    // ── Seed Memory Port ──────────────────────────────────────────────────────
    output logic                                seed_req_o,
    output logic                                seed_we_o,
    output logic [$clog2(NUM_SEEDS)-1:0]        seed_id_o,
    output logic [$clog2(SEED_BEATS)-1:0]       seed_idx_o,
    output logic [SEED_W-1:0]                   seed_wdata_o,
    input  wire                                 seed_ready_i,

    input  wire                                 seed_rvalid_i,
    input  wire  [SEED_W-1:0]                   seed_rdata_i,

    // ── Status ────────────────────────────────────────────────────────────────
    // Packer has finished draining gearbox buffer for the current poly.
    // Controller safe to pulse absorb_poly_i again or switch input_sel_i.
    output logic                                packer_done_o
);

    // ==========================================================
    // Interconnection Signals
    // ==========================================================

    // Keccak Core
    logic                                       keccak_start;
    keccak_mode                                 keccak_mode_sel;
    logic                                       keccak_stop;
    logic [XOF_LEN_WIDTH-1:0]                   keccak_xof_len;

    logic [63:0]                                keccak_t_data_i;
    logic                                       keccak_t_valid_i;
    logic                                       keccak_t_last_i;
    logic [7:0]                                 keccak_t_keep_i;
    logic                                       keccak_t_ready_o;

    logic [63:0]                                keccak_t_data_o;
    logic                                       keccak_t_valid_o;
    logic                                       keccak_t_last_o;
    logic [7:0]                                 keccak_t_keep_o;
    logic                                       keccak_t_ready_i;

    // Sample NTT
    logic                                       sample_ntt_start;
    logic [63:0]                                sample_ntt_t_data_i;
    logic                                       sample_ntt_t_valid_i;
    logic                                       sample_ntt_t_last_i;
    logic [7:0]                                 sample_ntt_t_keep_i;
    logic                                       sample_ntt_t_ready_o;
    logic [3:0]                                 sample_ntt_wr_en;
    logic [3:0][$clog2(NCOEFF)-1:0]             sample_ntt_wr_idx;
    logic [3:0][COEFF_W-1:0]                    sample_ntt_wr_data;
    logic                                       sample_ntt_wr_valid;
    logic                                       sample_ntt_done;

    // Sample CBD
    logic                                       sample_cbd_start;
    logic                                       sample_cbd_is_eta3;
    logic [63:0]                                sample_cbd_t_data_i;
    logic                                       sample_cbd_t_valid_i;
    logic                                       sample_cbd_t_last_i;
    logic [7:0]                                 sample_cbd_t_keep_i;
    logic                                       sample_cbd_t_ready_o;
    logic [3:0]                                 sample_cbd_wr_en;
    logic [3:0][$clog2(NCOEFF)-1:0]             sample_cbd_wr_idx;
    logic [3:0][COEFF_W-1:0]                    sample_cbd_wr_data;
    logic                                       sample_cbd_wr_valid;
    logic                                       sample_cbd_done;

    // Packer (MODE_ABSORB_POLY)
    logic [63:0]                                packer_t_data;
    logic                                       packer_t_valid;
    logic                                       packer_t_last;
    logic [7:0]                                 packer_t_keep;
    logic                                       packer_t_ready;
    logic                                       packer_rd_req;
    logic [$clog2(NUM_POLYS)-1:0]               packer_rd_poly_id;
    logic [3:0][$clog2(NCOEFF)-1:0]             packer_rd_idx;

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

    // Seed input beat counter (used for t_last in seed path)
    logic [$clog2(SEED_BEATS)-1:0] seed_rd_beat_cnt;
    logic                          seed_beat_last;

    assign seed_beat_last = (seed_rd_beat_cnt == SEED_BEATS - 1);

    always_ff @(posedge clk or posedge rst) begin
        if (rst) begin
            seed_rd_beat_cnt <= '0;
        end else begin
            if (start_i)
                seed_rd_beat_cnt <= '0;
            else if (input_sel_i == 1'b0 && seed_rvalid_i && keccak_t_ready_o)
                seed_rd_beat_cnt <= seed_rd_beat_cnt + 1;
        end
    end

    // Keccak start + mode
    assign keccak_start   = start_i;
    assign keccak_stop    = 1'b0;
    assign keccak_xof_len = xof_len_i;

    // Keccak Sink Input MUX: Seed Memory vs Poly Packer
    always_comb begin
        if (input_sel_i) begin
            // Poly Memory Reader path (via packer)
            keccak_t_data_i  = packer_t_data;
            keccak_t_valid_i = packer_t_valid;
            keccak_t_last_i  = packer_t_last;  // Packer gates t_last with is_last_i internally
            keccak_t_keep_i  = packer_t_keep;
        end else begin
            // Seed Memory path — t_last gated by absorb_last_i from controller
            keccak_t_data_i  = seed_rdata_i;
            keccak_t_valid_i = seed_rvalid_i;
            keccak_t_last_i  = seed_beat_last && absorb_last_i;
            keccak_t_keep_i  = 8'hFF;
        end
    end

    // Packer t_ready: only connected in poly absorb mode
    assign packer_t_ready = (hsu_mode_i == MODE_ABSORB_POLY) ? keccak_t_ready_o : 1'b0;

    // --- Sample NTT ---
    sample_ntt #(
        .COEFF_W(COEFF_W),
        .NCOEFF(NCOEFF)
    ) sample_ntt_inst (
        .clk        (clk),
        .rst        (rst),
        .start      (sample_ntt_start),
        .t_data_i   (sample_ntt_t_data_i),
        .t_valid_i  (sample_ntt_t_valid_i),
        .t_last_i   (sample_ntt_t_last_i),
        .t_keep_i   (sample_ntt_t_keep_i),
        .t_ready_o  (sample_ntt_t_ready_o),
        .wr_en_o    (sample_ntt_wr_en),
        .wr_idx_o   (sample_ntt_wr_idx),
        .wr_data_o  (sample_ntt_wr_data),
        .wr_valid_o (sample_ntt_wr_valid),
        .done_o     (sample_ntt_done),
        .stall_i    (hsu_stall_i)
    );

    assign sample_ntt_start    = start_i;
    assign sample_ntt_t_data_i = keccak_t_data_o;
    assign sample_ntt_t_last_i = keccak_t_last_o;
    assign sample_ntt_t_keep_i = keccak_t_keep_o;

    // --- Sample CBD ---
    sample_poly_cbd #(
        .COEFF_W(COEFF_W),
        .NCOEFF(NCOEFF)
    ) sample_cbd_inst (
        .clk        (clk),
        .rst        (rst),
        .start      (sample_cbd_start),
        .is_eta3    (sample_cbd_is_eta3),
        .t_data_i   (sample_cbd_t_data_i),
        .t_valid_i  (sample_cbd_t_valid_i),
        .t_last_i   (sample_cbd_t_last_i),
        .t_keep_i   (sample_cbd_t_keep_i),
        .t_ready_o  (sample_cbd_t_ready_o),
        .wr_en_o    (sample_cbd_wr_en),
        .wr_idx_o   (sample_cbd_wr_idx),
        .wr_data_o  (sample_cbd_wr_data),
        .wr_valid_o (sample_cbd_wr_valid),
        .done_o     (sample_cbd_done),
        .stall_i    (hsu_stall_i)
    );

    assign sample_cbd_start    = start_i;
    assign sample_cbd_is_eta3  = is_eta3_i;
    assign sample_cbd_t_data_i = keccak_t_data_o;
    assign sample_cbd_t_last_i = keccak_t_last_o;
    assign sample_cbd_t_keep_i = keccak_t_keep_o;

    // --- Coeff-to-AXI Packer (MODE_ABSORB_POLY) ---
    // Triggered by absorb_poly_i, NOT start_i — allows multiple poly absorptions
    // within a single Keccak hash operation without resetting state.
    coeff_to_axis_packer #(
        .COEFF_W  (COEFF_W),
        .NCOEFF   (NCOEFF),
        .NUM_POLYS(NUM_POLYS)
    ) packer_inst (
        .clk          (clk),
        .rst          (rst),
        .absorb_poly  (absorb_poly_i),
        .poly_id_i    (poly_id_i),
        .is_last_i    (absorb_last_i),
        .rd_req_o     (packer_rd_req),
        .rd_poly_id_o (packer_rd_poly_id),
        .rd_idx_o     (packer_rd_idx),
        .rd_data_i    (hsu_rd_data_i),
        .rd_valid_i   (hsu_rd_valid_i),
        .t_data_o     (packer_t_data),
        .t_valid_o    (packer_t_valid),
        .t_last_o     (packer_t_last),
        .t_keep_o     (packer_t_keep),
        .t_ready_i    (packer_t_ready),
        .done_o       (packer_done_o)
    );


    // ==========================================================
    // Top-Level Control Logic (Demux / Mux Routing)
    // ==========================================================

    logic [$clog2(SEED_BEATS)-1:0] seed_wr_beat_cnt;

    always_ff @(posedge clk or posedge rst) begin
        if (rst) begin
            seed_wr_beat_cnt <= '0;
        end else begin
            if (start_i)
                seed_wr_beat_cnt <= '0;
            else if (seed_req_o && seed_ready_i)
                seed_wr_beat_cnt <= seed_wr_beat_cnt + 1;
        end
    end

    always_comb begin
        // ------------------------------------------------------
        // Default Assignments
        // ------------------------------------------------------
        keccak_mode_sel      = SHA3_256;

        sample_ntt_t_valid_i = 1'b0;
        sample_cbd_t_valid_i = 1'b0;
        keccak_t_ready_i     = 1'b0;

        hsu_req_o            = 1'b0;
        hsu_poly_id_o        = poly_id_i;
        hsu_wr_en_o          = 4'b0;
        hsu_wr_idx_o         = '0;
        hsu_wr_data_o        = '0;
        hsu_done_o           = 1'b0;

        seed_req_o           = 1'b0;
        seed_we_o            = 1'b0;
        seed_id_o            = seed_id_i;
        seed_idx_o           = seed_wr_beat_cnt;
        seed_wdata_o         = '0;

        hsu_rd_req_o         = 1'b0;
        hsu_rd_poly_id_o     = '0;
        hsu_rd_idx_o         = '0;

        // ------------------------------------------------------
        // Routing
        // ------------------------------------------------------
        unique case (hsu_mode_i)

            MODE_SAMPLE_NTT: begin
                keccak_mode_sel      = SHAKE128;
                sample_ntt_t_valid_i = keccak_t_valid_o;
                keccak_t_ready_i     = sample_ntt_t_ready_o;
                hsu_req_o            = sample_ntt_wr_valid;
                hsu_wr_en_o          = sample_ntt_wr_en;
                hsu_wr_idx_o         = sample_ntt_wr_idx;
                hsu_wr_data_o        = sample_ntt_wr_data;
                hsu_done_o           = sample_ntt_done;
            end

            MODE_SAMPLE_CBD: begin
                keccak_mode_sel      = SHAKE256;
                sample_cbd_t_valid_i = keccak_t_valid_o;
                keccak_t_ready_i     = sample_cbd_t_ready_o;
                hsu_req_o            = sample_cbd_wr_valid;
                hsu_wr_en_o          = sample_cbd_wr_en;
                hsu_wr_idx_o         = sample_cbd_wr_idx;
                hsu_wr_data_o        = sample_cbd_wr_data;
                hsu_done_o           = sample_cbd_done;
            end

            MODE_HASH_SHA3_256, MODE_HASH_SHA3_512, MODE_HASH_SHAKE256: begin
                if      (hsu_mode_i == MODE_HASH_SHA3_256) keccak_mode_sel = SHA3_256;
                else if (hsu_mode_i == MODE_HASH_SHA3_512) keccak_mode_sel = SHA3_512;
                else                                        keccak_mode_sel = SHAKE256;
                seed_req_o       = keccak_t_valid_o;
                seed_we_o        = 1'b1;
                seed_wdata_o     = keccak_t_data_o;
                keccak_t_ready_i = seed_ready_i;
            end

            MODE_ABSORB_POLY: begin
                keccak_mode_sel  = SHA3_256;
                // Poly reader driven by packer
                hsu_rd_req_o     = packer_rd_req;
                hsu_rd_poly_id_o = packer_rd_poly_id;
                hsu_rd_idx_o     = packer_rd_idx;
                // Keccak output → Seed Memory (32B SHA3-256 digest)
                seed_req_o       = keccak_t_valid_o;
                seed_we_o        = 1'b1;
                seed_wdata_o     = keccak_t_data_o;
                keccak_t_ready_i = seed_ready_i;
            end

        endcase
    end

endmodule

`default_nettype wire
