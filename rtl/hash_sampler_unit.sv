/*
 * Module Name: hash_sampler_unit
 * Author(s): Kiet Le
 * Target: FIPS 203 (ML-KEM / Kyber) Hardware Accelerator
 *
 * Reference:
 *
 * Description:
 */

import hash_sample_pkg::*;

module hash_sampler_unit (
    input   wire                            clk,
    input   wire                            rst,

    // Control
    input  wire                                 start_i,
    input  wire hs_mode_t                       hsu_mode_i,
    input  wire [XOF_LEN_WIDTH-1:0]             xof_len_i,  // Keccak XOF length (in bytes)
    input  wire                                 is_eta3_i,  // 1 = ML-KEM-768/1024 (η=3), 0 = ML-KEM-512 (η=2)

    // AXI4-Stream Sink
    input  wire  [HSU_IN_DWIDTH-1:0]        t_data_i,
    input  wire                             t_valid_i,
    input  wire                             t_last_i,
    input  wire  [HSU_IN_KEEP_WIDTH-1:0]    t_keep_i,
    output logic                            t_ready_o,

    // AXI4-Stream Source
    output logic [HSU_OUT_DWIDTH-1:0]       t_data_o,
    output logic                            t_valid_o,
    output logic                            t_last_o,
    output logic [HSU_OUT_KEEP_WIDTH-1:0]   t_keep_o,
    input  wire                             t_ready_i
);
    // ==========================================================
    // Interconnection Signals
    // ==========================================================

    // Keccak Core Logic
    logic                                   keccak_start;
    logic [MODE_SEL_WIDTH-1:0]              keccak_mode;
    logic                                   keccak_stop;

    logic [DWIDTH-1:0]                      keccak_t_data_i;
    logic                                   keccak_t_valid_i;
    logic                                   keccak_t_last_i;
    logic [KEEP_WIDTH-1:0]                  keccak_t_keep_i;
    logic                                   keccak_t_ready_o;

    logic [DWIDTH-1:0]                      keccak_t_data_o;
    logic                                   keccak_t_valid_o;
    logic                                   keccak_t_last_o;
    logic [KEEP_WIDTH-1:0]                  keccak_t_keep_o;
    logic                                   keccak_t_ready_i;

    // Sample NTT Logic
    logic                                   sample_ntt_start;
    logic                                   sample_ntt_done;

    logic [HSU_IN_DWIDTH-1:0]               sample_ntt_t_data_i;
    logic                                   sample_ntt_t_valid_i;
    logic                                   sample_ntt_t_last_i;
    logic [HSU_IN_KEEP_WIDTH-1:0]           sample_ntt_t_keep_i;
    logic                                   sample_ntt_t_ready_o;

    logic [HSU_OUT_DWIDTH-1:0]              sample_ntt_t_data_o;
    logic                                   sample_ntt_t_valid_o;
    logic                                   sample_ntt_t_last_o;
    logic [HSU_OUT_KEEP_WIDTH-1:0]          sample_ntt_t_keep_o;
    logic                                   sample_ntt_t_ready_i;

    // Sample CBD Logic
    logic                                   sample_cbd_start;
    logic                                   sample_cbd_done;

    logic [HSU_IN_DWIDTH-1:0]               sample_cbd_t_data_i;
    logic                                   sample_cbd_t_valid_i;
    logic                                   sample_cbd_t_last_i;
    logic [HSU_IN_KEEP_WIDTH-1:0]           sample_cbd_t_keep_i;
    logic                                   sample_cbd_t_ready_o;

    logic [HSU_OUT_DWIDTH-1:0]              sample_cbd_t_data_o;
    logic                                   sample_cbd_t_valid_o;
    logic                                   sample_cbd_t_last_o;
    logic [HSU_OUT_KEEP_WIDTH-1:0]          sample_cbd_t_keep_o;
    logic                                   sample_cbd_t_ready_i;

    // ==========================================================
    // Module Instantiations
    // ==========================================================

    // --- Keccak Core ---
    keccak_core keccak_core_inst (
        .clk            (clk),
        .rst            (rst),

        .start_i        (keccak_start),
        .keccak_mode_i  (keccak_mode),
        .stop_i         (keccak_stop),

        .t_data_i       (keccak_t_data_i),
        .t_valid_i      (keccak_t_valid_i),
        .t_last_i       (keccak_t_last_i),
        .t_keep_i       (keccak_t_keep_i),
        .t_ready_o      (keccak_t_ready_o),

        .t_data_o       (keccak_t_data_o),
        .t_valid_o      (keccak_t_valid_o),
        .t_last_o       (keccak_t_last_o),
        .t_keep_o       (keccak_t_keep_o),
        .t_ready_i      (keccak_t_ready_i)
    );
    // Assign Keccak Core Inputs
    assign keccak_start         = ;
    assign keccak_mode          = ;
    assign keccak_stop          = ;

    assign keccak_t_data_i      = ;
    assign keccak_t_valid_i     = ;
    assign keccak_t_last_i      = ;
    assign keccak_t_keep_i      = ;

    assign keccak_t_ready_i     = ;

    // --- Sample NTT Module ---
    sample_ntt #(
        .DWIDTH(DWIDTH),
        .KEEP_WIDTH(KEEP_WIDTH)
    ) sample_ntt_inst (
        .clk            (clk),
        .rst            (rst),

        .start_i        (sample_ntt_start),
        .stop_i         (sample_ntt_stop),

        .t_data_i       (sample_ntt_t_data_i),
        .t_valid_i      (sample_ntt_t_valid_i),
        .t_last_i       (sample_ntt_t_last_i),
        .t_keep_i       (sample_ntt_t_keep_i),
        .t_ready_o      (sample_ntt_t_ready_o),

        .t_data_o       (sample_ntt_t_data_o),
        .t_valid_o      (sample_ntt_t_valid_o),
        .t_last_o       (sample_ntt_t_last_o),
        .t_keep_o       (sample_ntt_t_keep_o),
        .t_ready_i      (sample_ntt_t_ready_i)
    );
    // Assign Sample NTT Inputs
    assign sample_ntt_start         = ;
    assign sample_ntt_stop          = ;

    assign sample_ntt_t_data_i      = ;
    assign sample_ntt_t_valid_i     = ;
    assign sample_ntt_t_last_i      = ;
    assign sample_ntt_t_keep_i      = ;

    assign sample_ntt_t_ready_i     = ;

    // --- Sample CBD Module ---
    sample_cbd #(
        .DWIDTH(DWIDTH),
        .KEEP_WIDTH(KEEP_WIDTH)
    ) sample_cbd_inst (
        .clk            (clk),
        .rst            (rst),

        .start_i        (sample_cbd_start),
        .stop_i         (sample_cbd_stop),

        .t_data_i       (sample_cbd_t_data_i),
        .t_valid_i      (sample_cbd_t_valid_i),
        .t_last_i       (sample_cbd_t_last_i),
        .t_keep_i       (sample_cbd_t_keep_i),
        .t_ready_o      (sample_cbd_t_ready_o),

        .t_data_o       (sample_cbd_t_data_o),
        .t_valid_o      (sample_cbd_t_valid_o),
        .t_last_o       (sample_cbd_t_last_o),
        .t_keep_o       (sample_cbd_t_keep_o),
        .t_ready_i      (sample_cbd_t_ready_i)
    );
    // Assign Sample CBD Inputs
    assign sample_cbd_start         = ;
    assign sample_cbd_stop          = ;

    assign sample_cbd_t_data_i      = ;
    assign sample_cbd_t_valid_i     = ;
    assign sample_cbd_t_last_i      = ;
    assign sample_cbd_t_keep_i      = ;

    assign sample_cbd_t_ready_i     = ;

    // ==========================================================
    // Top-Level Control Logic
    // ==========================================================



endmodule
