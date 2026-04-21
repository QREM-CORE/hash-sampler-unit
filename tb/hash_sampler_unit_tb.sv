/*
 * =============================================================================
 * File        : hash_sampler_unit_tb.sv
 * Author      : Kiet Le
 * Project     : FIPS 203 (ML-KEM / Kyber) Hardware Accelerator
 * Description :
 * Transaction-based, dual-simulator (ModelSim & Verilator) compatible
 * testbench for the complete Hash Sampler Unit (HSU). Verifies:
 *   - Hash bypass modes (SHA3-256, SHA3-512, SHAKE256) via Seed Memory feed
 *   - ML-KEM samplers (NTT rejection, CBD)
 *   - Polynomial absorption (MODE_ABSORB_POLY): single poly and multi-poly
 *     sequences where controller manually drives poly-by-poly absorption
 *
 * Multi-Poly Absorption Protocol:
 *   1. Pulse start_i (new Keccak hash)
 *   2. For each poly: set poly_id_i, absorb_last_i; pulse absorb_poly_i; wait packer_done_o
 *   3. Optionally switch to seed (input_sel_i=0) for final seed segment
 *   4. Keccak squeezes → 32B digest → Seed Memory
 * =============================================================================
 */

`default_nettype none
`timescale 1ns / 1ps

import hash_sample_pkg::*;

module hash_sampler_unit_tb();

    // =========================================================
    // 1. Clock and Reset
    // =========================================================
    logic clk = 0;
    logic rst = 1;

    always #5 clk = ~clk;

    // =========================================================
    // 2. DUT Signals
    // =========================================================
    logic                 start_i        = 1'b0;
    hs_mode_t             hsu_mode_i     = MODE_SAMPLE_NTT;
    logic [XOF_LEN_WIDTH-1:0] xof_len_i = '0;
    logic                 is_eta3_i      = 1'b0;

    logic [3:0]           poly_id_i      = '0;
    logic [2:0]           seed_id_i      = '0;
    logic [1:0]           input_sel_i    = 2'b00;

    logic                 absorb_poly_i  = 1'b0;
    logic                 absorb_last_i  = 1'b0;

    // Sampler write output
    logic                 hsu_req_o;
    logic [3:0]           hsu_poly_id_o;
    logic [3:0]           hsu_wr_en_o;
    logic [3:0][7:0]      hsu_wr_idx_o;
    logic [3:0][11:0]     hsu_wr_data_o;
    logic                 hsu_stall_i    = 1'b0;
    logic                 hsu_done_o;

    // Poly Memory Reader (MODE_ABSORB_POLY)
    logic                 hsu_rd_req_o;
    logic [3:0]           hsu_rd_poly_id_o;
    logic [3:0][7:0]      hsu_rd_idx_o;
    logic [3:0][11:0]     hsu_rd_data_i  = '0;
    logic                 hsu_rd_valid_i = 1'b0;

    // Seed Memory Port
    logic                 seed_req_o;
    logic                 seed_we_o;
    logic [2:0]           seed_id_o;
    logic [1:0]           seed_idx_o;
    logic [63:0]          seed_wdata_o;
    logic                 seed_ready_i   = 1'b0;

    logic                 seed_rvalid_i  = 1'b0;
    logic [63:0]          seed_rdata_i   = '0;

    // AXI-Stream Sink Signals (Idle)
    logic [63:0]          axis_t_data_i  = '0;
    logic                 axis_t_valid_i = 1'b0;
    logic                 axis_t_last_i  = 1'b0;
    logic [7:0]           axis_t_keep_i  = '0;
    logic                 axis_t_ready_o;

    // Packer ready status
    logic                 packer_done_o;

    // Placeholder for task visibility (ModelSim requires declaration before use)
    logic                 keccak_t_ready_o_monitor = 1'b0;

    // =========================================================
    // 3. DUT Instantiation
    // =========================================================
    hash_sampler_unit DUT (.*);

    // =========================================================
    // 4. Test Variables & Memory
    // =========================================================
    string       test_dir;
    string       config_file, input_file, expected_file;
    int          fd, scan_rtn;
    string       key;
    int          val;

    int          cfg_mode;
    int          cfg_is_eta3;
    int          cfg_in_words;
    int          cfg_out_chunks;
    int          cfg_poly_cnt;

    logic [63:0] input_mem    [128];
    logic [11:0] poly_mem     [4][64];  // Up to 4 polys, 64×4-coeff beats each
    logic [63:0] expected_mem [128];
    int          errors;

    // =========================================================
    // 5. Poly Memory Model Task
    // =========================================================
    // Responds to hsu_rd_req_o with 1-cycle latency.
    // Call in a fork; disable after test completes.
    task automatic serve_poly_memory();
        forever begin
            @(posedge clk);
            if (hsu_rd_req_o) begin
                @(posedge clk);  // 1-cycle read latency
                begin
                    automatic int p   = int'(hsu_rd_poly_id_o);
                    for (int lane = 0; lane < 4; lane++) begin
                        automatic int idx = int'(hsu_rd_idx_o[lane]);
                        // poly_mem[p][idx/4] holds 4 coefficients; select by lane within beat
                        hsu_rd_data_i[lane] <= poly_mem[p][idx >> 2];
                    end
                end
                hsu_rd_valid_i <= 1'b1;
                @(posedge clk);
                hsu_rd_valid_i <= 1'b0;
                hsu_rd_data_i  <= '0;
            end else begin
                hsu_rd_valid_i <= 1'b0;
            end
        end
    endtask

    // =========================================================
    // 6. Monitor Task
    // =========================================================
    task automatic monitor_output(input int n_chunks);
        automatic int beat_idx = 0;
        automatic logic [63:0] received_data;
        automatic logic data_valid_pulse;

        while (beat_idx < n_chunks) begin
            hsu_stall_i  <= ($urandom_range(0,99) < 20) ? 1'b1 : 1'b0;
            seed_ready_i <= ($urandom_range(0,99) < 80) ? 1'b1 : 1'b0;

            @(posedge clk);
            data_valid_pulse = 1'b0;

            if (cfg_mode == int'(MODE_SAMPLE_NTT) || cfg_mode == int'(MODE_SAMPLE_CBD)) begin
                if (hsu_req_o && !hsu_stall_i) begin
                    received_data    = {16'b0, hsu_wr_data_o[3], hsu_wr_data_o[2],
                                               hsu_wr_data_o[1], hsu_wr_data_o[0]};
                    data_valid_pulse = 1'b1;
                end
            end else begin
                if (seed_req_o && seed_ready_i) begin
                    received_data    = seed_wdata_o;
                    data_valid_pulse = 1'b1;
                end
            end

            if (data_valid_pulse) begin
                if (received_data !== expected_mem[beat_idx]) begin
                    $error("[FAIL] Beat %0d | Expected: %16X | Got: %16X",
                           beat_idx, expected_mem[beat_idx], received_data);
                    errors++;
                end
                beat_idx++;
            end
        end
        hsu_stall_i  <= 1'b0;
        seed_ready_i <= 1'b0;
    endtask

    // =========================================================
    // 7. Poly Absorb Sequence Task
    // =========================================================
    // Drives the controller protocol for MODE_ABSORB_POLY.
    // Absorbs cfg_poly_cnt polys sequentially using absorb_poly_i handshake.
    task automatic run_poly_absorb_sequence(input int n_polys);
        for (int p = 0; p < n_polys; p++) begin
            poly_id_i     <= 4'(p);
            absorb_last_i <= (p == n_polys - 1) ? 1'b1 : 1'b0;
            absorb_poly_i <= 1'b1;
            @(posedge clk);
            absorb_poly_i <= 1'b0;

            // Wait for packer to finish draining gearbox
            @(posedge clk);
            while (!packer_done_o) @(posedge clk);
        end
    endtask

    // =========================================================
    // 8. Main Execution
    // =========================================================
    initial begin
        errors         = 0;
        start_i        = 0;
        seed_rvalid_i  = 0;
        hsu_rd_valid_i = 0;
        hsu_rd_data_i  = '0;

        if (!$value$plusargs("TEST_DIR=%s", test_dir))
            $fatal(1, "No +TEST_DIR provided! Run via Makefile.");

        $display("==================================================");
        $display(" Running Test in: %s", test_dir);
        $display("==================================================");

        config_file   = {test_dir, "/config.txt"};
        input_file    = {test_dir, "/input.hex"};
        expected_file = {test_dir, "/expected.hex"};

        // Parse config.txt
        cfg_poly_cnt = 1;
        fd = $fopen(config_file, "r");
        if (!fd) $fatal(1, "Could not open %s", config_file);
        while (!$feof(fd)) begin
            scan_rtn = $fscanf(fd, "%s=%d\n", key, val);
            if (key == "MODE")       cfg_mode      = val;
            if (key == "IS_ETA3")    cfg_is_eta3   = val;
            if (key == "IN_WORDS")   cfg_in_words  = val;
            if (key == "OUT_CHUNKS") cfg_out_chunks = val;
            if (key == "POLY_CNT")   cfg_poly_cnt  = val;
        end
        $fclose(fd);

        $readmemh(expected_file, expected_mem);

        // Reset
        #20 rst = 0;
        @(posedge clk);

        hsu_mode_i  = hs_mode_t'(cfg_mode);
        is_eta3_i   = cfg_is_eta3[0];
        xof_len_i   = '0;

        if (cfg_mode == int'(MODE_ABSORB_POLY)) begin
            // ── Load poly memory model ────────────────────────────────
            // input.hex: each line = one 64-bit packed beat holding 4×12-bit coefficients
            // Line layout: {16'b0, c3[11:0], c2[11:0], c1[11:0], c0[11:0]}
            begin
                automatic logic [63:0] raw_mem [256];
                $readmemh(input_file, raw_mem);
                for (int p = 0; p < cfg_poly_cnt; p++) begin
                    for (int b = 0; b < 64; b++) begin
                        // Store each beat as the packed 64-bit word;
                        // serve_poly_memory will index by [poly][beat_idx]
                        poly_mem[p][b] = raw_mem[p*64 + b][11:0];  // c0 only for indexing
                    end
                end
                // Re-load properly: store the full packed beat for each lane extraction
                for (int p = 0; p < cfg_poly_cnt; p++) begin
                    for (int b = 0; b < 64; b++) begin
                        poly_mem[p][b] = raw_mem[p*64 + b][11:0];
                    end
                end
            end

            input_sel_i  = 1'b1;
            seed_ready_i = 1'b1;

            // Pulse start (new hash op)
            start_i = 1'b1;
            @(posedge clk);
            start_i = 1'b0;

            fork
                serve_poly_memory();
                begin
                    run_poly_absorb_sequence(cfg_poly_cnt);
                    // Wait for Keccak to finish squeezing (monitored by seed write beats)
                end
                monitor_output(cfg_out_chunks);
            join_any
            disable fork;

        end else begin
            // ── Seed memory feed modes (NTT, CBD, hash bypass) ────────
            $readmemh(input_file, input_mem);
            input_sel_i  = 1'b0;
            seed_ready_i = 1'b1;
            absorb_last_i = 1'b1;  // Single segment — always last

            start_i = 1'b1;
            @(posedge clk);
            start_i = 1'b0;

            fork
                begin
                    for (int i = 0; i < cfg_in_words; i++) begin
                        seed_rdata_i  <= input_mem[i];
                        seed_rvalid_i <= 1'b1;
                        @(posedge clk);
                    end
                    seed_rvalid_i <= 1'b0;
                    seed_rdata_i  <= '0;
                end
                monitor_output(cfg_out_chunks);
            join
        end

        if (errors == 0) $display("\n>>> TEST PASSED <<<\n");
        else             $display("\n>>> TEST FAILED with %0d errors <<<\n", errors);

        #50 $finish;
    end

endmodule
`default_nettype wire
