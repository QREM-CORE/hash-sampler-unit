/*
 * =============================================================================
 * File        : hash_sampler_unit_tb.sv
 * Author      : Kiet Le
 * Project     : FIPS 203 (ML-KEM / Kyber) Hardware Accelerator
 * Description :
 * Transaction-based, dual-simulator (ModelSim & Verilator) compatible
 * testbench for the complete Hash Sampler Unit (HSU). It verifies both
 * cryptographic hashing (via Seed Memory feed), ML-KEM polynomial samplers
 * (NTT/CBD), and polynomial absorption (MODE_ABSORB_POLY).
 *
 * Key Features:
 * 1. Dynamic File I/O  : Uses the +TEST_DIR plusarg to load specific test
 *                        vectors (config.txt, input.hex, expected.hex) at
 *                        runtime without recompiling the RTL.
 * 2. Seed Memory Driver: Emulates Seed Memory read port driving t_data to
 *                        Keccak for NTT, CBD, and hash bypass modes.
 * 3. Poly Mem Model    : Simulates poly memory for MODE_ABSORB_POLY. Responds
 *                        to hsu_rd_req_o with coefficients loaded from input.hex.
 * 4. AXI Slave Monitor : Emulates downstream consumers with random backpressure.
 * 5. Cycle-Accurate    : Strict @(posedge clk) synchronization for Verilator.
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
    logic                 start_i;
    hs_mode_t             hsu_mode_i = MODE_SAMPLE_NTT;
    logic [XOF_LEN_WIDTH-1:0] xof_len_i;
    logic                 is_eta3_i;
    logic [2:0]           poly_absorb_cnt_i = 3'd1;

    logic [3:0]           poly_id_i = '0;
    logic                 hsu_req_o;
    logic [3:0]           hsu_poly_id_o;
    logic [3:0]           hsu_wr_en_o;
    logic [3:0][7:0]      hsu_wr_idx_o;
    logic [3:0][11:0]     hsu_wr_data_o;
    logic                 hsu_stall_i = 1'b0;
    logic                 hsu_done_o;

    // Poly Memory Reader (MODE_ABSORB_POLY)
    logic                 hsu_rd_req_o;
    logic [3:0]           hsu_rd_poly_id_o;
    logic [3:0][7:0]      hsu_rd_idx_o;
    logic [3:0][11:0]     hsu_rd_data_i;
    logic                 hsu_rd_valid_i;

    // Seed Memory Port
    logic [2:0]           seed_id_i = '0;
    logic                 input_sel_i = 1'b0;
    logic                 keccak_t_ready_o_monitor = 1'b0; // Placeholder for task visibility
    logic                 seed_req_o;
    logic                 seed_we_o;
    logic [2:0]           seed_id_o;
    logic [1:0]           seed_idx_o;
    logic [63:0]          seed_wdata_o;
    logic                 seed_ready_i = 1'b0;

    logic                 seed_rvalid_i = 1'b0;
    logic [63:0]          seed_rdata_i = '0;

    // =========================================================
    // 3. DUT Instantiation
    // =========================================================
    hash_sampler_unit DUT (.*);;;

    // =========================================================
    // 4. Test Variables & Memory
    // =========================================================
    string       test_dir;
    string       config_file, input_file, expected_file;
    int          fd, scan_rtn;
    string       key;
    int          val;

    // Test Parameters loaded from config.txt
    int          cfg_mode;
    int          cfg_is_eta3;
    int          cfg_in_words;    // Number of 64-bit words in input.hex
    int          cfg_out_chunks;
    int          cfg_poly_cnt;    // Number of polys to absorb (MODE_ABSORB_POLY)

    // For seed/hash modes: 64-bit LE words
    logic [63:0] input_mem    [128];
    // For poly absorb mode: coefficients stored as 12-bit values, 4-per-entry
    // input.hex lines for poly mode: each line = one 48-bit beat packed as 64-bit (upper 16 zero)
    // poly_mem[poly_idx][coeff_idx/4] = {c3, c2, c1, c0}
    logic [11:0] poly_mem     [4][64];  // Up to 4 polys, 64 beats (256 coeffs) each
    logic [63:0] expected_mem [128];
    int          errors;

    // =========================================================
    // 5. Seed Memory Driver Task (for NTT/CBD/hash bypass modes)
    // =========================================================
    task automatic drive_seed_memory(input int in_words);
        int beat;
        beat = 0;
        input_sel_i <= 1'b0;
        while (beat < in_words) begin
            seed_rdata_i  <= input_mem[beat];
            seed_rvalid_i <= 1'b1;
            @(posedge clk);
            if (keccak_t_ready_o_monitor) begin
                beat++;
                if (beat >= in_words)
                    seed_rvalid_i <= 1'b0;
            end
        end
        seed_rvalid_i <= 1'b0;
    endtask

    // Monitor wire for keccak ready — accessed via hierarchical reference
    // Using a simple approach: just drive continuously and rely on beat counter
    task automatic drive_seed_memory_simple(input int in_words);
        for (int i = 0; i < in_words; i++) begin
            seed_rdata_i  <= input_mem[i];
            seed_rvalid_i <= 1'b1;
            // Wait for keccak to accept (keccak_t_ready_o from DUT internal)
            // We drive valid continuously; keccak core will assert ready when it can absorb
            @(posedge clk);
            // Keep valid high; keccak_core internally manages backpressure
            // One beat is accepted per cycle in ABSORB state when ready
        end
        seed_rvalid_i <= 1'b0;
        seed_rdata_i  <= '0;
    endtask

    // =========================================================
    // 6. Poly Memory Model Task (for MODE_ABSORB_POLY)
    // =========================================================
    task automatic serve_poly_memory();
        // Respond to rd_req cycles with 1-cycle latency
        // Runs until hsu_done_o (packer done signal propagates via seed)
        // or until all expected output chunks received
        forever begin
            @(posedge clk);
            if (hsu_rd_req_o) begin
                // 1-cycle latency: provide data next cycle
                @(posedge clk);
                // Extract coefficients from poly_mem based on rd_poly_id and rd_idx
                for (int lane = 0; lane < 4; lane++) begin
                    automatic int p   = int'(hsu_rd_poly_id_o) - int'(poly_id_i);
                    automatic int idx = int'(hsu_rd_idx_o[lane]);
                    // poly_mem[p][idx/4] holds 4 coefficients; select the right one
                    // Each input.hex line = 4 coefficients packed as {c3,c2,c1,c0}×12-bit
                    hsu_rd_data_i[lane] <= poly_mem[p][idx >> 2][((idx & 2'h3)) * 12 +: 12];
                end
                hsu_rd_valid_i <= 1'b1;
                @(posedge clk);
                hsu_rd_valid_i <= 1'b0;
            end else begin
                hsu_rd_valid_i <= 1'b0;
                hsu_rd_data_i  <= '0;
            end
        end
    endtask

    // =========================================================
    // 7. Monitor Task (checks outputs against expected)
    // =========================================================
    task automatic monitor_output();
        int beat_idx = 0;
        logic [63:0] received_data;
        logic        data_valid_pulse;

        while (beat_idx < cfg_out_chunks) begin
            // Randomize backpressure
            hsu_stall_i  <= ($urandom_range(0, 99) < 20) ? 1'b1 : 1'b0;
            seed_ready_i <= ($urandom_range(0, 99) < 80) ? 1'b1 : 1'b0;

            @(posedge clk);

            data_valid_pulse = 1'b0;

            if (cfg_mode == int'(MODE_SAMPLE_NTT) || cfg_mode == int'(MODE_SAMPLE_CBD)) begin
                if (hsu_req_o && !hsu_stall_i) begin
                    received_data    = {16'b0, hsu_wr_data_o[3], hsu_wr_data_o[2],
                                               hsu_wr_data_o[1], hsu_wr_data_o[0]};
                    data_valid_pulse = 1'b1;
                end
            end else begin
                // Hash/absorb output via Seed Memory write interface
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
    // 8. Main Execution
    // =========================================================
    initial begin
        errors = 0;
        start_i = 0;
        seed_rvalid_i = 0;
        hsu_rd_valid_i = 0;
        hsu_rd_data_i  = '0;

        if (!$value$plusargs("TEST_DIR=%s", test_dir)) begin
            $fatal(1, "No +TEST_DIR provided! Run via Makefile.");
        end

        $display("==================================================");
        $display(" Running Test in: %s", test_dir);
        $display("==================================================");

        config_file   = {test_dir, "/config.txt"};
        input_file    = {test_dir, "/input.hex"};
        expected_file = {test_dir, "/expected.hex"};

        // Parse config.txt
        cfg_poly_cnt = 1; // Default
        fd = $fopen(config_file, "r");
        if (!fd) $fatal(1, "Could not open %s", config_file);
        while (!$feof(fd)) begin
            scan_rtn = $fscanf(fd, "%s=%d\n", key, val);
            if (key == "MODE")      cfg_mode      = val;
            if (key == "IS_ETA3")   cfg_is_eta3   = val;
            if (key == "IN_WORDS")  cfg_in_words  = val;
            if (key == "OUT_CHUNKS") cfg_out_chunks = val;
            if (key == "POLY_CNT")  cfg_poly_cnt  = val;
        end
        $fclose(fd);

        $readmemh(expected_file, expected_mem);

        // Reset Sequence
        #20 rst = 0;
        @(posedge clk);

        // Trigger DUT
        hsu_mode_i        = hs_mode_t'(cfg_mode);
        is_eta3_i         = cfg_is_eta3[0];
        xof_len_i         = '0;
        poly_absorb_cnt_i = 3'(cfg_poly_cnt);

        if (cfg_mode == int'(MODE_ABSORB_POLY)) begin
            // Load poly memory model from input.hex
            // Format: each line is 4 coefficients packed as {c3[11:0], c2[11:0], c1[11:0], c0[11:0]}
            // Stored as 64-bit hex (upper 16 bits zero)
            begin
                logic [63:0] raw_mem [256];
                $readmemh(input_file, raw_mem);
                for (int p = 0; p < cfg_poly_cnt; p++) begin
                    for (int b = 0; b < 64; b++) begin
                        poly_mem[p][b][11:0]  = raw_mem[p*64 + b][11:0];
                        poly_mem[p][b][23:12] = raw_mem[p*64 + b][23:12];
                        poly_mem[p][b][35:24] = raw_mem[p*64 + b][35:24];
                        poly_mem[p][b][47:36] = raw_mem[p*64 + b][47:36];
                    end
                end
            end

            input_sel_i = 1'b1;
            start_i = 1'b1;
            @(posedge clk);
            start_i = 1'b0;

            fork
                serve_poly_memory();
                monitor_output();
            join_any
            disable fork;

        end else begin
            // Seed memory feed modes (NTT, CBD, hash bypass)
            $readmemh(input_file, input_mem);
            input_sel_i = 1'b0;
            seed_ready_i = 1'b1;

            start_i = 1'b1;
            @(posedge clk);
            start_i = 1'b0;

            fork
                begin
                    // Drive seed memory beats continuously
                    for (int i = 0; i < cfg_in_words; i++) begin
                        seed_rdata_i  <= input_mem[i];
                        seed_rvalid_i <= 1'b1;
                        @(posedge clk);
                    end
                    seed_rvalid_i <= 1'b0;
                    seed_rdata_i  <= '0;
                end
                monitor_output();
            join
        end

        if (errors == 0) $display("\n>>> TEST PASSED <<<\n");
        else $display("\n>>> TEST FAILED with %0d errors <<<\n", errors);

        #50 $finish;
    end

endmodule
`default_nettype wire
