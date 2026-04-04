/*
 * =============================================================================
 * File        : hash_sampler_unit_tb.sv
 * Author      : Kiet Le
 * Project     : FIPS 203 (ML-KEM / Kyber) Hardware Accelerator
 * Description :
 * Transaction-based, dual-simulator (ModelSim & Verilator) compatible
 * testbench for the complete Hash Sampler Unit (HSU). It verifies both
 * direct cryptographic hashing and the ML-KEM polynomial samplers (NTT/CBD).
 *
 * Key Features:
 * 1. Dynamic File I/O  : Uses the +TEST_DIR plusarg to load specific test
 * vectors (config.txt, input.hex, expected.hex) at
 * runtime without recompiling the RTL.
 * 2. AXI Master Driver : Emulates upstream data sources, accurately driving
 * t_data, t_valid, t_keep, and t_last boundaries.
 * 3. AXI Slave Monitor : Emulates downstream consumers. Includes an elasticity
 * tester that randomly drops t_ready_i to prove the
 * DUT's internal FIFOs and gearboxes safely manage
 * backpressure during Keccak permutations.
 * 4. Cycle-Accurate    : Strict @(posedge clk) synchronization ensures
 * seamless compilation in C++ cycle-based simulators
 * like Verilator.
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

    // Note: Verilator 5+ supports this if compiled with --timing.
    // ModelSim supports this natively.
    always #5 clk = ~clk;

    // =========================================================
    // 2. DUT Signals
    // =========================================================
    logic                 start_i;
    hs_mode_t             hsu_mode_i = MODE_SAMPLE_NTT;
    logic [XOF_LEN_WIDTH-1:0] xof_len_i;
    logic                 is_eta3_i;

    logic [63:0]          t_data_i;
    logic                 t_valid_i;
    logic                 t_last_i;
    logic [7:0]           t_keep_i;
    logic                 t_ready_o;

    logic [63:0]          t_data_o;
    logic                 t_valid_o;
    logic                 t_last_o;
    logic [7:0]           t_keep_o;
    logic                 t_ready_i;

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

    // Test Parameters loaded from config.txt
    int          cfg_mode;
    int          cfg_is_eta3;
    int          cfg_in_bytes;
    int          cfg_out_chunks;

    logic [63:0] input_mem    [128]; // Sufficient for ML-KEM
    logic [63:0] expected_mem [128]; // 64 beats for samplers
    int          errors;

    // =========================================================
    // 5. Driver Task (AXI Master)
    // =========================================================
    task automatic drive_axi_stream();
        int input_beats = (cfg_in_bytes + 7) / 8; // Ceil division by 8
        int remaining_bytes = cfg_in_bytes;

        for (int i = 0; i < input_beats; i++) begin
            t_data_i  <= input_mem[i];
            t_valid_i <= 1'b1;
            t_last_i  <= (i == input_beats - 1) ? 1'b1 : 1'b0;

            // Calculate t_keep based on remaining bytes
            if (remaining_bytes >= 8) begin
                t_keep_i <= 8'hFF;
                remaining_bytes -= 8;
            end else begin
                t_keep_i <= (1 << remaining_bytes) - 1;
            end

            // Wait for handshake (Cycle accurate)
            do begin
                @(posedge clk);
            end while (!t_ready_o);
        end

        t_valid_i <= 1'b0;
        t_last_i  <= 1'b0;
        t_keep_i  <= 8'h00;
    endtask

    // =========================================================
    // 6. Monitor Task (AXI Slave + Elasticity Tester)
    // =========================================================
    task automatic monitor_axi_stream();
        int beat_idx = 0;

        while (beat_idx < cfg_out_chunks) begin
            // 20% chance to drop ready low to test FIFO backpressure
            t_ready_i <= ($urandom_range(0, 99) < 80) ? 1'b1 : 1'b0;
            @(posedge clk);

            if (t_valid_o && t_ready_i) begin
                if (t_data_o !== expected_mem[beat_idx]) begin
                    $error("[FAIL] Beat %0d | Expected: %16X | Got: %16X", beat_idx, expected_mem[beat_idx], t_data_o);
                    errors++;
                end
                beat_idx++;
            end
        end
        t_ready_i <= 1'b0;
    endtask

    // =========================================================
    // 7. Main Execution
    // =========================================================
    initial begin
        errors = 0;
        start_i = 0; t_valid_i = 0; t_ready_i = 0;

        // Grab the test directory from Makefile argument
        if (!$value$plusargs("TEST_DIR=%s", test_dir)) begin
            $fatal(1, "No +TEST_DIR provided! Run via Makefile.");
        end

        $display("==================================================");
        $display(" Running Test in: %s", test_dir);
        $display("==================================================");

        // Construct paths
        config_file   = {test_dir, "/config.txt"};
        input_file    = {test_dir, "/input.hex"};
        expected_file = {test_dir, "/expected.hex"};

        // Parse config.txt
        fd = $fopen(config_file, "r");
        if (!fd) $fatal(1, "Could not open %s", config_file);
        while (!$feof(fd)) begin
            scan_rtn = $fscanf(fd, "%s=%d\n", key, val);
            if (key == "MODE") cfg_mode = val;
            if (key == "IS_ETA3") cfg_is_eta3 = val;
            if (key == "IN_BYTES") cfg_in_bytes = val;
            if (key == "OUT_CHUNKS") cfg_out_chunks = val;
        end
        $fclose(fd);

        // Load Hex Files
        $readmemh(input_file, input_mem);
        $readmemh(expected_file, expected_mem);

        // Reset Sequence
        #20 rst = 0;
        @(posedge clk);

        // Trigger DUT
        hsu_mode_i = hs_mode_t'(cfg_mode);
        is_eta3_i  = cfg_is_eta3[0];
        xof_len_i  = '0; // Standardize for now

        start_i = 1'b1;
        @(posedge clk);
        start_i = 1'b0;

        // Run Master and Slave concurrently
        fork
            drive_axi_stream();
            monitor_axi_stream();
        join

        if (errors == 0) $display("\n>>> TEST PASSED <<<\n");
        else $display("\n>>> TEST FAILED with %0d errors <<<\n", errors);

        #50 $finish;
    end
endmodule
`default_nettype wire
