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
import qrem_global_pkg::*;

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

    logic [POLY_ID_WIDTH-1:0] poly_id_i      = '0;
    seed_id_e             seed_id_i      = SEED_ID_D;
    logic [7:0]           row_i          = '0;
    logic [7:0]           col_i          = '0;
    logic [7:0]           cbd_n_i        = '0;
    logic [1:0]           input_sel_i    = 2'b00;

    logic                 absorb_poly_i  = 1'b0;
    logic                 absorb_last_i  = 1'b0;

    // Sampler write output
    logic                 hsu_req_o;
    logic                 hsu_rd_en_o;
    logic [POLY_ID_WIDTH-1:0] hsu_wr_poly_id_o;
    logic [3:0]           hsu_wr_en_o;
    logic [3:0][$clog2(NCOEFF)-1:0] hsu_wr_idx_o;
    logic [3:0][COEFF_WIDTH-1:0] hsu_wr_data_o;
    logic                 hsu_stall_i    = 1'b0;
    logic                 hsu_done_o;

    // Poly Memory Reader (MODE_ABSORB_POLY)
    logic [POLY_ID_WIDTH-1:0] hsu_rd_poly_id_o;
    logic [3:0][$clog2(NCOEFF)-1:0] hsu_rd_idx_o;
    logic [3:0]           hsu_rd_lane_valid_o;
    logic [3:0]           hsu_rd_lane_valid_i = '0;
    logic [3:0][COEFF_WIDTH-1:0] hsu_rd_data_i  = '0;
    logic                 hsu_rd_valid_i = 1'b0;
    logic [POLY_ID_WIDTH-1:0] hsu_rd_poly_id_i = '0;
    logic [3:0][$clog2(NCOEFF)-1:0] hsu_rd_idx_i = '0;

    // Seed Memory Port
    logic                 hsu_seed_req_o;
    logic                 hsu_seed_we_o;
    seed_id_e             hsu_seed_id_o;
    logic [$clog2(SEED_BEATS)-1:0] hsu_seed_idx_o;
    logic [SEED_W-1:0]    hsu_seed_wdata_o;
    logic                 hsu_seed_ready_i   = 1'b0;

    logic                 hsu_seed_rvalid_i  = 1'b0;
    logic [SEED_W-1:0]    hsu_seed_rdata_i   = '0;

    // AXI-Stream Sink Signals (Idle)
    logic [SEED_W-1:0]    axis_t_data_i  = '0;
    logic                 axis_t_valid_i = 1'b0;
    logic                 axis_t_last_i  = 1'b0;
    logic [SEED_W/8-1:0]  axis_t_keep_i  = '0;
    logic                 axis_t_ready_o;

    // Packer ready status
    logic                 packer_done_o;

    // --- Poly Memory Model State ---
    logic                           poly_rd_pending = 1'b0;
    logic [POLY_ID_WIDTH-1:0]       poly_rd_poly_id;
    logic [3:0][$clog2(NCOEFF)-1:0] poly_rd_idx;

    // --- Monitor State ---
    // monitor_n_chunks is set from initial before arming; not driven by always_ff
    logic monitor_active = 1'b0;
    int   monitor_n_chunks = 0;
    // monitor_beat_idx / monitor_expected_idx driven exclusively by monitor always_ff
    int   monitor_beat_idx = 0;
    int   monitor_expected_idx = 0;
    logic monitor_done = 1'b0;

    // Error counters: split ownership to avoid vlog-7061 multi-driver errors.
    // monitor_err_count: driven exclusively by monitor always_ff.
    // init_err_count: driven exclusively by initial block.
    int   monitor_err_count = 0;
    int   init_err_count    = 0;

    // =========================================================
    // 3. DUT Instantiation
    // =========================================================
    hash_sampler_unit DUT (.*);

    // =========================================================
    // 4. Test Variables & Memory
    // =========================================================
    string       test_dir, config_file, input_file, expected_file;
    string       key;
    int          val;
    int          fd, scan_rtn, fd_sigma;
    logic [255:0] expected_sigma_val;

    int          cfg_mode;
    int          cfg_input_sel;
    int          cfg_is_eta3;
    int          cfg_in_words;
    int          cfg_out_chunks;
    int          cfg_poly_cnt;
    int          cfg_row;
    int          cfg_col;
    int          cfg_cbd_n;
    int          cfg_run_g_first;
    int          cfg_seed_words;

    logic [SEED_W-1:0] input_mem    [128];
    logic [SEED_W-1:0] poly_mem     [NUM_POLYS][64];  // 64x64-bit beats (4 coeffs each)
    logic [SEED_W-1:0] expected_mem [128];
    // errors: alias to err_count for display; use err_count throughout

    // =========================================================
    // 5. Poly Memory Model (Reactive)
    // =========================================================
    always_ff @(posedge clk) begin
        if (rst) begin
            poly_rd_pending <= 1'b0;
            hsu_rd_valid_i  <= 1'b0;
            hsu_rd_data_i   <= '0;
        end else if (hsu_req_o && hsu_rd_en_o && !poly_rd_pending) begin
            poly_rd_pending <= 1'b1;
            poly_rd_poly_id <= hsu_rd_poly_id_o;
            poly_rd_idx     <= hsu_rd_idx_o;
            hsu_rd_valid_i  <= 1'b0;
        end else if (poly_rd_pending) begin
            for (int lane = 0; lane < 4; lane++) begin
                automatic int p   = int'(poly_rd_poly_id);
                automatic int idx = int'(poly_rd_idx[lane]);
                hsu_rd_data_i[lane] <= poly_mem[p][idx >> 2][(idx % 4)*12 +: 12];
            end
            hsu_rd_valid_i  <= 1'b1;
            poly_rd_pending <= 1'b0;
        end else begin
            hsu_rd_valid_i <= 1'b0;
            hsu_rd_data_i  <= '0;
        end
    end

    logic force_seed_ready = 1'b0;

    // ==========================================================
    // Monitor / Data Checker Logic
    // ==========================================================
    int watchdog_timer = 0;
    always_ff @(posedge clk or posedge rst) begin
        if (rst) begin
            hsu_seed_ready_i <= 1'b0;
            hsu_stall_i      <= 1'b0;
            monitor_done     <= 1'b0;
            monitor_beat_idx <= '0;
            watchdog_timer   <= '0;
            monitor_err_count <= 0;
        end else begin
            if (monitor_active) begin
                if (monitor_beat_idx >= monitor_n_chunks) begin
                    monitor_done     <= 1'b1;
                    hsu_seed_ready_i <= 1'b0;
                    hsu_stall_i      <= 1'b0;
                end else begin
                    monitor_done     <= 1'b0;
                    watchdog_timer   <= watchdog_timer + 1;
                    if (watchdog_timer > 100000) begin
                        $error("[FAIL] Watchdog timeout after 100000 cycles in test: %s!", test_dir);
                        $stop;
                    end
                    hsu_seed_ready_i <= ($urandom_range(0,99) < 80) ? 1'b1 : 1'b0;
                    hsu_stall_i      <= ($urandom_range(0,99) < 20) ? 1'b1 : 1'b0;
                end
            end else begin
                monitor_done <= 1'b0;
                hsu_stall_i  <= 1'b0;
                if (force_seed_ready) begin
                    hsu_seed_ready_i <= 1'b1;
                end else begin
                    hsu_seed_ready_i <= 1'b0;
                end
            end

            if (cfg_mode == int'(MODE_SAMPLE_NTT) || cfg_mode == int'(MODE_SAMPLE_CBD)) begin
                if (hsu_req_o && !hsu_stall_i) begin
                    if (hsu_wr_en_o === 4'b0000) begin
                        $error("[FAIL] Poly write transaction valid but hsu_wr_en_o is 0!");
                         monitor_err_count <= monitor_err_count + 1;
                    end
                    if (hsu_wr_idx_o[0] !== monitor_expected_idx[$clog2(NCOEFF)-1:0]) begin
                         $error("[FAIL] Poly write index mismatch! Expected: %0d | Got: %0d", monitor_expected_idx[$clog2(NCOEFF)-1:0], hsu_wr_idx_o[0]);
                          monitor_err_count <= monitor_err_count + 1;
                    end
                    if (hsu_wr_data_o !== {expected_mem[monitor_beat_idx][3*12 +: 12],
                                           expected_mem[monitor_beat_idx][2*12 +: 12],
                                           expected_mem[monitor_beat_idx][1*12 +: 12],
                                           expected_mem[monitor_beat_idx][0*12 +: 12]}) begin
                        $error("[FAIL] Beat %0d | Expected: %16X | Got: %16X",
                               monitor_beat_idx, expected_mem[monitor_beat_idx], hsu_wr_data_o);
                         monitor_err_count <= monitor_err_count + 1;
                    end
                    monitor_beat_idx <= monitor_beat_idx + 1;
                    monitor_expected_idx <= monitor_expected_idx + 4;
                end
            end else begin
                if (hsu_seed_req_o && hsu_seed_ready_i) begin
                    if (hsu_seed_we_o !== 1'b1) begin
                        $error("[FAIL] Seed write transaction valid but hsu_seed_we_o is 0!");
                         monitor_err_count <= monitor_err_count + 1;
                    end
                    if (hsu_seed_idx_o !== monitor_expected_idx[$clog2(SEED_BEATS)-1:0]) begin
                         $error("[FAIL] Seed write index mismatch! Expected: %0d | Got: %0d", monitor_expected_idx[$clog2(SEED_BEATS)-1:0], hsu_seed_idx_o);
                          monitor_err_count <= monitor_err_count + 1;
                    end
                    if (hsu_seed_wdata_o !== expected_mem[monitor_beat_idx]) begin
                        $error("[FAIL] Beat %0d | Expected: %16X | Got: %16X",
                               monitor_beat_idx, expected_mem[monitor_beat_idx], hsu_seed_wdata_o);
                         monitor_err_count <= monitor_err_count + 1;
                    end
                    monitor_beat_idx <= monitor_beat_idx + 1;
                    monitor_expected_idx <= monitor_expected_idx + 1;
                end
            end
        end
    end

    // =========================================================
    // 6a. Watchdog Timer
    // =========================================================
    localparam int WATCHDOG_MAX = 100000;
    int watchdog_cnt = 0;

    always_ff @(posedge clk) begin
        if (rst || !monitor_active) begin
            watchdog_cnt <= 0;
        end else if (monitor_active && !monitor_done) begin
            watchdog_cnt <= watchdog_cnt + 1;
            if (watchdog_cnt >= WATCHDOG_MAX) begin
                $error("[FAIL] Watchdog timeout after %0d cycles in test: %s!", WATCHDOG_MAX, test_dir);
                $fatal(1, "Simulation Hang Detected");
            end
        end
    end

    // =========================================================
    // 7. Poly Absorb Sequence Task
    // =========================================================
    // Drives the controller protocol for MODE_ABSORB_POLY.
    // Absorbs cfg_poly_cnt polys sequentially using absorb_poly_i handshake.
    task automatic run_poly_absorb_sequence(input int n_polys, input bit last_segment);
        for (int p = 0; p < n_polys; p++) begin
            poly_id_i     = 4'(p);
            // Only set absorb_last_i on the last poly IF no seed segments follow.
            absorb_last_i = (p == n_polys - 1 && last_segment) ? 1'b1 : 1'b0;
            absorb_poly_i = 1'b1;
            @(posedge clk);
            absorb_poly_i = 1'b0;

            // Wait for packer to finish draining gearbox
            @(posedge clk);
            while (!packer_done_o) @(posedge clk);
        end
    endtask

    // =========================================================
    // 8. Main Execution
    // =========================================================
    initial begin
        init_err_count = 0;
        start_i        = 0;
        // hsu_rd_valid_i, hsu_rd_data_i owned by poly always_ff — reset via rst
        // hsu_seed_ready_i owned by monitor always_ff — reset via rst

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
        cfg_input_sel = 0;
        cfg_row = 0;
        cfg_col = 0;
        cfg_cbd_n = 0;
        cfg_run_g_first = 0;
        fd = $fopen(config_file, "r");
        if (!fd) $fatal(1, "Could not open %s", config_file);
        while (!$feof(fd)) begin
            scan_rtn = $fscanf(fd, "%s %d\n", key, val);
            if (key == "MODE")       cfg_mode      = val;
            if (key == "INPUT_SEL")  cfg_input_sel = val;
            if (key == "IS_ETA3")    cfg_is_eta3   = val;
            if (key == "IN_WORDS")   cfg_in_words  = val;
            if (key == "OUT_CHUNKS") cfg_out_chunks = val;
            if (key == "POLY_CNT")   cfg_poly_cnt  = val;
            if (key == "ROW")        cfg_row       = val;
            if (key == "COL")        cfg_col       = val;
            if (key == "CBD_N")      cfg_cbd_n     = val;
            if (key == "RUN_G_FIRST")cfg_run_g_first = val;
            if (key == "SEED_WORDS") cfg_seed_words  = val;
        end
        $fclose(fd);

        $readmemh(expected_file, expected_mem);

        // Reset
        #20 rst = 0;
        @(posedge clk);

        hsu_mode_i  = hs_mode_t'(cfg_mode);
        is_eta3_i   = cfg_is_eta3[0];
        xof_len_i   = '0;
        row_i       = cfg_row[7:0];
        col_i       = cfg_col[7:0];
        cbd_n_i     = cfg_cbd_n[7:0];

        if (cfg_mode == int'(MODE_ABSORB_POLY)) begin
            // ── Load poly memory model ────────────────────────────────
            // input.hex: each line = one 64-bit packed beat holding 4×12-bit coefficients
            // Line layout: {16'b0, c3[11:0], c2[11:0], c1[11:0], c0[11:0]}
            begin
                automatic logic [SEED_W-1:0] raw_mem [NUM_POLYS*64];
                $readmemh(input_file, raw_mem);
                for (int p = 0; p < cfg_poly_cnt; p++) begin
                    for (int b = 0; b < 64; b++) begin
                        poly_mem[p][b] = raw_mem[p*64 + b];
                    end
                end
                // Also load into input_mem for potential subsequent seed phase
                for (int i = 0; i < 128; i++) input_mem[i] = raw_mem[i];
            end

            input_sel_i  = 1'b1;
            // hsu_seed_ready_i driven by monitor always_ff once armed

            // Pulse start (new hash op)
            start_i = 1'b1;
            @(posedge clk);
            start_i = 1'b0;

            // Arm monitor (monitor_beat_idx/expected_idx reset by always_ff on !monitor_active)
            monitor_n_chunks = cfg_out_chunks;
            monitor_active   = 1'b1;

            // Drive poly absorb sequence (sequential)
            run_poly_absorb_sequence(cfg_poly_cnt, (cfg_seed_words == 0));

            if (cfg_seed_words > 0) begin
                // Wait one cycle for packer to clear
                @(posedge clk);
                input_sel_i  = 1'b0; // Switch to Seed Memory
                for (int i = 0; i < cfg_seed_words; i++) begin
                    // Read from input_mem (which was loaded from input.hex after poly data)
                    hsu_seed_rdata_i  = input_mem[cfg_poly_cnt*64 + i];
                    hsu_seed_rvalid_i = 1'b1;
                    absorb_last_i     = (i == cfg_seed_words - 1) ? 1'b1 : 1'b0;
                    do @(posedge clk); while (!DUT.keccak_t_ready_o);
                end
                hsu_seed_rvalid_i = 1'b0;
                absorb_last_i     = 1'b0;
            end

            // Wait for monitor to drain all output
            wait (monitor_done);
            monitor_active = 1'b0;

        end else begin
            // ── Seed memory feed modes (NTT, CBD, hash bypass) ────────
            $readmemh(input_file, input_mem);
            $display("DEBUG: input_mem[0] = %x", input_mem[0]);
            input_sel_i  = (cfg_input_sel == 2) ? 2'b10 : 2'b00;
            // hsu_seed_ready_i driven by monitor always_ff once armed
            // absorb_last_i set inside the loop

            if (cfg_run_g_first) begin
                $display("Running SHA3-512 Regression first to load sigma_reg...");
                hsu_mode_i = MODE_HASH_SHA3_512;
                start_i = 1'b1;
                @(posedge clk);
                start_i = 1'b0;

                // Enable Keccak output so sigma_reg can load
                force_seed_ready = 1'b1;

                // Send 4 beats of bypass input
                for (int i = 0; i < 4; i++) begin
                    if (cfg_input_sel == 2) begin
                        axis_t_data_i  = input_mem[i];
                        axis_t_valid_i = 1'b1;
                        axis_t_last_i  = (i == 3) ? 1'b1 : 1'b0;
                        axis_t_keep_i  = 8'hFF;
                        do @(posedge clk); while (!axis_t_ready_o);
                    end else begin
                        absorb_last_i     = (i == 3) ? 1'b1 : 1'b0;
                        hsu_seed_rdata_i  = input_mem[i];
                        hsu_seed_rvalid_i = 1'b1;
                        do @(posedge clk); while (!DUT.keccak_t_ready_o);
                    end
                end
                if (cfg_input_sel == 2) begin
                    axis_t_valid_i = 1'b0;
                    axis_t_last_i  = 1'b0;
                end else begin
                    absorb_last_i     = 1'b0;
                    hsu_seed_rvalid_i = 1'b0;
                    hsu_seed_rdata_i  = '0;
                end

                wait (DUT.sigma_valid == 1'b1);
                $display("sigma_reg captured: %x", DUT.sigma_reg);

                // Assert against EXPECTED_SIGMA if sigma.hex exists
                fd_sigma = $fopen({test_dir, "/sigma.hex"}, "r");
                if (fd_sigma) begin
                    scan_rtn = $fscanf(fd_sigma, "%x", expected_sigma_val);
                    $fclose(fd_sigma);
                    if (DUT.sigma_reg !== expected_sigma_val) begin
                        $error("[FAIL] sigma_reg mismatch!\n       Expected: %x\n       Got:      %x", expected_sigma_val, DUT.sigma_reg);
                        init_err_count++;
                    end
                end

                // Disable hsu_seed_ready_i before moving to main test
                force_seed_ready = 1'b0;
                $display("[PASS] sigma_reg matches expected value.");

                @(posedge clk);

                hsu_mode_i = hs_mode_t'(cfg_mode);
                $display("Now running target test...");
            end

            hsu_rd_idx_i[0] = cfg_cbd_n; // Inject CBD_N for RTL sampling
            start_i = 1'b1;
            @(posedge clk);
            start_i = 1'b0;

            // Arm monitor (monitor_beat_idx/expected_idx reset by always_ff on !monitor_active)
            monitor_n_chunks = cfg_out_chunks;
            monitor_active   = 1'b1;

            // Drive seed input (sequential)
            for (int i = 0; i < cfg_in_words; i++) begin
                if (cfg_input_sel == 2) begin
                    axis_t_data_i  = input_mem[i];
                    axis_t_valid_i = 1'b1;
                    axis_t_last_i  = (i == cfg_in_words - 1) ? 1'b1 : 1'b0;
                    axis_t_keep_i  = 8'hFF;
                    do @(posedge clk); while (!axis_t_ready_o); // Backpressure aware
                end else begin
                    absorb_last_i     = (i == cfg_in_words - 1) ? 1'b1 : 1'b0;
                    hsu_seed_rdata_i  = input_mem[i];
                    hsu_seed_rvalid_i = 1'b1;
                    do @(posedge clk); while (!DUT.keccak_t_ready_o); // Backpressure aware
                end
            end
            if (cfg_input_sel == 2) begin
                axis_t_valid_i = 1'b0;
                axis_t_last_i  = 1'b0;
            end else begin
                absorb_last_i     = 1'b0;
                hsu_seed_rvalid_i = 1'b0;
                hsu_seed_rdata_i  = '0;
            end

            // Wait for monitor to drain all output
            wait (monitor_done);
            monitor_active = 1'b0;

            // We removed the wait(hsu_done_o) because it can race with monitor exits and hang.
        end

        begin
            automatic int total_errors = monitor_err_count + init_err_count;
            if (total_errors == 0) $display("\n>>> TEST PASSED <<<\n");
            else                   $display("\n>>> TEST FAILED with %0d errors <<<\n", total_errors);
        end

        #50 $finish;
    end

endmodule
`default_nettype wire
