// -----------------------------------------------------------------------------
// Module      : bypass_serializer_tb
// Author(s)   : Kiet Le
// Description : Self-checking testbench for the 256-to-64-bit AXI downsizer.
//               Verifies protocol compliance, 0-bubble streaming, and the
//               Keep-Aware dynamic truncation logic.
// -----------------------------------------------------------------------------

import hash_sample_pkg::*;

module bypass_serializer_tb;

    // =========================================================================
    // Parameters & Signals
    // =========================================================================
    localparam int CLK_PERIOD = 10;

    logic        clk;
    logic        rst;

    // AXI4-Stream Sink (from Keccak)
    logic [255:0] t_data_i;
    logic         t_valid_i;
    logic         t_last_i;
    logic [31:0]  t_keep_i;
    logic         t_ready_o;

    // AXI4-Stream Source (to Downstream)
    logic [HSU_OUT_DWIDTH-1:0]     t_data_o;
    logic                          t_valid_o;
    logic                          t_last_o;
    logic [HSU_OUT_KEEP_WIDTH-1:0] t_keep_o;
    logic                          t_ready_i;

    // =========================================================================
    // DUT Instantiation
    // =========================================================================
    bypass_serializer dut (
        .clk        (clk),
        .rst        (rst),
        .t_data_i   (t_data_i),
        .t_valid_i  (t_valid_i),
        .t_last_i   (t_last_i),
        .t_keep_i   (t_keep_i),
        .t_ready_o  (t_ready_o),
        .t_data_o   (t_data_o),
        .t_valid_o  (t_valid_o),
        .t_last_o   (t_last_o),
        .t_keep_o   (t_keep_o),
        .t_ready_i  (t_ready_i)
    );

    // =========================================================================
    // Clock Generation
    // =========================================================================
    initial clk = 0;
    always #(CLK_PERIOD/2) clk = ~clk;

    // =========================================================================
    // Golden Model & Scoreboard
    // =========================================================================
    typedef struct {
        logic [63:0] data;
        logic [7:0]  keep;
        logic        last;
    } expected_beat_t;

    expected_beat_t expected_q[$];

    int unsigned errors_detected = 0;
    int unsigned beats_checked   = 0;

    // Task: Compute expected 64-bit chunks based on Keep-Aware logic
    task automatic push_expected(
        input logic [255:0] d,
        input logic [31:0]  k,
        input logic         l
    );
        int num_chunks;

        if (k[31:24] != 8'd0)      num_chunks = 4;
        else if (k[23:16] != 8'd0) num_chunks = 3;
        else if (k[15:8] != 8'd0)  num_chunks = 2;
        else                       num_chunks = 1;

        for (int i = 0; i < num_chunks; i++) begin
            expected_beat_t beat;
            beat.data = d[i*64 +: 64];
            beat.keep = k[i*8 +: 8];
            // t_last is only asserted on the final valid chunk of the block
            beat.last = (i == num_chunks - 1) ? l : 1'b0;
            expected_q.push_back(beat);
        end
    endtask

    // Monitor: Automatically pop and check when valid and ready are high
    always_ff @(posedge clk) begin
        if (!rst && t_valid_o && t_ready_i) begin
            if (expected_q.size() == 0) begin
                $error("[Scoreboard] Unexpected output beat detected! D=%h", t_data_o);
                errors_detected++;
            end else begin
                automatic expected_beat_t exp = expected_q.pop_front();

                if (t_data_o !== exp.data || t_keep_o !== exp.keep || t_last_o !== exp.last) begin
                    $error("[Scoreboard] Mismatch! \n  Expected: D=%h K=%h L=%b \n  Got     : D=%h K=%h L=%b",
                           exp.data, exp.keep, exp.last, t_data_o, t_keep_o, t_last_o);
                    errors_detected++;
                end
                beats_checked++;
            end
        end
    end

    // =========================================================================
    // Driver Tasks
    // =========================================================================
    task automatic drive_beat(
        input logic [255:0] d,
        input logic [31:0]  k,
        input logic         l
    );
        t_data_i  <= d;
        t_keep_i  <= k;
        t_last_i  <= l;
        t_valid_i <= 1'b1;

        push_expected(d, k, l);

        // Wait for AXI handshake
        @(posedge clk);
        while (!t_ready_o) @(posedge clk);

        t_valid_i <= 1'b0;
        t_last_i  <= 1'b0;
    endtask

    // Generate random 256-bit data
    function automatic logic [255:0] get_rand_256();
        return {$urandom, $urandom, $urandom, $urandom,
                $urandom, $urandom, $urandom, $urandom};
    endfunction

    // =========================================================================
    // Main Test Sequence
    // =========================================================================
    initial begin
        $display("=========================================================");
        $display(" Starting bypass_serializer Testbench");
        $display("=========================================================");

        // Initialize
        rst       = 1'b1;
        t_data_i  = '0;
        t_valid_i = 1'b0;
        t_last_i  = 1'b0;
        t_keep_i  = '0;
        t_ready_i = 1'b0;

        repeat (5) @(posedge clk);
        rst = 1'b0;
        repeat (2) @(posedge clk);

        // ---------------------------------------------------------
        $display("[TEST 1] Full-Width Clean Streaming (10 blocks)");
        t_ready_i = 1'b1;
        for (int i = 0; i < 10; i++) begin
            drive_beat(get_rand_256(), 32'hFFFF_FFFF, (i == 9));
        end
        while (expected_q.size() > 0) @(posedge clk);

        // ---------------------------------------------------------
        $display("[TEST 2] Keep-Aware Ragged Edge (Dynamic Truncation)");
        t_ready_i = 1'b1;
        drive_beat(get_rand_256(), 32'h0000_00FF, 1'b0); // 1 chunk
        drive_beat(get_rand_256(), 32'h0000_FFFF, 1'b0); // 2 chunks
        drive_beat(get_rand_256(), 32'h00FF_FFFF, 1'b0); // 3 chunks
        drive_beat(get_rand_256(), 32'hFFFF_FFFF, 1'b1); // 4 chunks
        while (expected_q.size() > 0) @(posedge clk);

        // ---------------------------------------------------------
        $display("[TEST 3] Downstream Backpressure (Random t_ready_i)");
        fork
            // Thread 1: Randomize downstream ready (50% stall rate)
            begin
                for (int i = 0; i < 100; i++) begin
                    @(posedge clk);
                    t_ready_i <= ($urandom % 2 == 0);
                end
                t_ready_i <= 1'b1; // Ensure it finishes
            end
            // Thread 2: Drive data
            begin
                for (int i = 0; i < 10; i++) begin
                    drive_beat(get_rand_256(), 32'hFFFF_FFFF, (i == 9));
                end
            end
        join
        while (expected_q.size() > 0) @(posedge clk);

        // ---------------------------------------------------------
        $display("[TEST 4] Upstream Starvation (Random t_valid_i delays)");
        t_ready_i = 1'b1;
        for (int i = 0; i < 5; i++) begin
            int delay;                        // 1. Declare
            delay = $urandom_range(1, 5);     // 2. Assign
            repeat(delay) @(posedge clk);
            drive_beat(get_rand_256(), 32'hFFFF_FFFF, (i == 4));
        end
        while (expected_q.size() > 0) @(posedge clk);

        // ---------------------------------------------------------
        $display("[TEST 5] t_last Synchronization on a Ragged Block");
        t_ready_i = 1'b1;
        // Output should have exactly 2 beats, and the 2nd beat must have t_last=1
        drive_beat(get_rand_256(), 32'h0000_FFFF, 1'b1);
        while (expected_q.size() > 0) @(posedge clk);

        // =========================================================
        // Final Verdict
        // =========================================================
        repeat(5) @(posedge clk);

        $display("=========================================================");
        if (errors_detected == 0 && beats_checked > 0)
            $display(" PASS: All %0d expected beats verified perfectly.", beats_checked);
        else
            $display(" FAIL: %0d errors detected across %0d beats.", errors_detected, beats_checked);
        $display("=========================================================");
        $finish;
    end

    // =========================================================================
    // Protocol Assertions (Concurrent)
    // =========================================================================
    // synthesis translate_off

    // 1. Data/Keep/Last must remain stable if valid is high but downstream is stalled
    assert property (@(posedge clk) disable iff (rst)
        (t_valid_o && !t_ready_i) |=>
        ($stable(t_data_o) && $stable(t_keep_o) && $stable(t_last_o)))
        else $error("SVA VIOLATION: Output payload changed while stalled.");

    // 2. Valid cannot drop until the downstream module accepts the data
    assert property (@(posedge clk) disable iff (rst)
        (t_valid_o && !t_ready_i) |=> t_valid_o)
        else $error("SVA VIOLATION: t_valid_o dropped without handshake.");

    // synthesis translate_on

endmodule
