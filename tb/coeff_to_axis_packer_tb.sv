`default_nettype none
`timescale 1ns / 1ps

import qrem_global_pkg::*;

module coeff_to_axis_packer_tb;

    localparam int CLK_PERIOD = 10;
    localparam int COEFF_W    = 12;
    localparam int NCOEFF     = 256;
    localparam int NUM_POLYS  = 1;
    localparam int DWIDTH     = 64;

    logic clk;
    logic rst;

    logic                              absorb_poly;
    logic [$clog2(NUM_POLYS)-1:0]      poly_id_i;
    logic                              is_last_i;

    logic                              rd_req_o;
    logic [$clog2(NUM_POLYS)-1:0]      rd_poly_id_o;
    logic [3:0][$clog2(NCOEFF)-1:0]    rd_idx_o;
    logic [3:0][COEFF_W-1:0]           rd_data_i;
    logic                              rd_valid_i;

    logic [DWIDTH-1:0]                 t_data_o;
    logic                              t_valid_o;
    logic                              t_last_o;
    logic [DWIDTH/8-1:0]               t_keep_o;
    logic                              t_ready_i;

    logic                              done_o;

    coeff_to_axis_packer #(
        .COEFF_W(COEFF_W),
        .NCOEFF(NCOEFF),
        .NUM_POLYS(NUM_POLYS),
        .DWIDTH(DWIDTH)
    ) DUT (
        .clk(clk),
        .rst(rst),
        .absorb_poly(absorb_poly),
        .poly_id_i(poly_id_i),
        .is_last_i(is_last_i),
        .rd_req_o(rd_req_o),
        .rd_poly_id_o(rd_poly_id_o),
        .rd_idx_o(rd_idx_o),
        .rd_data_i(rd_data_i),
        .rd_valid_i(rd_valid_i),
        .t_data_o(t_data_o),
        .t_valid_o(t_valid_o),
        .t_last_o(t_last_o),
        .t_keep_o(t_keep_o),
        .t_ready_i(t_ready_i),
        .done_o(done_o)
    );

    logic sim_done = 0;
    initial begin
        clk = 0;
        while (!sim_done) #(CLK_PERIOD/2) clk = ~clk;
    end

    // Watchdog
    int watchdog = 0;
    always_ff @(posedge clk or posedge rst) begin
        if (rst) watchdog <= 0;
        else begin
            watchdog <= watchdog + 1;
            if (watchdog > 50000) begin
                $error("[FAIL] Watchdog timeout!");
                $fatal(1, "Simulation Hang");
            end
        end
    end

    // Storage
    logic [COEFF_W-1:0] poly_mem [NCOEFF];
    logic [63:0] golden_queue [$];

    // Mock Reader Settings
    int rd_latency_min = 1;
    int rd_latency_max = 1;

    // Mock Sink Settings
    int sink_ready_prob = 100; // 0 to 100

    // Mock Reader (Poly Memory)
    int rd_delay_cnt = 0;
    logic rd_active = 0;
    logic [3:0][COEFF_W-1:0] cur_rd_data;

    always_ff @(posedge clk or posedge rst) begin
        if (rst) begin
            rd_valid_i <= 0;
            rd_active <= 0;
            rd_delay_cnt <= 0;
        end else begin
            rd_valid_i <= 0;
            if (rd_req_o && !rd_active) begin
                rd_active <= 1;
                rd_delay_cnt <= $urandom_range(rd_latency_min, rd_latency_max);
                cur_rd_data[0] <= poly_mem[rd_idx_o[0]];
                cur_rd_data[1] <= poly_mem[rd_idx_o[1]];
                cur_rd_data[2] <= poly_mem[rd_idx_o[2]];
                cur_rd_data[3] <= poly_mem[rd_idx_o[3]];
            end else if (rd_active) begin
                if (rd_delay_cnt > 1) begin
                    rd_delay_cnt <= rd_delay_cnt - 1;
                end else begin
                    rd_valid_i <= 1;
                    rd_data_i <= cur_rd_data;
                    rd_active <= 0;
                end
            end
        end
    end

    // Mock Sink
    logic is_last_lat_tb;
    always_ff @(posedge clk) begin
        if (absorb_poly) is_last_lat_tb <= is_last_i;
    end

    always_ff @(posedge clk or posedge rst) begin
        if (rst) begin
            t_ready_i <= 0;
        end else begin
            t_ready_i <= ($urandom_range(0, 99) < sink_ready_prob) ? 1'b1 : 1'b0;

            if (t_valid_o && t_ready_i) begin
                if (golden_queue.size() == 0) begin
                    $error("[FAIL] Sink received unexpected data: %x", t_data_o);
                end else begin
                    automatic logic [63:0] exp = golden_queue.pop_front();
                    if (t_data_o !== exp) begin
                        $error("[FAIL] Mismatch! Expected: %x | Got: %x", exp, t_data_o);
                    end
                    if (t_keep_o !== 8'hFF) begin
                        $error("[FAIL] Expected keep 0xFF, got %x", t_keep_o);
                    end
                    if (golden_queue.size() == 0 && is_last_lat_tb && t_last_o !== 1'b1) begin
                        $error("[FAIL] t_last_o not asserted on final beat!");
                    end
                    if (golden_queue.size() == 0 && !is_last_lat_tb && t_last_o === 1'b1) begin
                        $error("[FAIL] t_last_o asserted incorrectly (is_last_i was 0)!");
                    end
                    if (golden_queue.size() > 0 && t_last_o === 1'b1) begin
                        $error("[FAIL] t_last_o asserted prematurely!");
                    end
                end
            end
        end
    end

    // Data Generator Task
    task automatic setup_poly();
        golden_queue.delete();
        for (int i=0; i<NCOEFF; i++) begin
            poly_mem[i] = COEFF_W'($urandom_range(0, (1<<COEFF_W)-1));
        end
        // Pack into 64-bit words (FIPS 203 ByteEncode12 logic)
        for (int b=0; b<48; b++) begin // 48 beats = 384 bytes
            automatic logic [63:0] beat = 0;
            for (int j=0; j<8; j++) begin // 8 bytes per beat
                automatic int byte_idx = b*8 + j;
                automatic int i = byte_idx / 3;
                automatic logic [7:0] byte_val;
                if (byte_idx % 3 == 0) begin
                    byte_val = poly_mem[2*i][7:0];
                end else if (byte_idx % 3 == 1) begin
                    byte_val = {poly_mem[2*i+1][3:0], poly_mem[2*i][11:8]};
                end else begin
                    byte_val = poly_mem[2*i+1][11:4];
                end
                beat[j*8 +: 8] = byte_val;
            end
            golden_queue.push_back(beat);
        end
    endtask

    // Main sequence
    initial begin
        rst = 1;
        absorb_poly = 0;
        poly_id_i = 0;
        is_last_i = 0;
        #20 rst = 0;
        @(posedge clk);

        $display("=============================");
        $display("=== Test 1: Ideal =========");
        $display("=============================");
        rd_latency_min = 1; rd_latency_max = 1;
        sink_ready_prob = 100;
        setup_poly();
        absorb_poly = 1; is_last_i = 1;
        @(posedge clk); absorb_poly = 0;
        while (!done_o) @(posedge clk);
        @(posedge clk);
        if (golden_queue.size() > 0) $error("Test 1: Queue not empty!");
        $display("Test 1 Passed");

        $display("=============================");
        $display("=== Test 2: Backpressure ===");
        $display("=============================");
        rd_latency_min = 1; rd_latency_max = 1;
        sink_ready_prob = 50; // 50% stall chance
        setup_poly();
        absorb_poly = 1; is_last_i = 1;
        @(posedge clk); absorb_poly = 0;
        while (!done_o) @(posedge clk);
        @(posedge clk);
        if (golden_queue.size() > 0) $error("Test 2: Queue not empty!");
        $display("Test 2 Passed");

        $display("=============================");
        $display("=== Test 3: Reader Latency =");
        $display("=============================");
        rd_latency_min = 2; rd_latency_max = 5; // slow memory
        sink_ready_prob = 100;
        setup_poly();
        absorb_poly = 1; is_last_i = 1;
        @(posedge clk); absorb_poly = 0;
        while (!done_o) @(posedge clk);
        @(posedge clk);
        if (golden_queue.size() > 0) $error("Test 3: Queue not empty!");
        $display("Test 3 Passed");

        $display("=============================");
        $display("=== Test 4: Back-to-Back ===");
        $display("=============================");
        rd_latency_min = 1; rd_latency_max = 2;
        sink_ready_prob = 80;
        for (int k=0; k<3; k++) begin
            setup_poly();
            absorb_poly = 1; is_last_i = (k==2);
            @(posedge clk); absorb_poly = 0;
            while (!done_o) @(posedge clk);
            @(posedge clk);
            if (golden_queue.size() > 0) $error("Test 4.%0d: Queue not empty!", k);
        end
        $display("Test 4 Passed");

        $display(">>> TEST PASSED <<<");
        sim_done = 1;
    end

endmodule

`default_nettype wire
