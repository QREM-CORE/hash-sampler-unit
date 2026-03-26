/*
 * Module Name: bypass_serializer
 * Author(s): Kiet Le
 * Target: FIPS 203 (ML-KEM / Kyber) Hardware Accelerator
 *
 * Description:
 * A 256-to-64-bit AXI downsizer used for serializing 256-bit
 * keccak data to 64-bit data for output (i.e., pure hashing operations).
 * Fully registered payload for high Fmax, supports 0-bubble back-to-back streaming.
 */

import hash_sample_pkg::*;

module bypass_serializer (
    input  wire                            clk,
    input  wire                            rst,

    // AXI4-Stream Sink
    input  wire  [255:0]                    t_data_i,
    input  wire                             t_valid_i,
    input  wire                             t_last_i,
    input  wire  [31:0]                     t_keep_i,
    output logic                            t_ready_o,

    // AXI4-Stream Source
    output logic [HSU_OUT_DWIDTH-1:0]       t_data_o,
    output logic                            t_valid_o,
    output logic                            t_last_o,
    output logic [HSU_OUT_KEEP_WIDTH-1:0]   t_keep_o,
    input  wire                             t_ready_i
);

    // ==========================================================
    // Internal State & Registered Payload
    // ==========================================================
    logic [255:0] data_reg;
    logic [31:0]  keep_reg;
    logic         last_reg;

    logic [1:0]   cnt;
    logic         active;

    // We are ready to accept new data if we are IDLE (!active)
    // OR if we are on the very last chunk (cnt==3) and the downstream is accepting it.
    assign t_ready_o = !active || (active && (cnt == 2'd3) && t_ready_i);

    // ==========================================================
    // Sequential Logic: Control and Latching
    // ==========================================================
    always_ff @(posedge clk or posedge rst) begin
        if (rst) begin
            active <= 1'b0;
            cnt    <= 2'd0;
        end else begin
            // 1. Accept new data (Takes priority for back-to-back streaming)
            if (t_ready_o && t_valid_i) begin
                active   <= 1'b1;
                cnt      <= 2'd0;
                data_reg <= t_data_i;
                keep_reg <= t_keep_i;
                last_reg <= t_last_i;
            end
            // 2. Advance the counter if active and downstream accepts
            else if (active && t_ready_i) begin
                if (cnt == 2'd3) begin
                    active <= 1'b0; // Done with this block
                end else begin
                    cnt <= cnt + 2'd1;
                end
            end
        end
    end

    // ==========================================================
    // Combinational Logic: MUX & AXI Outputs
    // ==========================================================
    always_comb begin
        // Default assignments
        t_data_o = '0;
        t_keep_o = '0;

        // Output is valid as long as we have active registered data
        t_valid_o = active;

        // Only assert t_last on the 4th beat AND if the original block had t_last
        t_last_o  = active && (cnt == 2'd3) && last_reg;

        // 4-to-1 MUX out of the latched register
        case (cnt)
            2'd0: begin
                t_data_o = data_reg[63:0];
                t_keep_o = keep_reg[7:0];
            end
            2'd1: begin
                t_data_o = data_reg[127:64];
                t_keep_o = keep_reg[15:8];
            end
            2'd2: begin
                t_data_o = data_reg[191:128];
                t_keep_o = keep_reg[23:16];
            end
            2'd3: begin
                t_data_o = data_reg[255:192];
                t_keep_o = keep_reg[31:24];
            end
        endcase
    end

endmodule
