/*
 * Module   : bypass_serializer
 * Author   : Kiet Le
 * Target   : FIPS 203 (ML-KEM / Kyber) Hardware Accelerator
 *
 * Description:
 * AXI4-Stream 256-to-64-bit downsizer for pure hashing bypass.
 * * Features:
 * - Registered Payload: Breaks long combinational paths for high Fmax.
 * - 0-Bubble Streaming: Accepts new 256b words instantly upon finishing the last.
 * - Keep-Aware Truncation: Dynamically skips empty beats for ragged payloads.
 *
 * Usage Notes:
 * - `t_keep_i` MUST be accurate (e.g., 32'hFFFF_FFFF for a full valid word).
 * - `t_valid_i` should only be asserted during pure hash modes.
 *
 * Keep-Byte Mapping (256b -> 64b):
 * Chunk 0: data[63:0]    | keep[7:0]
 * Chunk 1: data[127:64]  | keep[15:8]
 * Chunk 2: data[191:128] | keep[23:16]
 * Chunk 3: data[255:192] | keep[31:24]
 */

import hash_sample_pkg::*;

module bypass_serializer (
    input  wire                              clk,
    input  wire                              rst,

    // AXI4-Stream Sink
    input  wire  [255:0]                     t_data_i,
    input  wire                              t_valid_i,
    input  wire                              t_last_i,
    input  wire  [31:0]                      t_keep_i,
    output logic                             t_ready_o,

    // AXI4-Stream Source
    output logic [HSU_OUT_DWIDTH-1:0]        t_data_o,
    output logic                             t_valid_o,
    output logic                             t_last_o,
    output logic [HSU_OUT_KEEP_WIDTH-1:0]    t_keep_o,
    input  wire                              t_ready_i
);

    // ==========================================================
    // Internal State & Registered Payload
    // ==========================================================
    logic [255:0] data_reg;
    logic [31:0]  keep_reg;
    logic         last_reg;

    logic [1:0]   cnt;
    logic         active;
    logic [1:0]   final_cnt;

    // ==========================================================
    // Combinational Logic: Dynamic End-of-Word Calculation
    // ==========================================================
    // Determine the last valid 64-bit chunk based on the latched t_keep
    always_comb begin
        if (keep_reg[31:24] != 8'd0) begin
            final_cnt = 2'd3;
        end else if (keep_reg[23:16] != 8'd0) begin
            final_cnt = 2'd2;
        end else if (keep_reg[15:8] != 8'd0) begin
            final_cnt = 2'd1;
        end else begin
            final_cnt = 2'd0;
        end
    end

    // We are ready to accept new data if we are IDLE (!active)
    // OR if we are on the dynamically calculated last chunk and downstream accepts.
    assign t_ready_o = !active || (active && (cnt == final_cnt) && t_ready_i);

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
                if (cnt == final_cnt) begin
                    active <= 1'b0; // Done with this block early!
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

        // Only assert t_last on the final valid chunk AND if the original block had t_last
        t_last_o  = active && (cnt == final_cnt) && last_reg;

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
