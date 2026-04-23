# HSU Minimal Fixes — Implementation Plan

Two mandatory fixes to `hash_sampler_unit.sv` enabling correct ML-KEM matrix generation and seed expansion.

---

## User Review Required

> [!IMPORTANT]
> **Byte endianness on 5th beat:** FIPS 203 specifies `ρ || j || i` (col then row). Plan assumes Keccak treats `tdata[7:0]` as byte 0 → `col_i` goes in `[7:0]`, `row_i` in `[15:8]`. Confirm this matches your Keccak core's byte-lane convention.

> [!IMPORTANT]
> **`MODE_SAMPLE_NTT` reuse vs new enum:** Plan gates 5th-beat injection on `hsu_mode_i == MODE_SAMPLE_NTT` directly. No new enum added now. The nice-to-have `MODE_SAMPLE_MATRIX_NTT` split deferred per fix plan §E. Confirm this is acceptable.

> [!WARNING]
> **σ beat count:** Plan assumes `G(d)` always outputs exactly 8 beats (SHA3-512 = 64 bytes = 8×8B). The `sigma_reg` capture uses a 3-bit counter (0–7) gated on `MODE_HASH_SHA3_512`. If Keccak can produce fewer/more beats in edge cases, this needs adjustment.

> [!WARNING]
> **CBD σ input:** `MODE_SAMPLE_CBD` currently reads seed from Seed RAM (beats 0–3 via `input_sel_i=0`). After this change, it will read from `sigma_reg` internally. Controller must **not** attempt to feed σ via Seed RAM or AXI anymore — just pulse `start_i` for CBD and HSU handles everything.

---

## Proposed Changes

### Component 1: RTL — hash_sampler_unit.sv

#### [MODIFY] [hash_sampler_unit.sv](file:///home/kiet/repos/hash-sampler-unit/rtl/hash_sampler_unit.sv)

**Change 1a: Add `row_i` / `col_i` / `cbd_n_i` Ports**

```diff
 input  wire seed_id_e                       seed_id_i,
+input  wire [7:0]                           row_i,
+input  wire [7:0]                           col_i,
+input  wire [7:0]                           cbd_n_i,
```

Add three 8-bit sideband inputs to module port list (after `seed_id_i`, line ~67).
- `row_i`/`col_i`: Matrix coordinates for 5th-beat injection (MODE_SAMPLE_NTT).
- `cbd_n_i`: PRF counter N for `PRF_η(σ, N) = SHAKE256(σ || N)` (MODE_SAMPLE_CBD).

---

**Change 1b: 5th-Beat Injection FSM**

Add new internal signals and a micro-FSM for coordinate injection:

```sv
// --- 5th-Beat Coordinate Injection (MODE_SAMPLE_NTT only) ---
logic       coord_beat_pending;    // High after 4th seed beat consumed, before 5th emitted
logic       coord_beat_fire;       // 5th beat accepted by Keccak
logic [7:0] row_lat, col_lat;     // Latched on start_i
```

- Latch `row_i`/`col_i` on `start_i` (sequential block).
- `coord_beat_pending` sets when `seed_beat_last && seed_rvalid_i && keccak_t_ready_o` **and** `hsu_mode_i == MODE_SAMPLE_NTT`.
- `coord_beat_fire` = `coord_beat_pending && keccak_t_ready_o`.
- On fire, clear `coord_beat_pending`.

**Modify `input_sel_i == 2'b00` (default) Keccak MUX** (lines 242–249):

```diff
 default: begin
     // Seed Memory path
-    keccak_t_data_i  = seed_rdata_i;
-    keccak_t_valid_i = seed_rvalid_i;
-    keccak_t_last_i  = seed_beat_last && absorb_last_i;
-    keccak_t_keep_i  = 8'hFF;
+    if (coord_beat_pending) begin
+        // Synthetic 5th beat: inject (col, row) coordinates
+        keccak_t_data_i  = {48'b0, row_lat, col_lat};
+        keccak_t_valid_i = 1'b1;
+        keccak_t_last_i  = 1'b1;             // Always last for matrix gen input
+        keccak_t_keep_i  = 8'h03;            // 2 valid bytes
+    end else begin
+        keccak_t_data_i  = seed_rdata_i;
+        keccak_t_valid_i = seed_rvalid_i;
+        keccak_t_last_i  = seed_beat_last && absorb_last_i
+                           && (hsu_mode_i != MODE_SAMPLE_NTT); // Suppress for NTT — 5th beat handles it
+        keccak_t_keep_i  = 8'hFF;
+    end
 end
```

Key behaviors:
- **`MODE_SAMPLE_NTT`**: `t_last` suppressed on beat 4; asserted on synthetic beat 5 with `keep=0x03`.
- **All other modes**: Unchanged — `t_last` on beat 4 as before (guarded by `hsu_mode_i != MODE_SAMPLE_NTT`).
- Handshake: 5th beat drives `t_valid=1` independently of `seed_rvalid_i`. FSM waits for `keccak_t_ready_o`.

---

**Change 1c: σ Register Capture (SHA3-512 Output Path)**

Add internal state:

```sv
// --- Local σ Register (64-byte SHA3-512 output, beats 4-7) ---
logic [255:0] sigma_reg;
logic [2:0]   sha512_beat_cnt;     // Counts 0..7 output beats
logic         sigma_valid;         // Set after all 8 beats captured
```

In `MODE_HASH_SHA3_512` output routing (lines 407–415):

```diff
 MODE_HASH_SHA3_256, MODE_HASH_SHA3_512, MODE_HASH_SHAKE256: begin
     if      (hsu_mode_i == MODE_HASH_SHA3_256) keccak_mode_sel = SHA3_256;
     else if (hsu_mode_i == MODE_HASH_SHA3_512) keccak_mode_sel = SHA3_512;
     else                                        keccak_mode_sel = SHAKE256;
-    seed_req_o       = keccak_t_valid_o;
-    seed_we_o        = 1'b1;
-    seed_wdata_o     = keccak_t_data_o;
-    keccak_t_ready_i = seed_ready_i;
+    if (hsu_mode_i == MODE_HASH_SHA3_512 && sha512_beat_cnt >= 3'd4) begin
+        // Beats 4-7: trap σ locally, do NOT write to Seed RAM
+        seed_req_o       = 1'b0;
+        seed_we_o        = 1'b0;
+        keccak_t_ready_i = 1'b1;   // Always accept (no backpressure needed)
+    end else begin
+        seed_req_o       = keccak_t_valid_o;
+        seed_we_o        = 1'b1;
+        seed_wdata_o     = keccak_t_data_o;
+        keccak_t_ready_i = seed_ready_i;
+    end
 end
```

Sequential logic for `sha512_beat_cnt` and `sigma_reg`:

```sv
always_ff @(posedge clk or posedge rst) begin
    if (rst) begin
        sha512_beat_cnt <= '0;
        sigma_reg       <= '0;
        sigma_valid     <= 1'b0;
    end else begin
        if (start_i) begin
            sha512_beat_cnt <= '0;
            sigma_valid     <= 1'b0;
        end else if (hsu_mode_i == MODE_HASH_SHA3_512
                     && keccak_t_valid_o && keccak_t_ready_i) begin
            sha512_beat_cnt <= sha512_beat_cnt + 1;
            if (sha512_beat_cnt >= 3'd4)
                sigma_reg[64*(sha512_beat_cnt - 3'd4) +: 64] <= keccak_t_data_o;
            if (sha512_beat_cnt == 3'd7)
                sigma_valid <= 1'b1;
        end
    end
end
```

---

**Change 1d: σ + N Feed for `MODE_SAMPLE_CBD`**

FIPS 203 requires `PRF_η(σ, N) = SHAKE256(σ || N)`. σ is 32 bytes (4 beats), N is 1 byte (5th beat). Total: **5 Keccak input beats**.

Add internal signals:

```sv
logic [2:0] sigma_feed_cnt;       // 0..4 beats: 0-3 = σ, 4 = N byte
logic       sigma_feeding;        // Active during CBD σ||N absorption
logic [7:0] cbd_n_lat;            // Latched N value
```

In the Keccak input MUX `default` case (seed path), add priority check:

```sv
if (sigma_feeding) begin
    if (sigma_feed_cnt <= 3'd3) begin
        // Beats 0-3: stream σ (256 bits = 4 × 64-bit)
        keccak_t_data_i  = sigma_reg[64*sigma_feed_cnt[1:0] +: 64];
        keccak_t_valid_i = 1'b1;
        keccak_t_last_i  = 1'b0;
        keccak_t_keep_i  = 8'hFF;
    end else begin
        // Beat 4: inject N byte, then t_last
        keccak_t_data_i  = {56'b0, cbd_n_lat};
        keccak_t_valid_i = 1'b1;
        keccak_t_last_i  = 1'b1;
        keccak_t_keep_i  = 8'h01;    // 1 valid byte
    end
end
```

Sequential:

```sv
always_ff @(posedge clk or posedge rst) begin
    if (rst) begin
        sigma_feed_cnt <= '0;
        sigma_feeding  <= 1'b0;
        cbd_n_lat      <= '0;
    end else begin
        if (start_i && hsu_mode_i == MODE_SAMPLE_CBD) begin
            sigma_feed_cnt <= '0;
            sigma_feeding  <= 1'b1;
            cbd_n_lat      <= cbd_n_i;
        end else if (sigma_feeding && keccak_t_ready_o) begin
            if (sigma_feed_cnt == 3'd4)
                sigma_feeding <= 1'b0;
            else
                sigma_feed_cnt <= sigma_feed_cnt + 1;
        end
    end
end
/* --- TB FIX: Backpressure Monitoring ---
Note: TB monitor must use keccak_t_ready_o to avoid dropping data during 5th-beat injection.
*/
```

---

### Component 2: RTL — hash_sample_pkg.sv

#### [MODIFY] [hash_sample_pkg.sv](file:///home/kiet/repos/hash-sampler-unit/rtl/hash_sample_pkg.sv)

No changes needed now. `hs_mode_t` already has all required modes. `MODE_SAMPLE_MATRIX_NTT` deferred per §E.

---

### Component 3: Testbench

#### [MODIFY] [hash_sampler_unit_tb.sv](file:///home/kiet/repos/hash-sampler-unit/tb/hash_sampler_unit_tb.sv)

1. **Add `row_i`, `col_i`, `cbd_n_i` signals** — connect to DUT.
2. **Backpressure-aware seed feeder** — wait for `keccak_t_ready_o` before driving next `seed_rvalid_i`.
3. **Add `RUN_G_FIRST` logic** — if set, TB runs a SHA3-512 cycle first, waits for `sigma_valid`, then starts the target test.
4. **Add `sigma_reg` capture monitoring** — after SHA3-512 tests, verify `DUT.sigma_reg` via hierarchical reference.
5. **Update Config Keys** — parse `ROW`, `COL`, `CBD_N`, and `RUN_G_FIRST` from config.txt.
6. **Input Trimming** — NTT Test A now feeds only 32-byte ρ (4 beats); coords `row_i`/`col_i` are driven via sideband.
---

### Component 4: Verification Scripts

#### Test Vector Workflow

Test vectors are **fully generated** by [`verif/mlkem-python/tests/Intermediate_hash_sampling.py`](file:///home/kiet/repos/hash-sampler-unit/verif/mlkem-python/tests/Intermediate_hash_sampling.py). Script writes directly to `verif/test_vectors.json`. No manual editing required.

| Test | Type | Notes |
|------|------|-------|
| A, A2 | NTT sampler | Random ρ, fixed coords |
| B, C | CBD sampler | η=2, η=3 |
| D | SHA3-512 bypass | Regression baseline for σ capture |
| E | SHAKE256 bypass | |
| F | ABSORB_POLY | Deterministic coeffs 0–255, hardcoded SHA3-256 digest |
| G | CBD-from-σ flow | Two-phase: `G(d)` → internal σ → CBD |

**Pipeline:** `make run_hash_sampler_unit_tb` triggers:
1. `verif/mlkem-python/tests/Intermediate_hash_sampling.py` → writes `verif/test_vectors.json`
2. `verif/generate_tb_files.py` → expands into `verif/test_vectors/*/`

`verif/test_vectors.json` is gitignored (generated artifact).

#### [MODIFY] [generate_tb_files.py](file:///home/kiet/repos/hash-sampler-unit/verif/generate_tb_files.py)

1. Add `ROW`, `COL`, `CBD_N`, and `RUN_G_FIRST` fields to config.txt generation.
2. Port Test A coordinate logic: `input_seed_hex` is 32-byte ρ only. `row`/`col` in config.
3. New test vectors handled upstream by `Intermediate_hash_sampling.py`. `generate_tb_files.py` only needs to handle new config keys.


---

## Summary of Signal Changes

| Signal | Direction | Width | Description |
|--------|-----------|-------|-------------|
| `row_i` | input | 8 | Matrix row coordinate (from controller) |
| `col_i` | input | 8 | Matrix col coordinate (from controller) |
| `cbd_n_i` | input | 8 | PRF counter N for CBD sampling (from controller) |
| `sigma_reg` | internal | 256 | Locally captured σ from G(d) beats 4-7 |
| `sigma_valid` | internal | 1 | σ fully captured flag |
| `coord_beat_pending` | internal | 1 | 5th beat injection pending |
| `sha512_beat_cnt` | internal | 3 | Tracks SHA3-512 output beats 0-7 |
| `sigma_feeding` | internal | 1 | CBD mode: streaming σ||N into Keccak |
| `sigma_feed_cnt` | internal | 3 | CBD mode: σ||N beat counter (0-4) |
| `cbd_n_lat` | internal | 8 | Latched N value for CBD feed |

## What Stays Unchanged

- `coeff_to_axis_packer.sv` — untouched
- `qrem_global_pkg.sv` — no enum changes now
- Seed RAM interface width/depth — unchanged
- One-poly-per-request architecture — preserved
- Controller sequencing ownership — preserved

---

## Verification Plan

### Automated Tests

1. **Compile check**: `make build` — no new syntax errors.
2. **SHA3-512 Regression (Test D)**: Verify 8-beat write to Seed RAM. Regression baseline for σ capture logic.
3. **NTT Matrix Test (Test A/A2)**:
   - Input: 32-byte ρ (4 beats).
   - Coords: driven via `row_i`/`col_i` ports.
   - Verify: Output matches `SHAKE128(ρ || col || row)`. Asymmetric test (Test A2) confirms coordinate endianness.
4. **σ Capture Test**: During SHA3-512, verify `seed_we_o` is low for beats 4-7. Wait for `sigma_valid` and check `DUT.sigma_reg`.
5. **CBD Flow Test (Test G)**:
   - Phase 1: Pulse `start_i` in `MODE_HASH_SHA3_512` with bypass input.
   - Phase 2: Pulse `start_i` in `MODE_SAMPLE_CBD`. Verify HSU streams internal σ||N (5 beats) and samplers fire.
6. **Backpressure Check**: Insert random stall on `keccak_t_ready_o` during 5th-beat injection; verify no data loss.

### Manual Verification

- Waveform inspection of 5th-beat handshake timing.
- Waveform inspection of `seed_we_o` suppression during σ capture beats 4-7.
- Confirm `hsu_done_o` asserts for both direct and flow-based CBD paths.
