# Revise `hsu_done_o` — Sticky Done Signal for All Modes

## Problem

`hsu_done_o` currently only asserts for two modes:
- **MODE_SAMPLE_NTT** → `hsu_done_o = sample_ntt_done` (line 510)
- **MODE_SAMPLE_CBD** → `hsu_done_o = sample_cbd_done` (line 521)

All other modes (`SHA3_256`, `SHA3_512`, `SHAKE256`, `ABSORB_POLY`) default to `hsu_done_o = 1'b0` (line 484). No completion signal is ever generated.

Additionally, the current signal is **combinational** — it pulses for one cycle then drops. The requirement is for `hsu_done_o` to **latch high and stay high** until `start_i` pulses again.

## Current Done Signal Sources Per Mode

| Mode | Done Source | Current Status |
|------|-----------|----------------|
| `MODE_SAMPLE_NTT` | `sample_ntt_done` — combinational: `coeff_count >= 256 && packer_count == 0 && !s1_valid` | ✅ Pulses (not sticky) |
| `MODE_SAMPLE_CBD` | `sample_cbd_done` — combinational: `coeff_count >= 256` | ✅ Pulses (not sticky) |
| `MODE_HASH_SHA3_256` | Keccak output → Seed RAM write completes. Last beat indicated by `keccak_t_last_o && keccak_t_valid_o && keccak_t_ready_i` | ❌ Never asserts |
| `MODE_HASH_SHA3_512` | Same as SHA3-256 but also captures σ into `sigma_reg`. Last beat = `sha512_beat_cnt == 7` | ❌ Never asserts |
| `MODE_HASH_SHAKE256` | Same as hash bypass — last beat from Keccak | ❌ Never asserts |
| `MODE_ABSORB_POLY` | Keccak output → Seed RAM (32B digest). Same last-beat signal as hash bypass | ❌ Never asserts |

## Proposed Changes

### [MODIFY] [hash_sampler_unit.sv](file:///home/kiet/repos/hash-sampler-unit/rtl/hash_sampler_unit.sv)

**Strategy**: Add a registered `done_r` flag. Set it when any mode's completion condition fires. Clear it only on `start_i`. Drive `hsu_done_o` from `done_r`.

#### 1. Add `done_r` register (after line ~191, near internal state section)

```systemverilog
logic done_r;
```

#### 2. Add sequential logic for `done_r`

```systemverilog
always_ff @(posedge clk or posedge rst) begin
    if (rst)
        done_r <= 1'b0;
    else if (start_i)
        done_r <= 1'b0;
    else if (!done_r) begin
        case (hsu_mode_i)
            MODE_SAMPLE_NTT:    done_r <= sample_ntt_done;
            MODE_SAMPLE_CBD:    done_r <= sample_cbd_done;
            MODE_ABSORB_POLY,
            MODE_HASH_SHA3_256,
            MODE_HASH_SHA3_512,
            MODE_HASH_SHAKE256: done_r <= keccak_t_valid_o && keccak_t_last_o && keccak_t_ready_i;
            default:            done_r <= 1'b0;
        endcase
    end
end
```

> [!IMPORTANT]
> For SHA3-512, `keccak_t_last_o` fires on beat 7 (the final beat). Even though beats 4-7 are trapped in σ locally (not written to Seed RAM), the last Keccak output beat still has `keccak_t_last_o` asserted. The `keccak_t_ready_i` is `1'b1` (always accept) during those beats, so the condition fires correctly.

#### 3. Replace combinational `hsu_done_o` assignment

Remove the per-mode combinational `hsu_done_o` assignments (lines 484, 510, 521) and replace with:

```systemverilog
// In defaults section (line 484):
hsu_done_o = done_r;
```

And remove `hsu_done_o = sample_ntt_done;` from MODE_SAMPLE_NTT case and `hsu_done_o = sample_cbd_done;` from MODE_SAMPLE_CBD case.

> [!NOTE]
> This means `hsu_done_o` is no longer set inside the `case` block — it's always driven from the register. The register already captures the per-mode done conditions.

---

### [MODIFY] [hash_sampler_unit_tb.sv](file:///home/kiet/repos/hash-sampler-unit/tb/hash_sampler_unit_tb.sv)

#### Changes needed:

1. **Add `hsu_done_o` assertion after every test** — After `monitor_output` completes (all expected data verified), wait for `hsu_done_o` to go high. Add timeout guard.

2. **Verify sticky behavior** — After `hsu_done_o` goes high, wait a few cycles and verify it stays high.

3. **Verify clear on `start_i`** — Assert that `hsu_done_o` drops when `start_i` is pulsed.

Concrete changes:

```systemverilog
// After the fork-join (both code paths), add before the PASS/FAIL message:

// ── Verify hsu_done_o sticky behavior ─────────────────────────
begin
    automatic int timeout = 2000;
    while (!hsu_done_o && timeout > 0) begin
        @(posedge clk);
        timeout--;
    end
    if (timeout == 0) begin
        $error("[FAIL] hsu_done_o never asserted after test completion!");
        errors++;
    end else begin
        // Verify sticky: wait 5 cycles, check it's still high
        repeat (5) @(posedge clk);
        if (!hsu_done_o) begin
            $error("[FAIL] hsu_done_o dropped before start_i! Not sticky.");
            errors++;
        end
        // Verify clear: pulse start_i, check done drops
        start_i = 1'b1;
        @(posedge clk);
        start_i = 1'b0;
        @(posedge clk);
        if (hsu_done_o) begin
            $error("[FAIL] hsu_done_o did not clear after start_i!");
            errors++;
        end
    end
end
```

> [!IMPORTANT]
> The `wait(hsu_done_o)` was previously removed from the TB (line 406 comment) because it "can race with monitor exits and hang." The new implementation is different — `done_r` is a **registered sticky flag** that won't drop, so waiting for it after monitor completion is safe. We use a timeout guard as defense.

## Open Questions

> [!IMPORTANT]
> **MODE_ABSORB_POLY sequencing**: In multi-phase absorption (poly + seed), `done_r` should only assert after the *final* Keccak squeeze completes (i.e., the SHA3-256 digest is fully written to Seed RAM). The condition `keccak_t_valid_o && keccak_t_last_o && keccak_t_ready_i` fires when the last squeeze beat is consumed. Is this the correct completion point, or should done also wait for some external acknowledgment?

> [!NOTE]
> **No changes to sub-modules**: `sample_ntt.sv` and `sample_poly_cbd.sv` done signals remain combinational — the HSU's `done_r` register captures them. No changes needed in Keccak core either.

## Verification Plan

### Automated Tests
```bash
make run_hash_sampler_unit_tb SIM=verilator
```

All existing test vectors run through the same flow. The new done-checking code verifies:
1. `hsu_done_o` asserts after test completes (all modes)
2. `hsu_done_o` stays high (sticky check)
3. `hsu_done_o` clears on `start_i` pulse

### Manual Verification
- Inspect waveforms for any mode where done previously didn't assert
- Verify no simulation hangs from the new wait logic
