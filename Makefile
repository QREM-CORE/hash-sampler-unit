# =========================================================
# Dual-Simulator Makefile (ModelSim + Verilator)
# =========================================================

# --- PATH & FILE DEFINITIONS ---
# Define include directories here for cleaner commands
INCDIRS = +incdir+rtl

# 1. Dynamically read lines from rtl.f (ignoring comments and empty lines)
RAW_RTL_LINES = $(shell grep -v '^\#' rtl.f | grep -v '^$$')

# 2. Expand wildcards (like rtl/*.sv) into a space-separated list of files
# This ensures the simulator receives a list of real files, not a "*" string.
RTL_FILES = $(wildcard $(RAW_RTL_LINES))

# 3. Automatically discover all testbenches in tb/
TESTBENCHES = $(patsubst tb/%.sv,%,$(wildcard tb/*_tb.sv))

# Simulator selection (default to vsim)
SIM ?= vsim

# --- VERILATOR FLAGS ---
# --binary: Build an executable (Verilator v5.0+)
# -j 0: Use all available CPU cores for compilation
# --timing: Support #delay statements
# --trace: Enable VCD generation
VERILATOR_FLAGS = --binary -j 0 --timing --trace -Wall -Wno-fatal

# =====================
# STANDARD TARGETS
# =====================

all: run_all

.PHONY: run_all clean run_%

# Loop through and run every testbench found
run_all:
	@for tb in $(TESTBENCHES); do \
		$(MAKE) run_$$tb SIM=$(SIM); \
	done

# Rule for each specific testbench
run_%:
	@echo "=== Running $* with $(SIM) ==="
ifeq ($(SIM), verilator)
	# --- VERILATOR FLOW ---
	# We pass $(RTL_FILES) (the expanded list) instead of -f rtl.f
	verilator $(VERILATOR_FLAGS) $(INCDIRS) --top-module $* $(RTL_FILES) tb/$*.sv
	bash -c "set -o pipefail; ./obj_dir/V$* 2>&1 | tee $*.log"
else
	# --- MODELSIM FLOW ---
	vlib work
	# We pass $(RTL_FILES) (the expanded list) instead of -f rtl.f
	vlog -work work -sv $(INCDIRS) $(RTL_FILES) tb/$*.sv

	@echo 'vcd file "$*.vcd"' > run_$*.macro
	@echo 'vcd add -r /$*/*' >> run_$*.macro
	@echo 'run -all' >> run_$*.macro
	@echo 'quit' >> run_$*.macro
	vsim -c -do run_$*.macro work.$* -l $*.log
	@rm -f run_$*.macro
endif

# =====================
# CLEANUP
# =====================
clean:
	rm -rf work *.vcd transcript vsim.wlf run_*.macro *.log obj_dir
