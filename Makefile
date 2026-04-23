# 1. Import the central build system
include build-tools/common.mk

# =========================================================
# Test Vector Generation Logic
# =========================================================
VECTOR_SCRIPT := verif/mlkem-python/tests/Intermediate_hash_sampling.py
VECTOR_PROC   := verif/generate_tb_files.py
VECTOR_JSON   := verif/test_vectors.json
VECTOR_STAMP  := verif/test_vectors/.generated_stamp

# Run Python reference script first (generates verif/test_vectors.json),
# then generate_tb_files.py to expand it into per-test directories.
$(VECTOR_STAMP): $(VECTOR_SCRIPT) $(VECTOR_PROC)
	@echo "=== Setting up Python venv for vector generation ==="
	python3 -m venv verif/.venv
	verif/.venv/bin/pip install -q -r verif/mlkem-python/requirements.txt
	@echo "=== Generating reference vectors ==="
	cd verif/mlkem-python && $(CURDIR)/verif/.venv/bin/python3 tests/Intermediate_hash_sampling.py
	@echo "=== Expanding test vector directories ==="
	cd verif && $(CURDIR)/verif/.venv/bin/python3 generate_tb_files.py
	@mkdir -p verif/test_vectors
	touch $(VECTOR_STAMP)
# 3. Local Cleanup
EXTRA_CLEAN = verif/test_vectors/ $(VECTOR_JSON) test_vectors/

# =========================================================
# Hash Sampler Unit Override Target
# =========================================================
# Notice the dependency on $(VECTOR_STAMP) added here!
run_hash_sampler_unit_tb: build.f $(VECTOR_STAMP)
	@echo "=== Running hash_sampler_unit_tb with custom vector loop ($(SIM)) ==="
ifeq ($(SIM), verilator)
	@echo "Compiling Verilator binary once..."
	verilator $(VERILATOR_FLAGS) $(INCDIRS) --top-module hash_sampler_unit_tb -f build.f tb/hash_sampler_unit_tb.sv

	@# We use shell wildcard here so it evaluates AFTER the Python script creates the folders
	@for dir in verif/test_vectors/*/; do \
		test_name=$$(basename "$${dir%/}"); \
		echo ""; \
		echo "--- Running Verilator on $$test_name ---"; \
		./obj_dir/Vhash_sampler_unit_tb +TEST_DIR=$$dir 2>&1 | tee hash_sampler_unit_tb_$$test_name.log; \
	done
else
	@echo "Compiling ModelSim work library once..."
	vlib work
	vlog -work work -sv $(INCDIRS) -f build.f tb/hash_sampler_unit_tb.sv

	@# We use shell wildcard here so it evaluates AFTER the Python script creates the folders
	@for dir in verif/test_vectors/*/; do \
		test_name=$$(basename "$${dir%/}"); \
		echo ""; \
		echo "--- Running ModelSim on $$test_name ---"; \
		vsim -c -do "run -all; quit" work.hash_sampler_unit_tb +TEST_DIR=$$dir -l hash_sampler_unit_tb_$$test_name.log; \
	done
endif
