# Parser and Reassembler Metamorphic Tests

This directory contains metamorphic tests for validating the **consistency between protocol parsers and reassemblers**.

## Usage

### 1. Enter the test directory
```bash
cd tests/PR_mr
```

### 2. Run the metamorphic test
```bash
./run.sh <PROTO> <SEED_DIR>
```

**Arguments**
- `<PROTO>`: Protocol name (e.g., `mqtt`, `ftp`, `sip`)
- `<SEED_DIR>`: Directory containing metamorphic test seeds

**Example**
```bash
./run.sh mqtt mr_test_seeds/mqtt_mr_test_seeds
```

### 3. Output
- All test results are written to the `out/` directory.
