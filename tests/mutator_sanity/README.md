# Mutator Sanity Tests

This directory contains sanity tests for validating protocol **mutators**.

## Usage

### 1. Enter the test directory
```bash
cd tests/mutator_sanity
```

### 2. Run the mutator sanity test
```bash
./run_mutator_sanity.sh <PROTO> <SEED_DIR>
```

**Arguments**
- `<PROTO>`: Protocol name (e.g., `mqtt`, `ftp`, `sip`)
- `<SEED_DIR>`: Path to the test seed directory

**Example**
```bash
./run_mutator_sanity.sh smtp ../PR_mr/mr_test_seeds/smtp_mr_test_seeds
```

### 3. Check results
The result summary is printed in the terminal:

- All mutators passed:
  ```
  [*] done. illegal=0 / total=18
  ```

- Some mutators failed:
  ```
  [*] done. illegal=6 / total=59
  ```

### 4. Inspect failed mutators
Detailed information for failed mutators is available in:
```text
tests/mutator_sanity/out_mutator_sanity_<PROTO>/
```
