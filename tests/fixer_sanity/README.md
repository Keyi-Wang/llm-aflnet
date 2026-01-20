# Fixer Sanity Tests (LLM-Assisted)

This directory validates protocol **fixers**. Test cases are generated with LLMs using protocol constraints.

## Usage

### 1. Enter the test directory
```bash
cd tests/fixer_sanity
```

### 2. Extract fixers into a registry
```bash
python3 gen_fixer_registry.py \
  --fixers /path/to/<PROTO>_fixers.c \
  --out   /path/to/<PROTO>_fixer_registry.c \
  --pkt-type <proto_packet_t>
```

**Example (DTLS)**
```bash
python3 gen_fixer_registry.py \
  --fixers ../../llm/dtls/dtls_fixers.c \
  --out   ./dtls_fixer_registry.c \
  --pkt-type dtls_packet_t
```

### 3. Generate `<PROTO>_fixer_sanity_tests.c` with an LLM
Provide these inputs to the LLM:
- `<PROTO>_constraints.txt` (natural-language constraints)
- `<PROTO>_fixer_registry.c` (generated registry)
- `mqtt_fixer_sanity_tests.c` (example style/structure)

Use this prompt:
```text
You are generating C test code for validating protocol fixers.

Task:
Generate a single C source file:
  <PROTO>_fixer_sanity_tests.c

Inputs:
1) <PROTO>_constraints.txt: a constraint file describing protocol constraints in natural language.
2) <PROTO>_fixer_registry.c: lists all implemented fixers.
3) mqtt_fixer_sanity_tests.c: example of structure and style.

Requirements:
- Follow the structure and coding style of mqtt_fixer_sanity_tests.c.
- Iterate over all fixers defined in <PROTO>_fixer_registry.c.
- For each fixer:
  - Construct a valid <PROTO> packet/state.
  - Intentionally violate one or more constraints from the constraint file.
  - Invoke the fixer.
  - Check whether constraints are restored.
- Record any fixer that fails into an output list (e.g., illegal_fixers.txt).
- The code must be self-contained, written in C (C11), and compilable.

Output:
- Output ONLY the complete C source code of <PROTO>_fixer_sanity_tests.c.
- No explanations or extra text.
```

### 4. Run the fixer sanity test
```bash
./run_fixer_sanity.sh <PROTO>
```

**Example**
```bash
./run_fixer_sanity.sh dtls
```

**Arguments**
- `<PROTO>`: Protocol name (e.g., `mqtt`, `ftp`, `sip`, `dtls`)
