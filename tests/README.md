# Validation Framework Overview

This directory contains three complementary validation components designed to ensure the **Usability** of LLM-generated components of LEMUR-Fuzz.

Together, these tests validate **parsers**, **reassemblers**, **mutators**, and **fixers** from different perspectives.

---

## 1. Parser & Reassembler Metamorphic Tests (`PR_mr/`)

**Goal:**  
Validate the *round-trip consistency* between LLM-generated parsers and reassemblers.

**Key idea:**  
A valid input should satisfy the metamorphic relation:

```
bytes → parse → structured packets → reassemble → bytes'
```

where `bytes'` must be semantically equivalent to the original input.


**Directory:**  
```
tests/PR_mr/
```

---

## 2. Mutator Sanity Tests (`mutator_sanity/`)

**Goal:**  
Validate that **mutators** operate safely and produce structurally grammar-valid outputs.

**Key idea:**  
Each mutator is applied to valid protocol seeds and must not:
- Crash
- Produce malformed structures


**Directory:**  
```
tests/mutator_sanity/
```

---

## 3. Fixer Sanity Tests (LLM-Assisted) (`fixer_sanity/`)

**Goal:**  
Validate that **fixers** correctly restore protocol validity when constraints are violated.

**Key idea:**  
Given an intentionally corrupted protocol state, a fixer must enforce the protocol’s semantic and structural constraints.

**Workflow:**
1. Extract fixers into a registry
2. Use an LLM to generate protocol-specific sanity tests from:
   - Natural-language constraint descriptions
   - The fixer registry
   - An existing sanity-test example
3. Execute the generated tests automatically


**Directory:**  
```
tests/fixer_sanity/
```

---

## Summary

| Component                         | Validates                | Focus                          |
|-----------------------------------|--------------------------|--------------------------------|
| Parser/Reassembler MR Tests       | Parser & Reassembler     | Structural consistency         |
| Mutator Sanity Tests              | Mutators                 | Safety & validity              |
| Fixer Sanity Tests (LLM-Assisted) | Fixers                   | Constraint restoration         |

Together, these three validation layers provide **end-to-end assurance** for protocol processing pipelines, from parsing and mutation to semantic repair.

---

For detailed usage instructions, refer to the README in each subdirectory.
