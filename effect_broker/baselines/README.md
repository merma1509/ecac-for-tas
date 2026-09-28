# External Baseline Implementations

## External Systems Reference

These are **architectural stubs** representing the CORE SECURITY PROPERTIES of each system,
not actual implementations. The referenced systems are research prototypes from academic papers
without public pip-installable implementations.

| System | Paper | pip | Our Stub | Block Rate |
|--------|-------|-----|----------|-----------|
| **CaMeL** | Research (Cornell/NYU) | ❌ | `mode_camel.py` | 9.1% |
| **FIDES** | Research | ❌ | `mode_camel.py` | 9.1% |
| **PACT** | Property Attestation | ❌ | `mode_pact.py` | 45.5% |
| **ChainCaps** | Capability research | ❌ | `mode_chaincaps.py` | 27.3% |
| **Cordon** | Commit-time revalidation | ❌ | `mode_cordon.py` | 45.5% |
| **FORGE** | Policy DSL | ❌ | `mode_forge.py` | 63.6% |
| **AgentDojo** | [Princeton](https://github.com/PrincetonUniversity/AgentDojo) | ✅ | reference | — |

## Running Comparison

```bash
python -c "from effect_broker.baselines import run_comparison; run_comparison()"
```

## Baseline Comparison Results (11 adversarial traces)

| System | Blocked | Allowed | Rate |
|--------|---------|---------|------|
| **ECAC** | 11 | 0 | **100%** |
| FORGE | 7 | 4 | 63.6% |
| PACT | 5 | 6 | 45.5% |
| Cordon | 5 | 6 | 45.5% |
| Allowlist | 4 | 7 | 36.4% |
| ChainCaps | 3 | 8 | 27.3% |
| ArgProv | 2 | 9 | 18.2% |
| CaMeL | 1 | 10 | 9.1% |

## Key Findings

### What Each System Catches

| System | Strengths | Weaknesses |
|--------|-----------|------------|
| CaMeL | IFC enforcement | No session taint, no ledger |
| PACT | Capability scope | No content hash, no taint |
| ChainCaps | Transformation chains | EXPAND allows widening |
| Cordon | Commit-time revalidation | No provenance, no taint |
| FORGE | Policy DSL flexibility | No formal invariant |
| Allowlist | Simple deployment | Pattern matching only |
| ArgProv | Provenance tracking | No capabilities |
| **ECAC** | **All T1-T4** | **—** |

### ECAC's Unique Contributions

1. **Formal Invariant:** `Commit(e,t) ⟺ Authorized ∧ FlowOK ∧ NoAmp`
2. **Session Taint Propagation:** Confidential reads taint session
3. **Content Hash Binding:** ApprovedRequest binds message content
4. **Independent Ledger:** Machine-checkable audit trail
5. **HMAC-Signed IPC:** Cross-process integrity (A2)

## AgentDojo Integration

AgentDojo is installed and available for reference:
```python
from agentdojo.task_suite.load_suites import get_suite, get_suites

# List available suites
suites = get_suites("v1.2.2")
# Available: workspace, travel, banking, slack
```
