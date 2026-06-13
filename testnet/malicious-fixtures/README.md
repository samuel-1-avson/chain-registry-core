# MAL-002 — Malicious package fixture suite

Controlled negative-test packages for the validator static-analysis pipeline. Each fixture is a minimal npm tarball that **must** trigger at least one expected deterministic finding.

| ID | Category | Expected findings (minimum) |
| --- | --- | --- |
| `01-eval-exfil` | Dynamic code execution | `SA001` |
| `02-install-script` | Install hook abuse | `SA004` or install-hook pattern |
| `03-obfuscated` | Obfuscation | `SA002` or entropy finding |
| `04-typosquat` | Typosquatting | `SA010` (`lodish` → `lodash`) |
| `05-process-spawn` | Undeclared spawn | `SA003` |
| `06-fs-write` | Dangerous filesystem access | `SA005` or write pattern |
| `07-network-hook` | Network in install hook | `SA004` |

## Run

```powershell
# Unit tests (static analysis, no sandbox required)
cargo test -p validator malicious_fixture --locked

# Evidence JSON for launch gates
.\testnet\malicious-fixtures-verify.ps1
```

Sandbox behavioural checks (SB00x) run in `sandbox-301-verify.ps1` / fleet soak — not in this suite yet.
