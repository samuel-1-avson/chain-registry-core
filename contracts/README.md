# Smart contracts

Solidity sources for Chain Registry L1. Deploy with Foundry (`forge test`, `forge script`).

## Status

| Contract | File | Status |
|----------|------|--------|
| Registry, Staking, Governance, ZK stack, etc. | `*.sol` | **Active** — see root [README.md](../../README.md) contract table |
| CrossChainRegistry | `CrossChainRegistry.sol` | **Planned** — D4 / SEC-303c; spec `cross_chain: false` on Sepolia |
| PrivateRegistry | *(not in tree)* | **Planned** — D5 / SEC-306a; ISSUE-004; no `PrivateRegistry.sol` until enterprise commitment |

```bash
cd chain-registry/contracts
forge test
```
