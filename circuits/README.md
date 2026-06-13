# ZK Circuits for Chain Registry

This directory contains the Circom circuits currently tracked in this workspace
for Chain Registry proof experiments.

## Current Circuits

### DoubleSignProof.circom

Proof of conflicting validator votes for the same package.

- Public inputs: validator public key, package hash, first vote hash, second vote hash
- Private witness: signature data for both votes
- Intended use: double-sign evidence and slashing workflows

### PackageValidator.circom

Proof that a package satisfies published safety thresholds without revealing the
full package contents.

- Public inputs: `contentHash`, `manifestHash`, `staticAnalysisScore`, `sandboxPassed`, `noVulnerableDeps`, plus the configured threshold values
- Private witness: package content array and internal safety metrics such as complexity, network calls, and file writes
- Intended use: publisher admission attestation experiments

## Directory Layout

| Path | Purpose |
|---|---|
| `DoubleSignProof.circom` | Double-sign evidence circuit |
| `PackageValidator.circom` | Package safety / publisher-attestation circuit |
| `build_circuit.sh` | Supported local build helper |
| `package.json` / `package-lock.json` | Node dependencies for circuit tooling |
| `build/` | Generated build artifacts |
| `keys/` | Generated proving and verification keys |

`node_modules/` is dependency output and should not be treated as part of the
public circuit interface.

## Build

Prerequisites:

1. Circom 2.1+
2. Node.js and npm
3. `snarkjs`

Install dependencies and run the build helper:

```bash
npm install
./build_circuit.sh
```

The build helper is the supported path for local development in this workspace.
It compiles the configured circuit, generates R1CS/WASM artifacts, and writes
proof material into `build/` and `keys/`.

## Manual Proof Workflow

After building, the general proof flow is:

1. generate a witness from the compiled WASM
2. create a Groth16 proof with `snarkjs`
3. verify the proof against the generated verification key

The exact file names under `build/` and `keys/` depend on which circuit you
compiled.

## References

- [Circom Documentation](https://docs.circom.io/)
- [Circomlib](https://github.com/iden3/circomlib)
- [Groth16 Paper](https://eprint.iacr.org/2016/260)
- [Poseidon Hash](https://eprint.iacr.org/2019/458)
