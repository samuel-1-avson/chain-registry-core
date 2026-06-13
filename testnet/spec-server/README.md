# Chain Spec Server

Minimal nginx-based server for hosting the signed chain spec.

## Quick Start

```bash
cd testnet/spec-server
cp ../chain-spec.sepolia.json ./chain-spec.json
cp ../chain-spec.sepolia.json.sig ./chain-spec.json.sig
docker compose up -d
```

## Test

```bash
curl http://localhost:8888/chain-spec.json | jq .chain_id
curl http://localhost:8888/chain-spec.json.sig
```

## Production Deployment

### Option A: Cloudflare Pages (Recommended — Free + CDN)

1. Create a repo or folder with `chain-spec.json` + `chain-spec.json.sig`
2. Push to GitHub
3. Connect to Cloudflare Pages
4. Your spec is available at `https://your-spec.pages.dev/chain-spec.json`

### Option B: AWS S3 + CloudFront

```bash
aws s3 cp chain-spec.json s3://your-bucket/chain-spec.json
aws s3 cp chain-spec.json.sig s3://your-bucket/chain-spec.json.sig
```

### Option C: Run this Docker Compose on a VPS

```bash
docker compose up -d
# Place behind Cloudflare proxy for HTTPS + caching
```

## Node Configuration

Nodes fetch the spec at boot via `CREG_CHAIN_SPEC_URL`:

```bash
CREG_CHAIN_SPEC_URL=https://your-spec-server.example.com/chain-spec.json
CREG_SPEC_SIGNING_PUBKEY=0437e4adac481519cd6ae66907294c40cfcbf0bdeadd47806f6233be4bd5f82d
```
