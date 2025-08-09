# sybilglass — see through your airdrop list

**sybilglass** is an offline CLI that inspects EVM address lists and highlights
**near-duplicate clusters** and **vanity anomalies** that often correlate with
airdrop farming. It requires no RPC or internet access. Feed it your CSV/TXT/JSON,
get a scored report, a near-pairs file, and an optional SVG badge to drop into your
repo or dashboard.

> It does not claim “proof of sybil.” It surfaces *suspicious structure* so you can review faster.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
