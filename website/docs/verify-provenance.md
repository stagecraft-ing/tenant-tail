---
id: verify-provenance
title: Verify Provenance Guide
sidebar_position: 4
---

# Verify Provenance Guide

The `verify-provenance` verb runs a claim-provenance audit over a produced application. It re-checks every claim minted during the build, read-only. A Markdown report is written to **stdout** and never into the audited project.

## Usage

```bash
tenant-tail verify-provenance --project <dir> [OPTIONS]
```

## Flags

- `--project <dir>`: (Required) The application directory to re-check.
- `--corpus <path>`: Override the corpus path. Supports typed JSON (`ExtractionOutput`) or a legacy `.txt` directory.
- `--fail-on-rejected`: Exit `1` if any claim is rejected. By default, the audit is diagnostic and exits `0` even with rejected claims, but the verdict text is identical either way.

## What the Audit Checks

The audit verifies that every claim in the project carries valid provenance:
1. It has a valid citation against the extraction corpus.
2. Or, it is explicitly tagged as an `ASSUMPTION` and fits within the project's assumption budget.

## The Extraction Corpus

The corpus is the source of truth for claims. It can be a typed JSON artifact store (spec-120) or synthesized from legacy `.txt` files. The report explicitly marks `synthesizedCorpus: true` if it falls back to text files.

## The Assumption Budget

Projects have an assumption budget that limits the number of un-cited claims. The audit verifies that the total number of assumptions does not exceed this budget.

## Reading the Markdown Report

The report is printed to `stdout` and includes:
- **Metadata:** Schema versions, corpus source, and hashes.
- **Summary Table:** Counts of claims by mode (`derived`, `assumption`, `rejected`, etc.) and the overall `provenanceHealth` percentage.
- **Findings:** Detailed breakdown of each claim, its anchor hash, and search results.
- **Suggested Next Actions:** Guidance on fixing rejected or orphaned claims.

## Fail-Closed Mode

For CI or strict enforcement, use `--fail-on-rejected`. This causes the verifier to exit `1` if any claim is rejected, acting as a tenant-ward fail-closed gate.
