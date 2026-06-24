---
id: verify-certificate
title: Verify Certificate Guide
sidebar_position: 3
---

# Verify Certificate Guide

The `verify-certificate` verb re-derives the certificate self-hash, verifies the Ed25519 signature (the authoritative provenance check), re-derives stage artifact hashes, replays the inter-stage manifest chain, adjudicates an optional platform countersign, and checks corpus binding by reference.

## Usage

```bash
tenant-tail verify-certificate <certificate.json> [OPTIONS]
```

## Flags

- `--artifact-dir <dir>`: Directory containing stage artifacts for hash re-derivation. If provided, the verifier reads the files and ensures their hashes match the certificate.
- `--platform-jwks <file>`: Path to a saved platform JWKS JSON file for offline seal verification.
- `--require-sealed`: Exit `1` if there is no verifiable platform countersign. By default, an unsealed certificate is reported visually but exits `0`.
- `--corpus-attestation <file>`: Link-check the certificate's corpus binding against this attestation file.

## Offline Verification

`tenant-tail` is entirely offline. When verifying a platform seal, you must provide a saved JWKS file via `--platform-jwks`. It will not fetch keys from the network.

## Re-deriving Artifact Hashes

When you pass `--artifact-dir`, `tenant-tail` reads the artifacts recorded in the certificate's stages and re-derives their hashes. If a file has been tampered with, the verifier exits `1` with an artifact-hash mismatch error.

## Platform Seal Verification

A certificate may carry a platform countersign. 
- If you supply `--platform-jwks`, the countersign is verified against the keyset.
- If you supply `--require-sealed` and the certificate lacks a countersign (or lacks a JWKS to verify it), the command fails closed (exit `1`).

## Corpus Binding Link-Check

The verifier can check if the `corpusAttestationHash` in the certificate matches a supplied file (`--corpus-attestation`). It only checks the hash link; verifying the attestation's truth is delegated to `spec-spine`.

## Exit Codes

- `0`: Verified successfully.
- `1`: Verification failed (e.g., signature mismatch, artifact hash mismatch, or a fail-closed flag fired).
- `2`: Usage or I/O error (e.g., unreadable input file).
