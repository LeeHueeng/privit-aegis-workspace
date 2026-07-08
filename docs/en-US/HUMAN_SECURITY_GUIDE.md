# Aegis CLI Human Security Guide

Aegis CLI helps teams run authorized, non-destructive security checks against services they own or are approved to test.

## Quick Start

```bash
npm install
npm run catalog:generate
npm run aegis -- init
npm run aegis -- scope verify
npm run aegis -- plan --mode passive --target frontend
npm run aegis -- run --target frontend --mode passive
npm run aegis -- report --format html
```

## Authorization and Scope

`aegis.scope.json` is mandatory. It records project, environment, enabled targets, allowlisted hosts and paths, denied paths, authorization owner, proof type, expiry, and safety limits. Production defaults to passive-only behavior.

## Frontend Anomaly Capture

Frontend checks collect safe browser/runtime evidence such as headers, console errors, failed network summaries, screenshots, and DOM snapshots.

## Backend/API Testing

API checks are selected from the safe catalog. Authenticated and role-matrix checks require explicit approval and dedicated test accounts.

## DB Read-only Audit

Database audit mode is limited to read-only configuration review. Write queries, schema mutation, and data dumps are blocked by policy.

## Supply Chain Scan

CI mode is designed for SAST, SCA, SBOM, container, IaC, and secret scanning integrations.

## Docker Usage

```bash
docker build -t aegis/security-cli .
docker run --rm -v "$PWD:/workspace" aegis/security-cli run --scope aegis.scope.json
```

## npm Usage

The package includes scripts such as `security:init`, `security:plan`, `security:frontend`, `security:api`, `security:ci`, and `security:report`.

## CI/CD Usage

Run `aegis scope verify`, `aegis plan --mode ci`, `aegis run --mode ci`, then publish SARIF with `aegis report --format sarif`.

## Reports and Remediation

Reports include scope, environment, scan configuration, findings by severity, artifacts, authenticated matrix placeholders, supply-chain readiness, DB audit readiness, and remediation guidance.
