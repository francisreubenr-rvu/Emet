# Scanner Setup Guide

This document covers local setup for scanner integrations used by EMET.

## Nmap

1. Install Nmap:
   - Ubuntu/Debian: `sudo apt-get install -y nmap`
   - macOS (Homebrew): `brew install nmap`
2. Verify: `nmap --version`

## Nessus

1. Install Nessus from Tenable.
2. Start service and open `https://localhost:8834`.
3. Create API keys and place values in `.env`:
   - `NESSUS_URL`
   - `NESSUS_ACCESS_KEY`
   - `NESSUS_SECRET_KEY`
4. If keys are missing, EMET should show "Nessus unavailable" but continue with other scanners.

## OpenVAS / Greenbone

1. Install OpenVAS/Greenbone.
2. Set `.env` values:
   - `OPENVAS_HOST`
   - `OPENVAS_PORT`
   - `OPENVAS_USERNAME`
   - `OPENVAS_PASSWORD`
3. Validate connectivity before enabling in production.

## Nuclei

1. Install Nuclei binary.
2. Sync templates: `nuclei -update-templates`
3. Confirm version: `nuclei -version`

## Nikto and Wapiti

Install both tools through your package manager and ensure binaries are in `PATH`.

## Graceful Degradation

- If a scanner is unavailable, backend reports `is_available = false`.
- Frontend displays the tool as unavailable with a clear message.
- Scan execution continues for available tools.
