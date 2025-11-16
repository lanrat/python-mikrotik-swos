# Switch Code

This folder contains the basic HTML and JS used by the various MikroTik SwitchOS and SwitchOS Lite HTTP interfaces.

- Cloud Router Switch (CRS): Runs the full SwitchOS or RouterOS
- Cloud Smart Switch (CSS): Runs simpler SwitchOS

## Purpose

The code here is used as a reference when reverse-engineering the API calls.

## Contents

- Organized by switch model (one folder per model)
- Minified JavaScript extracted directly from switch firmware
- Generic code only - contains no device-specific information, credentials, or PII

## Notes

- Files are typically minified/obfuscated as they appear in the original firmware
- Useful for understanding API endpoints, request formats, and data structures
