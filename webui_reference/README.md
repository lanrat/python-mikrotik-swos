# Switch Code

This folder contains the basic HTML and JS used by the various MikroTik SwitchOS and SwitchOS Lite HTTP interfaces.

- Cloud Router Switch (CRS): Runs the full SwitchOS or RouterOS
- Cloud Smart Switch (CSS): Runs either the full SwitchOS or SwitchOS Lite,
  depending on the model

The model prefix does not tell you which platform a switch runs. CSS610 models run
SwitchOS Lite, while CSS318 and CSS326 run the full SwitchOS. The reliable signal is the
field naming in `sys.b`: SwitchOS Lite uses hex IDs (`i01`, `i02`), the full SwitchOS uses
descriptive names (`id`, `ver`, `brd`).

## Purpose

The code here is used as a reference when reverse-engineering the API calls.

## Contents

- Organized by switch model (one folder per model)
- Minified JavaScript extracted directly from switch firmware
- Generic code only - contains no device-specific information, credentials, or PII

## Notes

- Files are typically minified/obfuscated as they appear in the original firmware
- Useful for understanding API endpoints, request formats, and data structures
