#!/usr/bin/env bash
# Run from any working directory. --interactive permits lock/unlock prompts;
# --require treats unavailable desktop/hardware coverage as failure.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
node tests/hardware-unlock-lifecycle.test.js
node tests/desktop-state.test.js
node tests/desktop/keyring.integration.js --require
node tests/desktop/hardware.integration.js
node tests/desktop/focus.integration.js "$@"
