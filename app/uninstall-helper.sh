#!/bin/bash
set -euo pipefail
helper='/Library/Application Support/vpn.akimov.macos/helper'
if [ ! -x "$helper" ]; then echo 'The akimov vpn helper is not installed.'; exit 0; fi
sudo "$helper" --remove-helper
