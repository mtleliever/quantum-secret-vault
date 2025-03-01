#!/bin/bash
# Mount host directories:
# - ./input_images/: Container's /input/ (place source PNGs here)
# - ./vault_output/: Container's /output/
# Example: ./run.sh "word1 ... word24" "passphrase" 5 7 2

SEED="$1"
PASSPHRASE="$2"
SHAMIR_THRESHOLD="$3"
SHAMIR_TOTAL="$4"
PARITY="$5"

docker run --rm -it \
  -v "$(pwd)/input_images/:/input/" \
  -v "$(pwd)/vault_output/:/output/" \
  -e SEED="$SEED" \
  -e PASSPHRASE="$PASSPHRASE" \
  -e SHAMIR_THRESHOLD="$SHAMIR_THRESHOLD" \
  -e SHAMIR_TOTAL="$SHAMIR_TOTAL" \
  -e PARITY="$PARITY" \
  -e IMAGES="$(ls ./input_images/*.png | tr '\n' ' ')" \
  quantum-vault:1.0
