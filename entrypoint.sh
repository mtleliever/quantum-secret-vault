#!/bin/bash

# Create output directory if missing
mkdir -p /output

# Execute the Python script with mounted volumes and layered security arguments
python3 -m src.cli \
  --seed "$SEED" \
  --passphrase "$PASSPHRASE" \
  $LAYERS \
  $SHAMIR_PARAMS \
  $IMAGES_ARG \
  --output-dir /output

# Fix permissions for host access
chown -R 1000:1000 /output
