#!/bin/bash
# Quantum Secret Vault with Layered Security
# Usage: ./run.sh "seed phrase" "passphrase" [layers] [shamir_params] [images]
# Example: ./run.sh "word1 ... word24" "passphrase" "quantum_encryption" "shamir_sharing" "steganography" 5 7 image1.png image2.png

SEED="$1"
PASSPHRASE="$2"
shift 2

# Parse layers (everything until we hit numbers or image files)
LAYERS=()
while [[ $# -gt 0 ]]; do
    case $1 in
        standard_encryption|quantum_encryption|shamir_sharing|steganography)
            LAYERS+=("$1")
            shift
            ;;
        [0-9]*)
            # Found numbers, these are Shamir parameters
            break
            ;;
        *.png|*.jpg|*.jpeg|*.bmp)
            # Found image files
            break
            ;;
        *)
            echo "Unknown layer: $1"
            exit 1
            ;;
    esac
done

# Parse Shamir parameters if shamir_sharing is selected
SHAMIR_PARAMS=""
if [[ " ${LAYERS[@]} " =~ " shamir_sharing " ]]; then
    if [[ $# -ge 2 ]]; then
        SHAMIR_THRESHOLD="$1"
        SHAMIR_TOTAL="$2"
        SHAMIR_PARAMS="--shamir $SHAMIR_THRESHOLD $SHAMIR_TOTAL"
        shift 2
    else
        echo "Error: shamir_sharing requires threshold and total parameters"
        exit 1
    fi
fi

# Remaining arguments are image files
IMAGES="$@"

# Build layers argument
LAYERS_ARG=""
for layer in "${LAYERS[@]}"; do
    LAYERS_ARG="$LAYERS_ARG --layers $layer"
done

# Build images argument
IMAGES_ARG=""
if [[ -n "$IMAGES" ]]; then
    for img in $IMAGES; do
        IMAGES_ARG="$IMAGES_ARG --images $img"
    done
fi

echo "Creating quantum vault with layers: ${LAYERS[*]}"
echo "Seed: $SEED"
echo "Passphrase: $PASSPHRASE"
if [[ -n "$SHAMIR_PARAMS" ]]; then
    echo "Shamir: $SHAMIR_THRESHOLD-of-$SHAMIR_TOTAL"
fi
if [[ -n "$IMAGES" ]]; then
    echo "Images: $IMAGES"
fi

docker run --rm -it \
  -v "$(pwd)/input_images/:/input/" \
  -v "$(pwd)/vault_output/:/output/" \
  -e SEED="$SEED" \
  -e PASSPHRASE="$PASSPHRASE" \
  -e LAYERS="$LAYERS_ARG" \
  -e SHAMIR_PARAMS="$SHAMIR_PARAMS" \
  -e IMAGES_ARG="$IMAGES_ARG" \
  quantum-vault:1.0
