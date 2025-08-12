#!/bin/bash

echo "Generating proof..."

if ! command -v snarkjs &> /dev/null; then
    echo "Error: snarkjs not found. Please install snarkjs first."
    echo "Run: npm install -g snarkjs"
    exit 1
fi

if [ ! -f "keys/poseidon2.zkey" ]; then
    echo "Error: Setup not complete. Run ./setup.sh first."
    exit 1
fi

if [ ! -f "build/poseidon2_js/poseidon2.wasm" ]; then
    echo "Error: Circuit not compiled. Run ./compile.sh first."
    exit 1
fi

if [ ! -f "input.json" ]; then
    echo "Error: input.json not found."
    exit 1
fi

mkdir -p proofs

echo "Computing witness..."
node build/poseidon2_js/generate_witness.js build/poseidon2_js/poseidon2.wasm input.json proofs/witness.wtns

echo "Generating proof..."
snarkjs groth16 prove keys/poseidon2.zkey proofs/witness.wtns proofs/proof.json proofs/public.json

echo "Proof generated successfully!"
echo "Generated files:"
echo "  - proofs/witness.wtns (witness file)"
echo "  - proofs/proof.json (zero-knowledge proof)"
echo "  - proofs/public.json (public inputs)"

echo ""
echo "Proof:"
cat proofs/proof.json
echo ""
echo "Public inputs:"
cat proofs/public.json
