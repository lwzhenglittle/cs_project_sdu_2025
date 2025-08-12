#!/bin/bash

echo "Verifying proof..."

if ! command -v snarkjs &> /dev/null; then
    echo "Error: snarkjs not found. Please install snarkjs first."
    echo "Run: npm install -g snarkjs"
    exit 1
fi

if [ ! -f "proofs/proof.json" ]; then
    echo "Error: proof.json not found. Run ./prove.sh first."
    exit 1
fi

if [ ! -f "proofs/public.json" ]; then
    echo "Error: public.json not found. Run ./prove.sh first."
    exit 1
fi

if [ ! -f "keys/verification_key.json" ]; then
    echo "Error: verification_key.json not found. Run ./setup.sh first."
    exit 1
fi

echo "Running verification..."
snarkjs groth16 verify keys/verification_key.json proofs/public.json proofs/proof.json

if [ $? -eq 0 ]; then
    echo "Proof verification successful!"
    echo "The proof is valid - the prover knows a preimage that hashes to the given digest."
else
    echo "Proof verification failed!"
    echo "The proof is invalid."
    exit 1
fi
