#!/bin/bash

echo "Running Groth16 trusted setup..."

if ! command -v snarkjs &> /dev/null; then
    echo "Error: snarkjs not found. Please install snarkjs first."
    echo "Run: npm install -g snarkjs"
    exit 1
fi

if [ ! -f "build/poseidon2.r1cs" ]; then
    echo "Error: Circuit not compiled. Run ./compile.sh first."
    exit 1
fi

mkdir -p keys

echo "Starting powers of tau ceremony..."

snarkjs powersoftau new bn128 12 keys/pot12_0000.ptau -v

snarkjs powersoftau contribute keys/pot12_0000.ptau keys/pot12_0001.ptau --name="First contribution" -v -e="random entropy"

echo "Preparing phase 2..."
snarkjs powersoftau prepare phase2 keys/pot12_0001.ptau keys/pot12_final.ptau -v

echo "Generating proving key..."
snarkjs groth16 setup build/poseidon2.r1cs keys/pot12_final.ptau keys/poseidon2_0000.zkey

snarkjs zkey contribute keys/poseidon2_0000.zkey keys/poseidon2_0001.zkey --name="1st Contributor Name" -v -e="Another random entropy"

echo "Exporting verification key..."
snarkjs zkey export verificationkey keys/poseidon2_0001.zkey keys/verification_key.json

cp keys/poseidon2_0001.zkey keys/poseidon2.zkey

echo "Trusted setup completed!"
echo "Generated files:"
echo "  - keys/poseidon2.zkey (proving key)"
echo "  - keys/verification_key.json (verification key)"
