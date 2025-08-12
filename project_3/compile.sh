#!/bin/bash

echo "Compiling Poseidon2 circuit..."

if ! command -v circom &> /dev/null; then
    echo "Error: circom not found. Please install circom first."
    echo "Visit: https://docs.circom.io/getting-started/installation/"
    exit 1
fi

mkdir -p build

echo "Compiling poseidon2.circom to R1CS and WASM..."
circom poseidon2.circom --r1cs --wasm --sym --c -o build/

if [ $? -eq 0 ]; then
    echo "Circuit compiled successfully!"
    echo "Generated files:"
    echo "  - build/poseidon2.r1cs (R1CS constraint system)"
    echo "  - build/poseidon2_js/poseidon2.wasm (WebAssembly)"
    echo "  - build/poseidon2.sym (symbol table)"
    echo "  - build/poseidon2_cpp/ (C++ files)"
else
    echo "Circuit compilation failed!"
    exit 1
fi

echo "Compilation complete!"
