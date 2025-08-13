#!/bin/bash

CFLAGS="-O3 -mavx2 -mbmi2 -march=native -mtune=native -funroll-loops -ffast-math -flto"

VARIANTS=(
    "sm3:Standard Implementation"
    "opt1_unroll:Full Loop Unrolling" 
    "opt2_regalloc:Register Allocation Optimized"
    "opt3_simd:SIMD Message Expansion"
    "opt4_on_the_fly:On-the-fly Computation"
    "opt5_flatten:Flattened & Macro Optimized"
)

echo "Using compilation flags: $CFLAGS"
echo ""

for variant_info in "${VARIANTS[@]}"; do
    IFS=':' read -r variant description <<< "$variant_info"
    echo "Compiling $variant ($description)..."
    g++ $CFLAGS -o "${variant}.elf" "${variant}.cpp"
    echo ""
done

for variant_info in "${VARIANTS[@]}"; do
    IFS=':' read -r variant description <<< "$variant_info"

    if [ -x "${variant}.elf" ]; then
        echo -n "Testing $variant: "
        HASH=$(echo -n "abc" | ./"${variant}.elf")
        echo "$HASH"
    fi
done

