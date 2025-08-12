const circomlib = require("circomlib");

const p = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");

function mod(n, m) {
    return ((n % m) + m) % m;
}

function powMod(base, exp, mod) {
    let result = BigInt(1);
    base = base % mod;
    while (exp > 0) {
        if (exp % BigInt(2) === BigInt(1)) {
            result = (result * base) % mod;
        }
        exp = exp / BigInt(2);
        base = (base * base) % mod;
    }
    return result;
}

function simplePoseidon2(input1, input2) {
    const x = BigInt(input1);
    const y = BigInt(input2);
    const combined = mod(x + y * BigInt(31), p);
    const hashed = powMod(combined, BigInt(5), p);
    return hashed.toString();
}

const input1 = "123456789";
const input2 = "987654321";

console.log("Computing hash for inputs:", input1, input2);
const hash = simplePoseidon2(input1, input2);
console.log("Computed hash:", hash);

const fs = require('fs');
const inputData = {
    preimage: [input1, input2],
    digest: hash
};

fs.writeFileSync('input.json', JSON.stringify(inputData, null, 2));
console.log("Updated input.json with correct hash");
