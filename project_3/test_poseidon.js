const fs = require('fs');
const circomlib = require('ffjavascript');
const wasm_tester = require('circom_tester').wasm;

async function testPoseidon2() {
    console.log('Testing Poseidon2 circuit...');
    try {
        const circuit = await wasm_tester("poseidon2.circom");
        const input = {
            preimage: ["0", "123456789"]
        };
        console.log('Input:', input);
        const witness = await circuit.calculateWitness(input, true);
        console.log('Witness generated successfully');
        await circuit.checkConstraints(witness);
        console.log('Constraints satisfied!');
        console.log('Hash output:', witness[1].toString());
    } catch (error) {
        console.error('Test failed:', error);
    }
}

testPoseidon2().catch(console.error);
