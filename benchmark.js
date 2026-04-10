const crypto = require("crypto");
const Ecdsa = require("./ellipticcurve/ecdsa");
const PrivateKey = require("./ellipticcurve/privateKey").PrivateKey;


const ROUNDS = 100;


function benchmark() {
    let privateKey = new PrivateKey();
    let publicKey = privateKey.publicKey();
    let message = "This is a benchmark test message";

    // Warmup
    let sig = Ecdsa.sign(message, privateKey);
    Ecdsa.verify(message, sig, publicKey);

    // Benchmark sign
    let start = Date.now();
    for (let i = 0; i < ROUNDS; i++) {
        sig = Ecdsa.sign(message, privateKey);
    }
    let signTime = (Date.now() - start) / ROUNDS;

    // Benchmark verify
    start = Date.now();
    for (let i = 0; i < ROUNDS; i++) {
        Ecdsa.verify(message, sig, publicKey);
    }
    let verifyTime = (Date.now() - start) / ROUNDS;

    console.log("");
    console.log(`starkbank-ecdsa benchmark (${ROUNDS} rounds)`);
    console.log("---------------------------------------");
    console.log(`sign:    ${signTime.toFixed(1)}ms`);
    console.log(`verify:  ${verifyTime.toFixed(1)}ms`);
    console.log("");
}


benchmark();
