// based on random-number-csprng: https://www.npmjs.com/package/random-number-csprng

const BigInt = require("big-integer");
const crypto = require("crypto");
const BinaryAscii = require("./binary");


function modulo(x, n) {
    let mod = x.divmod(n).remainder;

    if (mod.lesser(0)) {
        mod = mod.add(n);
    }

    return mod;
}


function calculateParameters(range) {
	/* This does the equivalent of:
	 *
	 *    bitsNeeded = Math.ceil(Math.log2(range));
	 *    bytesNeeded = Math.ceil(bitsNeeded / 8);
	 *    mask = Math.pow(2, bitsNeeded) - 1;
	 *
	 * ... however, it implements it as bitwise operations, to sidestep any
	 * possible implementation errors regarding floating point numbers in
	 * JavaScript runtimes. This is an easier solution than assessing each
	 * runtime and architecture individually.
	 */

	let bitsNeeded = 0;
	let bytesNeeded = 0;
	let mask = BigInt(1);

	while (range.greater(0)) {
		if (bitsNeeded % 8 === 0) {
			bytesNeeded += 1;
		}

        bitsNeeded += 1;
        mask = mask.shiftLeft(1).or(1); /* 0x00001111 -> 0x00011111 */

        range = range.shiftRight(1);  /* 0x01000000 -> 0x00100000 */
	}

	return {bitsNeeded, bytesNeeded, mask};
}


function secureRandomNumber(minimum, maximum) { // bigint, bigint
    if (crypto == null || crypto.randomBytes == null) {
        throw new Error("No suitable random number generator available. Ensure that your runtime is linked against OpenSSL (or an equivalent) correctly.");
    };

    if (maximum.lesserOrEquals(minimum)) {
        throw new Error("The maximum value must be higher than the minimum value.")
    };

    let range = maximum.minus(minimum);

    let {bitsNeeded, bytesNeeded, mask} = calculateParameters(range);

    let randomBytes = crypto.randomBytes(bytesNeeded);

    var randomValue = BigInt(0);

    /* Turn the random bytes into an integer, using bitwise operations. */
    for (let i = BigInt(0); i.lesser(bytesNeeded); i = i.add(1)) {
        randomValue = randomValue.or(BigInt(randomBytes[i]).shiftLeft(BigInt(8).multiply(i)));
    }

    randomValue = randomValue.and(mask);

    if (randomValue.lesserOrEquals(range)) {
        return minimum.add(randomValue);
    }

    return secureRandomNumber(minimum, maximum);
};


function rfc6979(hashBytes, secret, curve, hashfunc) {
    /**
     * Generate deterministic nonce values per RFC 6979.
     * Returns an iterator that yields BigInt nonce candidates.
     *
     * :param hashBytes: Buffer of hashed message bytes
     * :param secret: BigInt private key secret
     * :param curve: curve object with N
     * :param hashfunc: hash function name string (e.g. "sha256")
     */
    let orderBitLen = curve.N.bitLength().toJSNumber();
    let orderByteLen = Math.ceil(orderBitLen / 8);

    let secretHex = secret.toString(16).padStart(orderByteLen * 2, "0");
    let secretBytes = Buffer.from(secretHex, "hex");

    let hashReduced = modulo(BinaryAscii.numberFromHex(hashBytes.toString("hex"), orderBitLen), curve.N);
    let hashHex = hashReduced.toString(16).padStart(orderByteLen * 2, "0");
    let hashOctets = Buffer.from(hashHex, "hex");

    let hLen = _hashDigestSize(hashfunc);
    let V = Buffer.alloc(hLen, 0x01);
    let K = Buffer.alloc(hLen, 0x00);

    K = _hmac(hashfunc, K, Buffer.concat([V, Buffer.from([0x00]), secretBytes, hashOctets]));
    V = _hmac(hashfunc, K, V);
    K = _hmac(hashfunc, K, Buffer.concat([V, Buffer.from([0x01]), secretBytes, hashOctets]));
    V = _hmac(hashfunc, K, V);

    let results = [];
    let done = false;

    return {
        next: function () {
            while (true) {
                let T = Buffer.alloc(0);
                while (T.length * 8 < orderBitLen) {
                    V = _hmac(hashfunc, K, V);
                    T = Buffer.concat([T, V]);
                }

                let k = BinaryAscii.numberFromHex(T.toString("hex"), orderBitLen);

                if (k.greaterOrEquals(1) && k.lesserOrEquals(curve.N.minus(1))) {
                    return k;
                }

                K = _hmac(hashfunc, K, Buffer.concat([V, Buffer.from([0x00])]));
                V = _hmac(hashfunc, K, V);
            }
        }
    };
}


function _hmac(hashfunc, key, data) {
    let alg = _resolveHashAlgorithm(hashfunc);
    return crypto.createHmac(alg, key).update(data).digest();
}


function _hashDigestSize(hashfunc) {
    let alg = _resolveHashAlgorithm(hashfunc);
    return crypto.createHash(alg).digest().length;
}


function _resolveHashAlgorithm(hashfunc) {
    if (typeof hashfunc === "string") {
        return hashfunc;
    }
    // default to sha256
    return "sha256";
}


exports.between = secureRandomNumber;
exports.modulo = modulo;
exports.rfc6979 = rfc6979;
