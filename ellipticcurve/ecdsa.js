const crypto = require("crypto");
const BigInt = require("big-integer");

const EcdsaMath = require("./math");
const Signature = require("./signature").Signature;
const BinaryAscii = require("./utils/binary");
const Integer = require("./utils/integer");
const modulo = Integer.modulo;


exports.sign = function (message, privateKey, hashfunc = null) {
    if (hashfunc == null) {
        hashfunc = "sha256";
    }
    let curve = privateKey.curve;
    let byteMessage = crypto.createHash(hashfunc).update(message).digest();
    let numberMessage = BinaryAscii.numberFromHex(byteMessage.toString("hex"), curve.N.bitLength().toJSNumber());

    let r = BigInt(0), s = BigInt(0), randSignPoint = null;
    let kIterator = Integer.rfc6979(byteMessage, privateKey.secret, curve, hashfunc);
    while (r.eq(0) || s.eq(0)) {
        let randNum = kIterator.next();
        randSignPoint = EcdsaMath.multiply(curve.G, randNum, curve.N, curve.A, curve.P);
        r = modulo(randSignPoint.x, curve.N);
        s = modulo(numberMessage.add(r.multiply(privateKey.secret)).multiply(EcdsaMath.inv(randNum, curve.N)), curve.N);
    }
    let recoveryId = randSignPoint.y.and(1).toJSNumber();
    if (randSignPoint.y.greater(curve.N)) {
        recoveryId += 2;
    }
    if (s.greater(curve.N.over(2))) {
        s = curve.N.minus(s);
        recoveryId ^= 1;
    }

    return new Signature(r, s, recoveryId);
};


exports.verify = function (message, signature, publicKey, hashfunc = null) {
    if (hashfunc == null) {
        hashfunc = "sha256";
    }
    let byteMessage = crypto.createHash(hashfunc).update(message).digest();
    let curve = publicKey.curve;
    let numberMessage = BinaryAscii.numberFromHex(byteMessage.toString("hex"), curve.N.bitLength().toJSNumber());
    let r = BigInt(signature.r);
    let s = BigInt(signature.s);

    if (r.lesser(1) || r.greater(curve.N.minus(1))) {
        return false;
    }
    if (s.lesser(1) || s.greater(curve.N.minus(1))) {
        return false;
    }
    if (!curve.contains(publicKey.point)) {
        return false;
    }
    let inv = EcdsaMath.inv(s, curve.N);
    let v = EcdsaMath.multiplyAndAdd(
        curve.G, modulo(numberMessage.multiply(inv), curve.N),
        publicKey.point, modulo(r.multiply(inv), curve.N),
        curve.N, curve.A, curve.P,
    );
    if (v.isAtInfinity()) {
        return false;
    }
    return v.x.mod(curve.N).eq(r);
};
