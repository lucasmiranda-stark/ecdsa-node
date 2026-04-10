const assert = require("assert");

const Ecdsa = require("../ellipticcurve/ecdsa");
const PrivateKey = require("../ellipticcurve/privateKey").PrivateKey;
const Signature = require("../ellipticcurve/signature").Signature;


describe("SignatureWithRecoveryIdTest", function () {

    describe("#testDerConversion()", function () {
        it("should round-trip DER with recovery ID", function () {
            let privateKey = new PrivateKey();
            let message = "This is a text message";

            let signature1 = Ecdsa.sign(message, privateKey);

            let der = signature1.toDer(true);
            let signature2 = Signature.fromDer(der, true);

            assert.equal(String(signature1.r), String(signature2.r));
            assert.equal(String(signature1.s), String(signature2.s));
            assert.equal(signature1.recoveryId, signature2.recoveryId);
        });
    });

    describe("#testBase64Conversion()", function () {
        it("should round-trip Base64 with recovery ID", function () {
            let privateKey = new PrivateKey();
            let message = "This is a text message";

            let signature1 = Ecdsa.sign(message, privateKey);

            let base64 = signature1.toBase64(true);
            let signature2 = Signature.fromBase64(base64, true);

            assert.equal(String(signature1.r), String(signature2.r));
            assert.equal(String(signature1.s), String(signature2.s));
            assert.equal(signature1.recoveryId, signature2.recoveryId);
        });
    });
});
