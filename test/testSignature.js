const assert = require("assert");

const Ecdsa = require("../ellipticcurve/ecdsa");
const PrivateKey = require("../ellipticcurve/privateKey").PrivateKey;
const Signature = require("../ellipticcurve/signature").Signature;


describe("SignatureTest", function () {

    describe("#testDerConversion()", function () {
        it("should validate DER signature generation and conversion", function () {
            let privateKey = new PrivateKey();
            let message = "This is a text message";

            let signature1 = Ecdsa.sign(message, privateKey);

            let der = signature1.toDer();
            let signature2 = Signature.fromDer(der);

            assert.equal(String(signature1.r), String(signature2.r));
            assert.equal(String(signature1.s), String(signature2.s));
        });
    });

    describe("#testBase64Conversion()", function () {
        it("should validate Base64 signature generation and conversion", function () {
            let privateKey = new PrivateKey();
            let message = "This is a text message";

            let signature1 = Ecdsa.sign(message, privateKey);

            let base64 = signature1.toBase64();
            let signature2 = Signature.fromBase64(base64);

            assert.equal(String(signature1.r), String(signature2.r));
            assert.equal(String(signature1.s), String(signature2.s));
        });
    });

    describe("#testUniqueness()", function () {
        it("should produce different signatures for the same message and key", function () {
            let privateKey = new PrivateKey();
            let message = "This is a text message";

            let signature1 = Ecdsa.sign(message, privateKey);
            let signature2 = Ecdsa.sign(message, privateKey);

            let base641 = signature1.toBase64();
            let base642 = signature2.toBase64();

            assert.notEqual(base641, base642);
        });
    });
});
