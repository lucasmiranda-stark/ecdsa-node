const assert = require("assert");

const PrivateKey = require("../ellipticcurve/privateKey").PrivateKey;
const PublicKey = require("../ellipticcurve/publicKey").PublicKey;


describe("PublicKeyTest", function () {

    describe("#testPemConversion()", function () {
        it("should validate PEM generation and conversion", function () {
            let privateKey = new PrivateKey();
            let publicKey1 = privateKey.publicKey();
            let pem = publicKey1.toPem();
            let publicKey2 = PublicKey.fromPem(pem);

            assert.equal(String(publicKey1.point.x), String(publicKey2.point.x));
            assert.equal(String(publicKey1.point.y), String(publicKey2.point.y));
            assert.equal(publicKey1.curve, publicKey2.curve);
        });
    });

    describe("#testDerConversion()", function () {
        it("should validate DER generation and conversion", function () {
            let privateKey = new PrivateKey();
            let publicKey1 = privateKey.publicKey();
            let der = publicKey1.toDer();
            let publicKey2 = PublicKey.fromDer(der);

            assert.equal(String(publicKey1.point.x), String(publicKey2.point.x));
            assert.equal(String(publicKey1.point.y), String(publicKey2.point.y));
            assert.equal(publicKey1.curve, publicKey2.curve);
        });
    });

    describe("#testStringConversion()", function () {
        it("should validate public-key-string generation and conversion", function () {
            let privateKey = new PrivateKey();
            let publicKey1 = privateKey.publicKey();
            let string = publicKey1.toString();
            let publicKey2 = PublicKey.fromString(string);

            assert.equal(String(publicKey1.point.x), String(publicKey2.point.x));
            assert.equal(String(publicKey1.point.y), String(publicKey2.point.y));
            assert.equal(publicKey1.curve, publicKey2.curve);
        });
    });
});
