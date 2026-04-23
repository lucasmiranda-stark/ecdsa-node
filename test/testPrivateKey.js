const assert = require("assert");

const PrivateKey = require("../ellipticcurve/privateKey").PrivateKey;


describe("PrivateKeyTest", function () {

    describe("#testPemConversion()", function () {
        it("should validate PEM generation and conversion", function () {
            let privateKey1 = new PrivateKey();
            let pem = privateKey1.toPem();
            let privateKey2 = PrivateKey.fromPem(pem);

            assert.equal(String(privateKey1.secret), String(privateKey2.secret));
            assert.equal(String(privateKey1.curve), String(privateKey2.curve));
        });
    });

    describe("#testDerConversion()", function () {
        it("should validate DER generation and conversion", function () {
            let privateKey1 = new PrivateKey();
            let der = privateKey1.toDer();
            let privateKey2 = PrivateKey.fromDer(der);

            assert.equal(String(privateKey1.secret), String(privateKey2.secret));
            assert.equal(String(privateKey1.curve), String(privateKey2.curve));
        });
    });

    describe("#testStringConversion()", function () {
        it("should validate private-key-string generation and conversion", function () {
            let privateKey1 = new PrivateKey();
            let string = privateKey1.toString();
            let privateKey2 = PrivateKey.fromString(string);

            assert.equal(String(privateKey1.secret), String(privateKey2.secret));
            assert.equal(String(privateKey1.curve), String(privateKey2.curve));
        });
    });
});
