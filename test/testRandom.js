const assert = require("assert");

const Ecdsa = require("../ellipticcurve/ecdsa");
const PrivateKey = require("../ellipticcurve/privateKey").PrivateKey;
const PublicKey = require("../ellipticcurve/publicKey").PublicKey;
const Signature = require("../ellipticcurve/signature").Signature;


describe("RandomTest", function () {

    describe("#testMany()", function () {
        it("should sign and verify 1000 random key pairs", function () {
            this.timeout(120000);
            for (let i = 0; i < 1000; i++) {
                let privateKey1 = new PrivateKey();
                let publicKey1 = privateKey1.publicKey();

                let privateKeyPem = privateKey1.toPem();
                let publicKeyPem = publicKey1.toPem();

                let privateKey2 = PrivateKey.fromPem(privateKeyPem);
                let publicKey2 = PublicKey.fromPem(publicKeyPem);

                let message = "test";

                let signatureBase64 = Ecdsa.sign(message, privateKey2).toBase64();
                let signature = Signature.fromBase64(signatureBase64);

                assert.equal(Ecdsa.verify(message, signature, publicKey2), true);
            }
        });
    });
});
