const assert = require("assert");

const Ecdsa = require("../ellipticcurve/ecdsa");
const PrivateKey = require("../ellipticcurve/privateKey").PrivateKey;
const Signature = require("../ellipticcurve/signature").Signature;


describe("EcdsaTest", function () {

    describe("#testVerifyRightMessage()", function () {
        it("should confirm authenticity", function () {
            let privateKey = new PrivateKey();
            let publicKey = privateKey.publicKey();

            let message = "This is the right message";

            let signature = Ecdsa.sign(message, privateKey);

            assert.equal(Ecdsa.verify(message, signature, publicKey), true);
        });
    });

    describe("#testVerifyWrongMessage()", function () {
        it("should deny authenticity", function () {
            let privateKey = new PrivateKey();
            let publicKey = privateKey.publicKey();

            let message1 = "This is the right message";
            let message2 = "This is the wrong message";

            let signature = Ecdsa.sign(message1, privateKey);

            assert.equal(Ecdsa.verify(message2, signature, publicKey), false);
        });
    });

    describe("#testZeroSignature()", function () {
        it("should deny authenticity", function () {
            let privateKey = new PrivateKey();
            let publicKey = privateKey.publicKey();

            let message = "This is the right message";

            assert.equal(Ecdsa.verify(message, new Signature(0, 0), publicKey), false);
        });
    });
});
