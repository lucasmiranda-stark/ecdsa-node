const assert = require("assert");

const PrivateKey = require("../ellipticcurve/privateKey").PrivateKey;
const PublicKey = require("../ellipticcurve/publicKey").PublicKey;


describe("CompPubKeyTest", function () {

    describe("#testBatch()", function () {
        it("should compress and recover 1000 random public keys", function () {
            this.timeout(120000);
            for (let i = 0; i < 1000; i++) {
                let privateKey = new PrivateKey();
                let publicKey = privateKey.publicKey();
                let publicKeyString = publicKey.toCompressed();

                let recoveredPublicKey = PublicKey.fromCompressed(publicKeyString, publicKey.curve);

                assert.equal(String(publicKey.point.x), String(recoveredPublicKey.point.x));
                assert.equal(String(publicKey.point.y), String(recoveredPublicKey.point.y));
            }
        });
    });

    describe("#testFromCompressedEven()", function () {
        it("should recover public key from even compressed form", function () {
            let publicKeyCompressed = "0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2";
            let publicKey = PublicKey.fromCompressed(publicKeyCompressed);
            assert.equal(
                publicKey.toPem(),
                "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEUpclctRl0BbUxQGIe43zA+7j7WAsBWse\nsJJg36DaCrKIdC9NyX2e22/ZRrq8AC/fsG8myvEXuUBe15J1dj/bHA==\n-----END PUBLIC KEY-----\n"
            );
        });
    });

    describe("#testFromCompressedOdd()", function () {
        it("should recover public key from odd compressed form", function () {
            let publicKeyCompressed = "0318ed2e1ec629e2d3dae7be1103d4f911c24e0c80e70038f5eb5548245c475f50";
            let publicKey = PublicKey.fromCompressed(publicKeyCompressed);
            assert.equal(
                publicKey.toPem(),
                "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEGO0uHsYp4tPa574RA9T5EcJODIDnADj1\n61VIJFxHX1BMIg0B4cpBnLG6SzOTthXpndIKpr8HEHj3D9lJAI50EQ==\n-----END PUBLIC KEY-----\n"
            );
        });
    });

    describe("#testToCompressedEven()", function () {
        it("should produce even compressed form", function () {
            let publicKey = PublicKey.fromPem("-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEUpclctRl0BbUxQGIe43zA+7j7WAsBWse\nsJJg36DaCrKIdC9NyX2e22/ZRrq8AC/fsG8myvEXuUBe15J1dj/bHA==\n-----END PUBLIC KEY-----");
            let publicKeyCompressed = publicKey.toCompressed();
            assert.equal(publicKeyCompressed, "0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2");
        });
    });

    describe("#testToCompressedOdd()", function () {
        it("should produce odd compressed form", function () {
            let publicKey = PublicKey.fromPem("-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEGO0uHsYp4tPa574RA9T5EcJODIDnADj1\n61VIJFxHX1BMIg0B4cpBnLG6SzOTthXpndIKpr8HEHj3D9lJAI50EQ==\n-----END PUBLIC KEY-----");
            let publicKeyCompressed = publicKey.toCompressed();
            assert.equal(publicKeyCompressed, "0318ed2e1ec629e2d3dae7be1103d4f911c24e0c80e70038f5eb5548245c475f50");
        });
    });
});
