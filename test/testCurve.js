const assert = require("assert");
const BigInt = require("big-integer");

const curve = require("../ellipticcurve/curve");
const Ecdsa = require("../ellipticcurve/ecdsa");
const PrivateKey = require("../ellipticcurve/privateKey").PrivateKey;
const PublicKey = require("../ellipticcurve/publicKey").PublicKey;
const Signature = require("../ellipticcurve/signature").Signature;


describe("CurveTest", function () {

    describe("#testSupportedCurve()", function () {
        it("should sign and verify with a re-created secp256k1 curve", function () {
            let newCurve = new curve.CurveFp(
                BigInt("0000000000000000000000000000000000000000000000000000000000000000", 16),
                BigInt("0000000000000000000000000000000000000000000000000000000000000007", 16),
                BigInt("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16),
                BigInt("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16),
                BigInt("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16),
                BigInt("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16),
                "secp256k1",
                [1, 3, 132, 0, 10]
            );

            let privateKey1 = new PrivateKey(newCurve);
            let publicKey1 = privateKey1.publicKey();

            let privateKeyPem = privateKey1.toPem();
            let publicKeyPem = publicKey1.toPem();

            let privateKey2 = PrivateKey.fromPem(privateKeyPem);
            let publicKey2 = PublicKey.fromPem(publicKeyPem);

            let message = "test";

            let signatureBase64 = Ecdsa.sign(message, privateKey2).toBase64();
            let signature = Signature.fromBase64(signatureBase64);

            assert.equal(Ecdsa.verify(message, signature, publicKey2), true);
        });
    });

    describe("#testAddNewCurve()", function () {
        it("should sign and verify with a new registered curve (frp256v1)", function () {
            let newCurve = new curve.CurveFp(
                BigInt("f1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c00", 16),
                BigInt("ee353fca5428a9300d4aba754a44c00fdfec0c9ae4b1a1803075ed967b7bb73f", 16),
                BigInt("f1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c03", 16),
                BigInt("f1fd178c0b3ad58f10126de8ce42435b53dc67e140d2bf941ffdd459c6d655e1", 16),
                BigInt("b6b3d4c356c139eb31183d4749d423958c27d2dcaf98b70164c97a2dd98f5cff", 16),
                BigInt("6142e0f7c8b204911f9271f0f3ecef8c2701c307e8e4c9e183115a1554062cfb", 16),
                "frp256v1",
                [1, 2, 250, 1, 223, 101, 256, 1]
            );
            curve.add(newCurve);

            let privateKey1 = new PrivateKey(newCurve);
            let publicKey1 = privateKey1.publicKey();

            let privateKeyPem = privateKey1.toPem();
            let publicKeyPem = publicKey1.toPem();

            let privateKey2 = PrivateKey.fromPem(privateKeyPem);
            let publicKey2 = PublicKey.fromPem(publicKeyPem);

            let message = "test";

            let signatureBase64 = Ecdsa.sign(message, privateKey2).toBase64();
            let signature = Signature.fromBase64(signatureBase64);

            assert.equal(Ecdsa.verify(message, signature, publicKey2), true);
        });
    });

    describe("#testUnsupportedCurve()", function () {
        it("should raise error for unregistered curve on PEM import", function () {
            let newCurve = new curve.CurveFp(
                BigInt("a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5374", 16),
                BigInt("662c61c430d84ea4fe66a7733d0b76b7bf93ebc4af2f49256ae58101fee92b04", 16),
                BigInt("a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377", 16),
                BigInt("a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7", 16),
                BigInt("a3e8eb3cc1cfe7b7732213b23a656149afa142c47aafbc2b79a191562e1305f4", 16),
                BigInt("2d996c823439c56d7f7b22e14644417e69bcb6de39d027001dabe8f35b25c9be", 16),
                "brainpoolP256t1",
                [1, 3, 36, 3, 3, 2, 8, 1, 1, 8]
            );

            let privateKeyPem = new PrivateKey(newCurve).toPem();
            let publicKeyPem = new PrivateKey(newCurve).publicKey().toPem();

            assert.throws(function () {
                PrivateKey.fromPem(privateKeyPem);
            }, /Unknown curve/);

            assert.throws(function () {
                PublicKey.fromPem(publicKeyPem);
            }, /Unknown curve/);
        });
    });
});
