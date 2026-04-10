const assert = require("assert");
const BigInt = require("big-integer");

const Ecdsa = require("../ellipticcurve/ecdsa");
const PrivateKey = require("../ellipticcurve/privateKey").PrivateKey;
const PublicKey = require("../ellipticcurve/publicKey").PublicKey;
const Signature = require("../ellipticcurve/signature").Signature;
const Point = require("../ellipticcurve/point").Point;
const EcdsaMath = require("../ellipticcurve/math");
const EcdsaCurve = require("../ellipticcurve/curve");

let secp256k1 = EcdsaCurve.secp256k1;
let prime256v1 = EcdsaCurve.prime256v1;


describe("Rfc6979KnownAnswerTest", function () {
    // Test vectors from RFC 6979 Appendix A.2.5 (prime256v1/SHA-256).
    // The r values match the RFC exactly; s values are low-S normalized
    // (s = N - s when RFC s > N/2).
    let privateKey, publicKey;

    before(function () {
        privateKey = new PrivateKey(
            prime256v1,
            BigInt("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", 16),
        );
        publicKey = privateKey.publicKey();
    });

    describe("#testPublicKeyMatchesRfc()", function () {
        it("should match RFC public key coordinates", function () {
            assert.equal(
                publicKey.point.x.toString(16),
                BigInt("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6", 16).toString(16),
            );
            assert.equal(
                publicKey.point.y.toString(16),
                BigInt("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299", 16).toString(16),
            );
        });
    });

    describe("#testSampleMessageSignature()", function () {
        it("should produce correct 'sample' message signature", function () {
            let sig = Ecdsa.sign("sample", privateKey);
            // r matches RFC 6979 A.2.5 exactly
            assert.equal(
                sig.r.toString(16),
                BigInt("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716", 16).toString(16),
            );
            // s is low-S normalized
            assert.equal(
                sig.s.toString(16),
                BigInt("834E36AD29A83BF2BC9385E491D6099C8FDF9D1ED67AA7EA5F51F93782857A9", 16).toString(16),
            );
            assert.equal(Ecdsa.verify("sample", sig, publicKey), true);
        });
    });

    describe("#testTestMessageSignature()", function () {
        it("should produce correct 'test' message signature", function () {
            let sig = Ecdsa.sign("test", privateKey);
            // r matches RFC 6979 A.2.5 exactly
            assert.equal(
                sig.r.toString(16),
                BigInt("F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367", 16).toString(16),
            );
            // s already low-S, matches RFC directly
            assert.equal(
                sig.s.toString(16),
                BigInt("019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083", 16).toString(16),
            );
            assert.equal(Ecdsa.verify("test", sig, publicKey), true);
        });
    });
});


describe("Secp256k1KnownAnswerTest", function () {
    // Known-answer tests for secp256k1 with secret=1 (pubkey = generator G).
    let privateKey, publicKey;

    before(function () {
        privateKey = new PrivateKey(secp256k1, BigInt(1));
        publicKey = privateKey.publicKey();
    });

    describe("#testPublicKeyIsGenerator()", function () {
        it("should have public key equal to generator", function () {
            assert.equal(publicKey.point.x.toString(16), secp256k1.G.x.toString(16));
            assert.equal(publicKey.point.y.toString(16), secp256k1.G.y.toString(16));
        });
    });

    describe("#testSampleMessageSignature()", function () {
        it("should produce correct 'sample' message signature", function () {
            let sig = Ecdsa.sign("sample", privateKey);
            assert.equal(
                sig.r.toString(16),
                BigInt("58DB657BCD631038BEA07B4941172F0167ACA98F12B55E3176BD1C35435D6501", 16).toString(16),
            );
            assert.equal(
                sig.s.toString(16),
                BigInt("3A78E73D8FF8AB554E13C10F6390D81A882F91945D6275493882676170B53A57", 16).toString(16),
            );
            assert.equal(Ecdsa.verify("sample", sig, publicKey), true);
        });
    });

    describe("#testTestMessageSignature()", function () {
        it("should produce correct 'test' message signature", function () {
            let sig = Ecdsa.sign("test", privateKey);
            assert.equal(
                sig.r.toString(16),
                BigInt("98DF3AAED18D1299109E9732E3015F7E68E5D1FDEAD6924809B410D970A3B0CE", 16).toString(16),
            );
            assert.equal(
                sig.s.toString(16),
                BigInt("3EF15987C6592379BAAD6392586A382D63952572632FCD951AE75E7471C144C6", 16).toString(16),
            );
            assert.equal(Ecdsa.verify("test", sig, publicKey), true);
        });
    });
});


describe("MalleabilityTest", function () {

    describe("#testSignAlwaysProducesLowS()", function () {
        it("should always produce low-S signatures", function () {
            this.timeout(30000);
            for (let i = 0; i < 100; i++) {
                let privateKey = new PrivateKey();
                let signature = Ecdsa.sign("test message", privateKey);
                assert.ok(signature.s.lesserOrEquals(privateKey.curve.N.over(2)));
            }
        });
    });

    describe("#testHighSSignatureStillVerifies()", function () {
        it("verify() accepts high-s for OpenSSL compatibility; sign() prevents malleability", function () {
            let privateKey = new PrivateKey();
            let publicKey = privateKey.publicKey();
            let message = "test message";

            let signature = Ecdsa.sign(message, privateKey);
            let highS = new Signature(signature.r, privateKey.curve.N.minus(signature.s));

            assert.equal(Ecdsa.verify(message, signature, publicKey), true);
            assert.equal(Ecdsa.verify(message, highS, publicKey), true);
        });
    });
});


describe("PublicKeyValidationTest", function () {

    describe("#testRejectOffCurvePublicKey()", function () {
        it("should reject off-curve public key in verify", function () {
            let privateKey = new PrivateKey();
            let publicKey = privateKey.publicKey();
            let message = "test message";

            let signature = Ecdsa.sign(message, privateKey);

            let offCurvePoint = new Point(publicKey.point.x, publicKey.point.y.add(1));
            let offCurveKey = new PublicKey(offCurvePoint, publicKey.curve);

            assert.equal(Ecdsa.verify(message, signature, offCurveKey), false);
        });
    });

    describe("#testFromStringRejectsOffCurvePoint()", function () {
        it("should reject off-curve point in fromString", function () {
            let p = new PrivateKey().publicKey();
            let badY = p.point.y.add(1).toString(16).padStart(2 * p.curve.length(), "0");
            let badHex = p.point.x.toString(16).padStart(2 * p.curve.length(), "0") + badY;
            let badString = Buffer.from(badHex, "hex").toString("binary");
            assert.throws(function () {
                PublicKey.fromString(badString, p.curve);
            });
        });
    });

    describe("#testFromStringRejectsInfinityPoint()", function () {
        it("should reject infinity point in fromString", function () {
            let zeroHex = "00".repeat(2 * secp256k1.length());
            let zeroString = Buffer.from(zeroHex, "hex").toString("binary");
            assert.throws(function () {
                PublicKey.fromString(zeroString, secp256k1);
            });
        });
    });
});


describe("ForgeryAttemptTest", function () {
    let privateKey, publicKey, message, signature;

    before(function () {
        privateKey = new PrivateKey();
        publicKey = privateKey.publicKey();
        message = "authentic message";
        signature = Ecdsa.sign(message, privateKey);
    });

    describe("#testRejectZeroSignature()", function () {
        it("should reject zero signature", function () {
            assert.equal(Ecdsa.verify(message, new Signature(BigInt(0), BigInt(0)), publicKey), false);
        });
    });

    describe("#testRejectREqualsZero()", function () {
        it("should reject r=0", function () {
            assert.equal(Ecdsa.verify(message, new Signature(BigInt(0), signature.s), publicKey), false);
        });
    });

    describe("#testRejectSEqualsZero()", function () {
        it("should reject s=0", function () {
            assert.equal(Ecdsa.verify(message, new Signature(signature.r, BigInt(0)), publicKey), false);
        });
    });

    describe("#testRejectREqualsN()", function () {
        it("should reject r=N", function () {
            let N = publicKey.curve.N;
            assert.equal(Ecdsa.verify(message, new Signature(N, signature.s), publicKey), false);
        });
    });

    describe("#testRejectSEqualsN()", function () {
        it("should reject s=N", function () {
            let N = publicKey.curve.N;
            assert.equal(Ecdsa.verify(message, new Signature(signature.r, N), publicKey), false);
        });
    });

    describe("#testRejectRExceedsN()", function () {
        it("should reject r>N", function () {
            let N = publicKey.curve.N;
            assert.equal(Ecdsa.verify(message, new Signature(N.add(1), signature.s), publicKey), false);
        });
    });

    describe("#testRejectArbitrarySignature()", function () {
        it("should reject arbitrary signature", function () {
            assert.equal(Ecdsa.verify(message, new Signature(BigInt(1), BigInt(1)), publicKey), false);
        });
    });

    describe("#testRejectBoundarySignature()", function () {
        it("should reject boundary signature (N-1, N-1)", function () {
            let N = publicKey.curve.N;
            assert.equal(Ecdsa.verify(message, new Signature(N.minus(1), N.minus(1)), publicKey), false);
        });
    });

    describe("#testWrongKeyRejected()", function () {
        it("should reject wrong key", function () {
            let otherKey = new PrivateKey().publicKey();
            assert.equal(Ecdsa.verify(message, signature, otherKey), false);
        });
    });
});


describe("Rfc6979Test", function () {

    describe("#testDeterministicSignature()", function () {
        it("should produce deterministic signatures", function () {
            let privateKey = new PrivateKey();
            let message = "test message";

            let signature1 = Ecdsa.sign(message, privateKey);
            let signature2 = Ecdsa.sign(message, privateKey);

            assert.equal(signature1.r.toString(16), signature2.r.toString(16));
            assert.equal(signature1.s.toString(16), signature2.s.toString(16));
        });
    });

    describe("#testDifferentMessagesDifferentSignatures()", function () {
        it("should produce different signatures for different messages", function () {
            let privateKey = new PrivateKey();

            let signature1 = Ecdsa.sign("message 1", privateKey);
            let signature2 = Ecdsa.sign("message 2", privateKey);

            assert.ok(!signature1.r.eq(signature2.r) || !signature1.s.eq(signature2.s));
        });
    });

    describe("#testDifferentKeysDifferentSignatures()", function () {
        it("should produce different signatures for different keys", function () {
            let message = "test message";

            let signature1 = Ecdsa.sign(message, new PrivateKey());
            let signature2 = Ecdsa.sign(message, new PrivateKey());

            assert.ok(!signature1.r.eq(signature2.r) || !signature1.s.eq(signature2.s));
        });
    });
});


describe("EdgeCaseMessageTest", function () {
    let privateKey, publicKey;

    before(function () {
        privateKey = new PrivateKey();
        publicKey = privateKey.publicKey();
    });

    function signAndVerify(message) {
        let sig = Ecdsa.sign(message, privateKey);
        assert.equal(Ecdsa.verify(message, sig, publicKey), true);
        assert.equal(Ecdsa.verify(message + "x", sig, publicKey), false);
    }

    describe("#testEmptyMessage()", function () {
        it("should handle empty message", function () { signAndVerify(""); });
    });

    describe("#testSingleCharMessage()", function () {
        it("should handle single char message", function () { signAndVerify("a"); });
    });

    describe("#testUnicodeMessage()", function () {
        it("should handle unicode message", function () { signAndVerify("\u00e9\u00e8\u00ea\u00eb"); });
    });

    describe("#testEmojiMessage()", function () {
        it("should handle emoji message", function () { signAndVerify("\u{1f512}\u{1f511}"); });
    });

    describe("#testNullByteMessage()", function () {
        it("should handle null byte message", function () { signAndVerify("before\x00after"); });
    });

    describe("#testLongMessage()", function () {
        it("should handle long message", function () { signAndVerify("a".repeat(10000)); });
    });

    describe("#testNewlinesAndWhitespace()", function () {
        it("should handle newlines and whitespace", function () { signAndVerify("  line1\n\tline2\r\n  "); });
    });
});


describe("SerializationRoundTripTest", function () {
    let privateKey, publicKey, message, signature;

    before(function () {
        privateKey = new PrivateKey();
        publicKey = privateKey.publicKey();
        message = "round-trip test";
        signature = Ecdsa.sign(message, privateKey);
    });

    describe("#testSignatureDerRoundTrip()", function () {
        it("should round-trip signature through DER", function () {
            let der = signature.toDer();
            let restored = Signature.fromDer(der);
            assert.equal(restored.r.toString(16), signature.r.toString(16));
            assert.equal(restored.s.toString(16), signature.s.toString(16));
            assert.equal(Ecdsa.verify(message, restored, publicKey), true);
        });
    });

    describe("#testSignatureBase64RoundTrip()", function () {
        it("should round-trip signature through Base64", function () {
            let b64 = signature.toBase64();
            let restored = Signature.fromBase64(b64);
            assert.equal(restored.r.toString(16), signature.r.toString(16));
            assert.equal(restored.s.toString(16), signature.s.toString(16));
            assert.equal(Ecdsa.verify(message, restored, publicKey), true);
        });
    });

    describe("#testSignatureDerWithRecoveryIdRoundTrip()", function () {
        it("should round-trip DER with recovery ID", function () {
            let der = signature.toDer(true);
            let restored = Signature.fromDer(der, true);
            assert.equal(restored.r.toString(16), signature.r.toString(16));
            assert.equal(restored.s.toString(16), signature.s.toString(16));
            assert.equal(restored.recoveryId, signature.recoveryId);
        });
    });

    describe("#testPrivateKeyPemRoundTrip()", function () {
        it("should round-trip private key through PEM", function () {
            let pem = privateKey.toPem();
            let restored = PrivateKey.fromPem(pem);
            assert.equal(restored.secret.toString(16), privateKey.secret.toString(16));
            assert.equal(restored.curve.name, privateKey.curve.name);
        });
    });

    describe("#testPrivateKeyDerRoundTrip()", function () {
        it("should round-trip private key through DER", function () {
            let der = privateKey.toDer();
            let restored = PrivateKey.fromDer(der);
            assert.equal(restored.secret.toString(16), privateKey.secret.toString(16));
        });
    });

    describe("#testPublicKeyPemRoundTrip()", function () {
        it("should round-trip public key through PEM", function () {
            let pem = publicKey.toPem();
            let restored = PublicKey.fromPem(pem);
            assert.equal(restored.point.x.toString(16), publicKey.point.x.toString(16));
            assert.equal(restored.point.y.toString(16), publicKey.point.y.toString(16));
        });
    });

    describe("#testPublicKeyCompressedRoundTrip()", function () {
        it("should round-trip public key through compressed form", function () {
            let compressed = publicKey.toCompressed();
            let restored = PublicKey.fromCompressed(compressed, publicKey.curve);
            assert.equal(restored.point.x.toString(16), publicKey.point.x.toString(16));
            assert.equal(restored.point.y.toString(16), publicKey.point.y.toString(16));
            assert.equal(Ecdsa.verify(message, signature, restored), true);
        });
    });

    describe("#testPublicKeyCompressedEvenAndOdd()", function () {
        it("should round-trip both even-y and odd-y keys through compression", function () {
            for (let i = 0; i < 20; i++) {
                let pk = new PrivateKey();
                let pub = pk.publicKey();
                let compressed = pub.toCompressed();
                let restored = PublicKey.fromCompressed(compressed, pub.curve);
                assert.equal(restored.point.x.toString(16), pub.point.x.toString(16));
                assert.equal(restored.point.y.toString(16), pub.point.y.toString(16));
            }
        });
    });

    describe("#testPrime256v1KeyRoundTrip()", function () {
        it("should round-trip prime256v1 private key through PEM", function () {
            let pk = new PrivateKey(prime256v1);
            let pem = pk.toPem();
            let restored = PrivateKey.fromPem(pem);
            assert.equal(restored.secret.toString(16), pk.secret.toString(16));
            assert.equal(restored.curve.name, "prime256v1");
        });
    });
});


describe("TonelliShanksTest", function () {

    describe("#testPrimeCongruent1Mod4()", function () {
        it("P=17: exercises full Tonelli-Shanks (S=4)", function () {
            let P = BigInt(17);
            for (let v = 1; v < 17; v++) {
                let value = BigInt(v);
                if (value.modPow(P.minus(1).over(2), P).eq(1)) {
                    let root = EcdsaMath.modularSquareRoot(value, P);
                    assert.ok(root.multiply(root).mod(P).eq(value));
                }
            }
        });
    });

    describe("#testPrimeCongruent5Mod8()", function () {
        it("P=13: exercises S=2 path", function () {
            let P = BigInt(13);
            for (let v = 1; v < 13; v++) {
                let value = BigInt(v);
                if (value.modPow(P.minus(1).over(2), P).eq(1)) {
                    let root = EcdsaMath.modularSquareRoot(value, P);
                    assert.ok(root.multiply(root).mod(P).eq(value));
                }
            }
        });
    });

    describe("#testPrimeCongruent3Mod4()", function () {
        it("P=7: fast path (S=1)", function () {
            let P = BigInt(7);
            for (let v = 1; v < 7; v++) {
                let value = BigInt(v);
                if (value.modPow(P.minus(1).over(2), P).eq(1)) {
                    let root = EcdsaMath.modularSquareRoot(value, P);
                    assert.ok(root.multiply(root).mod(P).eq(value));
                }
            }
        });
    });

    describe("#testZeroValue()", function () {
        it("should return 0 for value 0", function () {
            assert.ok(EcdsaMath.modularSquareRoot(BigInt(0), BigInt(17)).eq(0));
        });
    });
});


describe("HashTruncationTest", function () {

    describe("#testSignVerifyWithSha512()", function () {
        it("should sign and verify with sha512", function () {
            let privateKey = new PrivateKey();
            let publicKey = privateKey.publicKey();
            let message = "test message";

            let signature = Ecdsa.sign(message, privateKey, "sha512");

            assert.equal(Ecdsa.verify(message, signature, publicKey, "sha512"), true);
            assert.equal(Ecdsa.verify("wrong message", signature, publicKey, "sha512"), false);
        });
    });

    describe("#testSha512DeterministicSignature()", function () {
        it("should produce deterministic sha512 signatures", function () {
            let privateKey = new PrivateKey();
            let message = "test message";

            let signature1 = Ecdsa.sign(message, privateKey, "sha512");
            let signature2 = Ecdsa.sign(message, privateKey, "sha512");

            assert.equal(signature1.r.toString(16), signature2.r.toString(16));
            assert.equal(signature1.s.toString(16), signature2.s.toString(16));
        });
    });

    describe("#testHashMismatchFails()", function () {
        it("should fail when hash functions mismatch", function () {
            let privateKey = new PrivateKey();
            let publicKey = privateKey.publicKey();
            let message = "test message";

            let signature = Ecdsa.sign(message, privateKey, "sha256");
            assert.equal(Ecdsa.verify(message, signature, publicKey, "sha512"), false);
        });
    });
});


describe("Prime256v1SecurityTest", function () {

    describe("#testSignVerify()", function () {
        it("should sign and verify", function () {
            let privateKey = new PrivateKey(prime256v1);
            let publicKey = privateKey.publicKey();
            let message = "test message";

            let signature = Ecdsa.sign(message, privateKey);

            assert.ok(signature.s.lesserOrEquals(prime256v1.N.over(2)));
            assert.equal(Ecdsa.verify(message, signature, publicKey), true);
        });
    });

    describe("#testDeterministicSignature()", function () {
        it("should produce deterministic signatures", function () {
            let privateKey = new PrivateKey(prime256v1);
            let message = "test message";

            let signature1 = Ecdsa.sign(message, privateKey);
            let signature2 = Ecdsa.sign(message, privateKey);

            assert.equal(signature1.r.toString(16), signature2.r.toString(16));
            assert.equal(signature1.s.toString(16), signature2.s.toString(16));
        });
    });

    describe("#testWrongCurveKeyFails()", function () {
        it("a signature made with secp256k1 should not verify with a prime256v1 key", function () {
            let k1Key = new PrivateKey(secp256k1);
            let p256Key = new PrivateKey(prime256v1);
            let message = "cross-curve test";

            let sig = Ecdsa.sign(message, k1Key);
            assert.equal(Ecdsa.verify(message, sig, p256Key.publicKey()), false);
        });
    });
});
