const Point = require("./point").Point;
const modulo = require("./utils/integer").modulo;
const BigInt = require("big-integer");


class Math {

    static modularSquareRoot(value, prime) {
        // Tonelli-Shanks algorithm for modular square root. Works for all odd primes.

        if (value.eq(0)) {
            return BigInt(0);
        }
        if (prime.eq(2)) {
            return modulo(value, BigInt(2));
        }

        // Factor out powers of 2: prime - 1 = Q * 2^S
        let Q = prime.minus(1);
        let S = 0;
        while (Q.mod(2).eq(0)) {
            Q = Q.over(2);
            S += 1;
        }

        if (S === 1) {  // prime = 3 (mod 4)
            return value.modPow(prime.add(1).over(4), prime);
        }

        // Find a quadratic non-residue z
        let z = BigInt(2);
        while (!z.modPow(prime.minus(1).over(2), prime).eq(prime.minus(1))) {
            z = z.add(1);
        }

        let M = S;
        let c = z.modPow(Q, prime);
        let t = value.modPow(Q, prime);
        let R = value.modPow(Q.add(1).over(2), prime);

        while (true) {
            if (t.eq(1)) {
                return R;
            }

            // Find the least i such that t^(2^i) = 1 (mod prime)
            let i = 1;
            let temp = modulo(t.multiply(t), prime);
            while (!temp.eq(1)) {
                temp = modulo(temp.multiply(temp), prime);
                i += 1;
            }

            let b = c.modPow(BigInt(1).shiftLeft(M - i - 1), prime);
            M = i;
            c = modulo(b.multiply(b), prime);
            t = modulo(t.multiply(c), prime);
            R = modulo(R.multiply(b), prime);
        }
    }

    static multiply(p, n, N, A, P) {
        // Fast way to multiply point and scalar in elliptic curves

        // :param p: First Point to multiply
        // :param n: Scalar to multiply
        // :param N: Order of the elliptic curve
        // :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
        // :param A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
        // :return: Point that represents the scalar multiplication

        return this._fromJacobian(
            this._jacobianMultiply(this._toJacobian(p), n, N, A, P), P
        );
    }

    static add(p, q, A, P) {
        // Fast way to add two points in elliptic curves

        // :param p: First Point you want to add
        // :param q: Second Point you want to add
        // :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
        // :param A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
        // :return: Point that represents the sum of First and Second Point

        return this._fromJacobian(
            this._jacobianAdd(this._toJacobian(p), this._toJacobian(q), A, P), P,
        );
    }

    static multiplyAndAdd(p1, n1, p2, n2, N, A, P) {
        // Compute n1*p1 + n2*p2 using Shamir's trick (simultaneous double-and-add).
        // Not constant-time — use only with public scalars (e.g. verification).

        // :param p1: First point
        // :param n1: First scalar
        // :param p2: Second point
        // :param n2: Second scalar
        // :param N: Order of the elliptic curve
        // :param A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
        // :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
        // :return: Point n1*p1 + n2*p2

        return this._fromJacobian(
            this._shamirMultiply(
                this._toJacobian(p1), n1,
                this._toJacobian(p2), n2,
                N, A, P,
            ), P,
        );
    }

    static inv(x, n) {
        // Modular inverse using Fermat's little theorem: x^(n-2) mod n.
        // Requires n to be prime (true for all ECDSA curve parameters).
        // Uses modPow which has more uniform execution time
        // than the extended Euclidean algorithm.

        // :param x: Divisor
        // :param n: Mod for division (must be prime)
        // :return: Value representing the division

        if (x.eq(0)) {
            return BigInt(0);
        }

        return x.modPow(n.minus(2), n);
    }

    static _toJacobian(p) {
        // Convert point to Jacobian coordinates

        // :param p: First Point you want to add
        // :return: Point in Jacobian coordinates

        return new Point(p.x, p.y, BigInt(1));
    }

    static _fromJacobian(p, P) {
        // Convert point back from Jacobian coordinates

        // :param p: First Point you want to add
        // :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
        // :return: Point in default coordinates

        if (p.y.eq(0)) {
            return new Point(BigInt(0), BigInt(0), BigInt(0));
        }

        let z = this.inv(p.z, P);
        let z2 = modulo(z.multiply(z), P);
        let z3 = modulo(z2.multiply(z), P);

        return new Point(
            modulo(p.x.multiply(z2), P),
            modulo(p.y.multiply(z3), P)
        );
    }

    static _jacobianDouble(p, A, P) {
        // Double a point in elliptic curves

        // :param p: Point you want to double
        // :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
        // :param A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
        // :return: Point that represents the sum of First and Second Point

        let py = p.y;
        if (py.eq(0)) {
            return new Point(BigInt(0), BigInt(0), BigInt(0));
        }

        let px = p.x;
        let pz = p.z;
        let ysq = modulo(py.multiply(py), P);
        let S = modulo(px.multiply(ysq).multiply(4), P);
        let pz2 = modulo(pz.multiply(pz), P);
        let M = modulo(px.multiply(px).multiply(3).add(A.multiply(pz2).multiply(pz2)), P);
        let nx = modulo(M.multiply(M).minus(S.multiply(2)), P);
        let ny = modulo(M.multiply(S.minus(nx)).minus(ysq.multiply(ysq).multiply(8)), P);
        let nz = modulo(py.multiply(pz).multiply(2), P);

        return new Point(nx, ny, nz);
    }

    static _jacobianAdd(p, q, A, P) {
        // Add two points in elliptic curves

        // :param p: First Point you want to add
        // :param q: Second Point you want to add
        // :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
        // :param A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
        // :return: Point that represents the sum of First and Second Point

        if (p.y.eq(0)) {
            return q;
        }
        if (q.y.eq(0)) {
            return p;
        }

        let px = p.x, py = p.y, pz = p.z;
        let qx = q.x, qy = q.y, qz = q.z;

        let qz2 = modulo(qz.multiply(qz), P);
        let pz2 = modulo(pz.multiply(pz), P);
        let U1 = modulo(px.multiply(qz2), P);
        let U2 = modulo(qx.multiply(pz2), P);
        let S1 = modulo(py.multiply(qz2).multiply(qz), P);
        let S2 = modulo(qy.multiply(pz2).multiply(pz), P);

        if (U1.eq(U2)) {
            if (S1.neq(S2)) {
                return new Point(BigInt(0), BigInt(0), BigInt(1));
            }
            return this._jacobianDouble(p, A, P);
        }

        let H = U2.minus(U1);
        let R = S2.minus(S1);
        let H2 = modulo(H.multiply(H), P);
        let H3 = modulo(H.multiply(H2), P);
        let U1H2 = modulo(U1.multiply(H2), P);
        let nx = modulo(R.multiply(R).minus(H3).minus(U1H2.multiply(2)), P);
        let ny = modulo(R.multiply(U1H2.minus(nx)).minus(S1.multiply(H3)), P);
        let nz = modulo(H.multiply(pz).multiply(qz), P);

        return new Point(nx, ny, nz);
    }

    static _jacobianMultiply(p, n, N, A, P) {
        // Multiply point and scalar in elliptic curves using Montgomery ladder
        // for constant-time execution.

        // :param p: First Point to multiply
        // :param n: Scalar to multiply
        // :param N: Order of the elliptic curve
        // :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
        // :param A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
        // :return: Point that represents the scalar multiplication

        if (p.y.eq(0) || n.eq(0)) {
            return new Point(BigInt(0), BigInt(0), BigInt(1));
        }

        if (n.lesser(0) || n.greaterOrEquals(N)) {
            n = modulo(n, N);
        }

        if (n.eq(0)) {
            return new Point(BigInt(0), BigInt(0), BigInt(1));
        }

        // Montgomery ladder: always performs one add and one double per bit
        let r0 = new Point(BigInt(0), BigInt(0), BigInt(1));
        let r1 = new Point(p.x, p.y, p.z);

        let bitLen = n.bitLength().toJSNumber();
        for (let i = bitLen - 1; i >= 0; i--) {
            if (n.shiftRight(i).and(1).eq(0)) {
                r1 = this._jacobianAdd(r0, r1, A, P);
                r0 = this._jacobianDouble(r0, A, P);
            } else {
                r0 = this._jacobianAdd(r0, r1, A, P);
                r1 = this._jacobianDouble(r1, A, P);
            }
        }

        return r0;
    }

    static _shamirMultiply(jp1, n1, jp2, n2, N, A, P) {
        // Compute n1*p1 + n2*p2 using Shamir's trick (simultaneous double-and-add).
        // Not constant-time — use only with public scalars (e.g. verification).

        // :param jp1: First point in Jacobian coordinates
        // :param n1: First scalar
        // :param jp2: Second point in Jacobian coordinates
        // :param n2: Second scalar
        // :param N: Order of the elliptic curve
        // :param A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
        // :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
        // :return: Point n1*p1 + n2*p2 in Jacobian coordinates

        if (n1.lesser(0) || n1.greaterOrEquals(N)) {
            n1 = modulo(n1, N);
        }
        if (n2.lesser(0) || n2.greaterOrEquals(N)) {
            n2 = modulo(n2, N);
        }

        let jp1p2 = this._jacobianAdd(jp1, jp2, A, P);

        let l = global.Math.max(n1.bitLength().toJSNumber(), n2.bitLength().toJSNumber());
        let r = new Point(BigInt(0), BigInt(0), BigInt(1));

        for (let i = l - 1; i >= 0; i--) {
            r = this._jacobianDouble(r, A, P);
            let b1 = n1.shiftRight(i).and(1).toJSNumber();
            let b2 = n2.shiftRight(i).and(1).toJSNumber();
            if (b1) {
                r = this._jacobianAdd(r, b2 ? jp1p2 : jp1, A, P);
            } else if (b2) {
                r = this._jacobianAdd(r, jp2, A, P);
            }
        }

        return r;
    }
}


module.exports = Math;
