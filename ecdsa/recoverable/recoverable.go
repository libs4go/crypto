package recoverable

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	"github.com/libs4go/crypto/ecdsa/rfc6979"
	ellipticx "github.com/libs4go/crypto/elliptic"
	"github.com/libs4go/errors"
)

func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}

func isEven(k *big.Int) bool {
	if k.Bit(0) == 0 {
		return true
	} else {
		return false
	}
}

// fastLucasSequence refer to https://en.wikipedia.org/wiki/Lucas_sequence
func fastLucasSequence(curveP, lucasParamP, lucasParamQ, k *big.Int) (*big.Int, *big.Int) {
	n := k.BitLen()
	s := getLowestSetBit(k)

	uh := big.NewInt(1)
	vl := big.NewInt(2)
	ql := big.NewInt(1)
	qh := big.NewInt(1)
	vh := big.NewInt(0).Set(lucasParamP)
	tmp := big.NewInt(0)

	for j := n - 1; j >= s+1; j-- {
		ql.Mul(ql, qh)
		ql.Mod(ql, curveP)

		if k.Bit(j) == 1 {
			qh.Mul(ql, lucasParamQ)
			qh.Mod(qh, curveP)

			uh.Mul(uh, vh)
			uh.Mod(uh, curveP)

			vl.Mul(vh, vl)
			tmp.Mul(lucasParamP, ql)
			vl.Sub(vl, tmp)
			vl.Mod(vl, curveP)

			vh.Mul(vh, vh)
			tmp.Lsh(qh, 1)
			vh.Sub(vh, tmp)
			vh.Mod(vh, curveP)
		} else {
			qh.Set(ql)

			uh.Mul(uh, vl)
			uh.Sub(uh, ql)
			uh.Mod(uh, curveP)

			vh.Mul(vh, vl)
			tmp.Mul(lucasParamP, ql)
			vh.Sub(vh, tmp)
			vh.Mod(vh, curveP)

			vl.Mul(vl, vl)
			tmp.Lsh(ql, 1)
			vl.Sub(vl, tmp)
			vl.Mod(vl, curveP)
		}
	}

	ql.Mul(ql, qh)
	ql.Mod(ql, curveP)

	qh.Mul(ql, lucasParamQ)
	qh.Mod(qh, curveP)

	uh.Mul(uh, vl)
	uh.Sub(uh, ql)
	uh.Mod(uh, curveP)

	vl.Mul(vh, vl)
	tmp.Mul(lucasParamP, ql)
	vl.Sub(vl, tmp)
	vl.Mod(vl, curveP)

	ql.Mul(ql, qh)
	ql.Mod(ql, curveP)

	for j := 1; j <= s; j++ {
		uh.Mul(uh, vl)
		uh.Mul(uh, curveP)

		vl.Mul(vl, vl)
		tmp.Lsh(ql, 1)
		vl.Sub(vl, tmp)
		vl.Mod(vl, curveP)

		ql.Mul(ql, ql)
		ql.Mod(ql, curveP)
	}

	return uh, vl
}

func getLowestSetBit(k *big.Int) int {
	i := 0
	for i = 0; k.Bit(i) != 1; i++ {
	}
	return i
}

// compute the coordinate of Y from Y**2
func curveSqrt(ySquare *big.Int, curve *elliptic.CurveParams) *big.Int {
	if curve.P.Bit(1) == 1 {
		tmp1 := big.NewInt(0)
		tmp1.Rsh(curve.P, 2)
		tmp1.Add(tmp1, big.NewInt(1))

		tmp2 := big.NewInt(0)
		tmp2.Exp(ySquare, tmp1, curve.P)

		tmp3 := big.NewInt(0)
		tmp3.Exp(tmp2, big.NewInt(2), curve.P)

		if 0 == tmp3.Cmp(ySquare) {
			return tmp2
		}
		return nil
	}

	qMinusOne := big.NewInt(0)
	qMinusOne.Sub(curve.P, big.NewInt(1))

	legendExponent := big.NewInt(0)
	legendExponent.Rsh(qMinusOne, 1)

	tmp4 := big.NewInt(0)
	tmp4.Exp(ySquare, legendExponent, curve.P)
	if 0 != tmp4.Cmp(big.NewInt(1)) {
		return nil
	}

	k := big.NewInt(0)
	k.Rsh(qMinusOne, 2)
	k.Lsh(k, 1)
	k.Add(k, big.NewInt(1))

	lucasParamQ := big.NewInt(0)
	lucasParamQ.Set(ySquare)
	fourQ := big.NewInt(0)
	fourQ.Lsh(lucasParamQ, 2)
	fourQ.Mod(fourQ, curve.P)

	seqU := big.NewInt(0)
	seqV := big.NewInt(0)

	for {
		lucasParamP := big.NewInt(0)
		for {
			tmp5 := big.NewInt(0)
			lucasParamP, _ = rand.Prime(rand.Reader, curve.P.BitLen())

			if lucasParamP.Cmp(curve.P) < 0 {
				tmp5.Mul(lucasParamP, lucasParamP)
				tmp5.Sub(tmp5, fourQ)
				tmp5.Exp(tmp5, legendExponent, curve.P)

				if 0 == tmp5.Cmp(qMinusOne) {
					break
				}
			}
		}

		seqU, seqV = fastLucasSequence(curve.P, lucasParamP, lucasParamQ, k)

		tmp6 := big.NewInt(0)
		tmp6.Mul(seqV, seqV)
		tmp6.Mod(tmp6, curve.P)
		if 0 == tmp6.Cmp(fourQ) {
			if 1 == seqV.Bit(0) {
				seqV.Add(seqV, curve.P)
			}
			seqV.Rsh(seqV, 1)
			return seqV
		}
		if (0 == seqU.Cmp(big.NewInt(1))) || (0 == seqU.Cmp(qMinusOne)) {
			break
		}
	}
	return nil
}

func decompressPoint(curve elliptic.Curve, xCoord *big.Int, yTilde int) (*big.Int, error) {

	curveParams := curve.Params()
	ySqare := big.NewInt(0)
	//x**2 + A
	ySqare.Exp(xCoord, big.NewInt(2), curveParams.P)
	if curveParams.Name != ellipticx.SECP256K1().Params().Name {
		//in secp256k1, A = 0
		//in others A = -3, there is no A's clear definition in the realization of p256.
		paramA := big.NewInt(-3)
		ySqare.Add(ySqare, paramA)
		ySqare.Mod(ySqare, curveParams.P)
	}
	//y**2 = x**3 + A*x +B
	ySqare.Mul(ySqare, xCoord)
	ySqare.Mod(ySqare, curveParams.P)
	ySqare.Add(ySqare, curveParams.B)
	ySqare.Mod(ySqare, curveParams.P)

	yValue := curveSqrt(ySqare, curveParams)
	if nil == yValue {
		return nil, errors.New("Invalid point compression")
	}

	yCoord := big.NewInt(0)
	if (isEven(yValue) && yTilde != 0) || (!isEven(yValue) && yTilde != 1) {
		yCoord.Sub(curveParams.P, yValue)
	} else {
		yCoord.Set(yValue)
	}

	return yCoord, nil
}

// ErrCurve .
var (
	ErrCurve  = errors.New("unsupport curve")
	ErrPubKey = errors.New("no valid solution for pubkey found")
)

// Cofactor elliptic.CurveParams extend interface
type Cofactor interface {
	H() int
}

// SignWithNonce .
func SignWithNonce(privateKey *ecdsa.PrivateKey, hash []byte, nonce int, compressed bool) (*big.Int, *big.Int, *big.Int, error) {

	H := 1

	cofactor, ok := privateKey.Curve.(Cofactor)

	if ok {
		H = cofactor.H()
	}

	r, s, err := rfc6979.SignWithNonce(privateKey, hash, nonce)

	if err != nil {
		return nil, nil, nil, err
	}

	curve := privateKey.Curve

	// bitcoind checks the bit length of R and S here. The ecdsa signature
	// algorithm returns R and S mod N therefore they will be the bitsize of
	// the curve, and thus correctly sized.
	for i := 0; i < (H+1)*2; i++ {
		pk, err := recoverKeyFromSignature(curve, r, s, hash, i, true)
		if err == nil && pk.X.Cmp(privateKey.X) == 0 && pk.Y.Cmp(privateKey.Y) == 0 {

			v := 27 + byte(i)
			if compressed {
				v += 4
			}

			return r, s, new(big.Int).SetBytes([]byte{v}), nil
		}
	}

	return nil, nil, nil, errors.Wrap(err, "can't find v for public key")
}

// Sign .
func Sign(privateKey *ecdsa.PrivateKey, hash []byte, compressed bool) (*big.Int, *big.Int, *big.Int, error) {
	return SignWithNonce(privateKey, hash, 0, compressed)
}

// RecoverWithNonce .
func RecoverWithNonce(curve elliptic.Curve, r, s, v *big.Int, hash []byte, nonce int) (*ecdsa.PublicKey, bool, error) {
	if nonce > 0 {
		moreHash := sha256.New()
		moreHash.Write(hash)
		moreHash.Write(bytes.Repeat([]byte{0x00}, nonce))
		hash = moreHash.Sum(nil)
	}

	vBytes := v.Bytes()

	iteration := int((vBytes[0] - 27) & ^byte(4))

	// The iteration used here was encoded
	key, err := recoverKeyFromSignature(curve, r, s, hash, iteration, false)
	if err != nil {
		return nil, false, err
	}

	return key, ((vBytes[0] - 27) & 4) == 4, nil
}

// Recover recover public key from sig and hash
func Recover(curve elliptic.Curve, r, s, v *big.Int, hash []byte) (*ecdsa.PublicKey, bool, error) {
	return RecoverWithNonce(curve, r, s, v, hash, 0)
}

// hashToInt converts a hash value to an integer. There is some disagreement
// about how this is done. [NSA] suggests that this is done in the obvious
// manner, but [SECG] truncates the hash to the bit-length of the curve order
// first. We follow [SECG] because that's what OpenSSL does. Additionally,
// OpenSSL right shifts excess bits from the number if the hash is too large
// and we mirror that too.
// This is borrowed from crypto/ecdsa.
func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

// recoverKeyFromSignature recovers a public key from the signature "sig" on the
// given message hash "msg". Based on the algorithm found in section 5.1.5 of
// SEC 1 Ver 2.0, page 47-48 (53 and 54 in the pdf). This performs the details
// in the inner loop in Step 1. The counter provided is actually the j parameter
// of the loop * 2 - on the first iteration of j we do the R case, else the -R
// case in step 1.6. This counter is used in the bitcoin compressed signature
// format and thus we match bitcoind's behaviour here.
func recoverKeyFromSignature(curve elliptic.Curve, r, s *big.Int, msg []byte,
	iter int, doChecks bool) (*ecdsa.PublicKey, error) {
	// 1.1 x = (n * i) + r
	Rx := new(big.Int).Mul(curve.Params().N,
		new(big.Int).SetInt64(int64(iter/2)))
	Rx.Add(Rx, r)
	if Rx.Cmp(curve.Params().P) != -1 {
		return nil, errors.New("calculated Rx is larger than curve P")
	}

	// convert 02<Rx> to point R. (step 1.2 and 1.3). If we are on an odd
	// iteration then 1.6 will be done with -R, so we calculate the other
	// term when uncompressing the point.
	Ry, err := decompressPoint(curve, Rx, iter)
	if err != nil {
		return nil, err
	}

	// 1.4 Check n*R is point at infinity
	if doChecks {
		nRx, nRy := curve.ScalarMult(Rx, Ry, curve.Params().N.Bytes())
		if nRx.Sign() != 0 || nRy.Sign() != 0 {
			return nil, errors.New("n*R does not equal the point at infinity")
		}
	}

	// 1.5 calculate e from message using the same algorithm as ecdsa
	// signature calculation.
	e := hashToInt(msg, curve)

	// Step 1.6.1:
	// We calculate the two terms sR and eG separately multiplied by the
	// inverse of r (from the signature). We then add them to calculate
	// Q = r^-1(sR-eG)
	invr := new(big.Int).ModInverse(r, curve.Params().N)

	// first term.
	invrS := new(big.Int).Mul(invr, s)
	invrS.Mod(invrS, curve.Params().N)
	sRx, sRy := curve.ScalarMult(Rx, Ry, invrS.Bytes())

	// second term.
	e.Neg(e)
	e.Mod(e, curve.Params().N)
	e.Mul(e, invr)
	e.Mod(e, curve.Params().N)
	minuseGx, minuseGy := curve.ScalarBaseMult(e.Bytes())

	// TODO: this would be faster if we did a mult and add in one
	// step to prevent the jacobian conversion back and forth.
	Qx, Qy := curve.Add(sRx, sRy, minuseGx, minuseGy)

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     Qx,
		Y:     Qy,
	}, nil
}
