package ecdsa

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/libs4go/crypto/ecdsa/recoverable"
	"github.com/libs4go/crypto/ecdsa/rfc6979"
)

// SignRF6979 Deterministic Signature see https://tools.ietf.org/html/rfc6979
var SignRFC6979 = rfc6979.Sign

var RecoverSign = recoverable.Sign

var Recover = recoverable.Recover

func Sig2Bytes(curve elliptic.Curve, r, s, v *big.Int) []byte {
	size := curve.Params().BitSize / 8

	buff := make([]byte, 2*size+1)

	rBytes := r.Bytes()

	if len(rBytes) > size {
		rBytes = rBytes[:size]
	}

	sBytes := s.Bytes()

	if len(sBytes) > size {
		sBytes = sBytes[:size]
	}

	copy(buff[size-len(rBytes):size], rBytes)
	copy(buff[2*size-len(sBytes):2*size], sBytes)
	buff[2*size] = v.Bytes()[0]

	return buff
}

func Bytes2Sig(curve elliptic.Curve, sig []byte) (r, s, v *big.Int, err error) {
	size := curve.Params().BitSize / 8

	if len(sig) != 2*size+1 {
		return nil, nil, nil, fmt.Errorf("sig len must be %d", 2*size+1)
	}

	return new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size : 2*size]), new(big.Int).SetBytes(sig[2*size:]), nil
}

func PublicKeyBytes(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}

	return elliptic.Marshal(pub.Curve, pub.X, pub.Y)
}

func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}

func paddedAppend(size uint, dst, src []byte) []byte {
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}

// CompressedPublicKeyBytes .
func CompressedPublicKeyBytes(pub *ecdsa.PublicKey) []byte {
	b := make([]byte, 0, 33)
	format := byte(0x2)
	if isOdd(pub.Y) {
		format |= 0x1
	}
	b = append(b, format)
	return paddedAppend(32, b, pub.X.Bytes())
}

// BytesToPublicKey .
func BytesToPublicKey(curve elliptic.Curve, buff []byte) *ecdsa.PublicKey {

	x, y := elliptic.Unmarshal(curve, buff)

	if x == nil {
		return nil
	}

	publicKey := new(ecdsa.PublicKey)

	publicKey.X = x
	publicKey.Y = y
	publicKey.Curve = curve

	return publicKey
}

// PrivateKeyBytes 。
func PrivateKeyBytes(priv *ecdsa.PrivateKey) (b []byte) {
	d := priv.D.Bytes()

	/* Pad D to 32 bytes */
	paddedd := append(bytes.Repeat([]byte{0x00}, 32-len(d)), d...)

	return paddedd
}

// BytesToPrivateKey 。
func BytesToPrivateKey(key []byte, curve elliptic.Curve) *ecdsa.PrivateKey {
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = curve
	priv.D = new(big.Int).SetBytes(key)
	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(key)
	return priv
}

// PrivKeyFromBytes returns a private and public key for `curve' based on the
// private key passed as an argument as a byte slice.
func PrivKeyFromBytes(curve elliptic.Curve, pk []byte) *ecdsa.PrivateKey {
	x, y := curve.ScalarBaseMult(pk)

	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: new(big.Int).SetBytes(pk),
	}

	return priv
}
