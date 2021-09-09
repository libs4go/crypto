package recoverable

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	ellipticx "github.com/libs4go/crypto/elliptic"
	"github.com/stretchr/testify/require"
)

func TestK(t *testing.T) {
	testK(t, elliptic.P256())

	testK(t, elliptic.P224())

	testK(t, elliptic.P384())

	testK(t, elliptic.P521())

	testK(t, ellipticx.SECP256K1())

}

func testK(t *testing.T, curve elliptic.Curve) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)

	require.NoError(t, err)

	r, s, v, err := Sign(privateKey, []byte("hello rfc6979"), false)

	require.NoError(t, err)

	r1, s1, v1, err := Sign(privateKey, []byte("hello rfc6971119"), true)

	require.NoError(t, err)

	require.NotEqual(t, r, r1)

	require.NotEqual(t, s, s1)

	require.NotEqual(t, v, v1)

	r2, s2, v2, err := Sign(privateKey, []byte("hello rfc6979"), false)

	require.NoError(t, err)

	require.Equal(t, r, r2)

	require.Equal(t, s, s2)

	require.Equal(t, v, v2)
}

func TestCompressSignVerify(t *testing.T) {

	testRecoverSign(t, elliptic.P256(), true)

	testRecoverSign(t, elliptic.P224(), true)

	testRecoverSign(t, elliptic.P384(), true)

	testRecoverSign(t, elliptic.P521(), true)

	testRecoverSign(t, ellipticx.SECP256K1(), true)

	testRecoverSign(t, elliptic.P256(), false)

	testRecoverSign(t, elliptic.P224(), false)

	testRecoverSign(t, elliptic.P384(), false)

	testRecoverSign(t, elliptic.P521(), false)

	testRecoverSign(t, ellipticx.SECP256K1(), false)
}

func testRecoverSign(t *testing.T, curve elliptic.Curve, c bool) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)

	require.NoError(t, err)

	source := "hello rfc6979"

	r, s, v, err := Sign(privateKey, []byte(source), c)

	require.NoError(t, err)

	require.True(t, ecdsa.Verify(&privateKey.PublicKey, []byte(source), r, s))

	publicKey, compressed, err := Recover(privateKey.Curve, r, s, v, []byte(source))

	require.NoError(t, err)

	require.Equal(t, compressed, c)

	require.Equal(t, publicKey.X, privateKey.PublicKey.X)
	require.Equal(t, publicKey.Y, privateKey.PublicKey.Y)
}
