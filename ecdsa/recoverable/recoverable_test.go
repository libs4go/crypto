package recoverable

import (
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/libs4go/crypto/elliptic"
	"github.com/stretchr/testify/require"
)

func TestSignVerify(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.SECP256K1(), rand.Reader)

	require.NoError(t, err)

	source := "hello rfc6979"

	r, s, v, err := Sign(privateKey, []byte(source), false)

	require.NoError(t, err)

	require.True(t, ecdsa.Verify(&privateKey.PublicKey, []byte(source), r, s))

	publicKey, compressed, err := Recover(privateKey.Curve, r, s, v, []byte(source))

	require.NoError(t, err)

	require.False(t, compressed)

	require.Equal(t, publicKey.X, privateKey.PublicKey.X)
	require.Equal(t, publicKey.Y, privateKey.PublicKey.Y)
}
func TestK(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.SECP256K1(), rand.Reader)

	require.NoError(t, err)

	r, s, v, err := Sign(privateKey, []byte("hello rfc6979"), false)

	require.NoError(t, err)

	r1, s1, v1, err := Sign(privateKey, []byte("hello rfc6971119"), true)

	require.NoError(t, err)

	require.NotEqual(t, r, r1)

	require.NotEqual(t, s, s1)

	require.NotEqual(t, v, v1)
}

func TestCompressSignVerify(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.SECP256K1(), rand.Reader)

	require.NoError(t, err)

	source := "hello rfc6979"

	r, s, v, err := Sign(privateKey, []byte(source), true)

	require.NoError(t, err)

	require.True(t, ecdsa.Verify(&privateKey.PublicKey, []byte(source), r, s))

	publicKey, compressed, err := Recover(privateKey.Curve, r, s, v, []byte(source))

	require.NoError(t, err)

	require.True(t, compressed)

	require.Equal(t, publicKey.X, privateKey.PublicKey.X)
	require.Equal(t, publicKey.Y, privateKey.PublicKey.Y)
}
