package rfc6979

import (
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/libs4go/crypto/elliptic"
)

func TestSignVerify(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.SECP256K1(), rand.Reader)

	require.NoError(t, err)

	source := "hello rfc6979"

	r, s, err := Sign(privateKey, []byte(source))

	require.NoError(t, err)

	require.True(t, ecdsa.Verify(&privateKey.PublicKey, []byte(source), r, s))
}

func TestK(t *testing.T) {
	k1, err := ecdsa.GenerateKey(elliptic.SECP256K1(), rand.Reader)

	require.NoError(t, err)

	k2, err := ecdsa.GenerateKey(elliptic.SECP256K1(), rand.Reader)

	require.NoError(t, err)

	source := "hello rfc6979"

	r1, s1, err := Sign(k1, []byte(source))

	require.NoError(t, err)

	r2, s2, err := Sign(k2, []byte(source))

	require.NoError(t, err)

	require.NotEqual(t, r1, r2)

	require.NotEqual(t, s1, s2)
}
