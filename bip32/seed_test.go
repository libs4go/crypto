package bip32

import (
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/libs4go/crypto/bip44"

	xelliptic "github.com/libs4go/crypto/elliptic"
	"github.com/stretchr/testify/require"
)

type paramTest struct {
}

func (t *paramTest) Curve() elliptic.Curve {
	return xelliptic.SECP256K1()
}

func TestSeed(t *testing.T) {
	seed := mnemonicToSeed("canal walnut regular license dust liberty story expect repeat design picture medal", "")

	println(hex.EncodeToString(seed))

	require.Equal(t, hex.EncodeToString(seed), "15cba277c500b4e0c777d563278130f4c24b52532b3c8c45e051d417bebc5c007243c07d2e341a2d7c17bbd3880b968ca60869edab8f015be30674ad4d3d260f")

	k, err := NewMasterKey(seed, &paramTest{})

	require.NoError(t, err)

	println(hex.EncodeToString(k.PrivateKey))

	k, err = k.ChildKey(bip44.MakeNumber(0x2c, true))

	require.NoError(t, err)

	println(hex.EncodeToString(k.PrivateKey))
}

func TestOutput(t *testing.T) {
	s := "canal walnut regular license dust liberty story expect repeat design picture medal"

	ss := strings.Split(s, " ")

	for i := range ss {
		println(fmt.Sprintf(`MnemonicWord(word:"\n",index:%d),`, i+1))
	}
}
