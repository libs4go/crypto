package bip32

import (
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"math/big"
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

func TestDrive(t *testing.T) {
	masterKey, err := FromMnemonic(FromCurve(xelliptic.SECP256K1()), "canal walnut regular license dust liberty story expect repeat design picture medal", "")

	require.NoError(t, err)

	testDrivePath(t, masterKey, "m/44'/60'/0'/0/0", "0aa534f35515818acb139cb75179bef659f6c8c8bbfca25b9e5e20748cb24ed3")

	testDrivePath(t, masterKey, "m/44'/60'/0'/0/1", "26894ab0843e95eebd226f8a0dc2f5cd4291295edb8e1a2472989776600eac2f")

	testDrivePath(t, masterKey, "m/44'/60'/0'/0/17", "e4480f23891aa46b931c6eff9b0b8cff4b04702754e1d6653f9d188dfe7c1ddb")
}

func testDrivePath(t *testing.T, masterKey *DrivedKey, path string, expect string) {
	privateKey, err := DriveFrom(masterKey, path)

	require.NoError(t, err)

	expectBytes, err := hex.DecodeString(expect)

	require.NoError(t, err)

	require.Equal(t, big.NewInt(0).SetBytes(privateKey), big.NewInt(0).SetBytes(expectBytes))
}
