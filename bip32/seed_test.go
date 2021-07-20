package bip32

import (
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/libs4go/crypto/bip44"
	"github.com/libs4go/crypto/ecdsa"
	"golang.org/x/crypto/sha3"

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
	masterKey, err := FromMnemonic(FromCurve(xelliptic.SECP256K1()), "orchard mean picnic worry sleep squeeze auto copy hard eager island entry define dune raise spice steel voice prosper mosquito warm ignore book negative", "")

	require.NoError(t, err)

	testDrivePath(t, masterKey, "m/44'/60'/0'/0/0", "e68232f718d6b892d544eae6957522437618ad49e636dd98693295b0d6424938")

	// testDrivePath(t, masterKey, "m/44'/60'/0'/0/1", "26894ab0843e95eebd226f8a0dc2f5cd4291295edb8e1a2472989776600eac2f")

	// testDrivePath(t, masterKey, "m/44'/60'/0'/0/17", "e4480f23891aa46b931c6eff9b0b8cff4b04702754e1d6653f9d188dfe7c1ddb")
}

func testDrivePath(t *testing.T, masterKey *DrivedKey, path string, expect string) {
	key, err := DriveFrom(masterKey, path)

	require.NoError(t, err)

	expectBytes, err := hex.DecodeString(expect)

	require.NoError(t, err)

	require.Equal(t, big.NewInt(0).SetBytes(key.PrivateKey), big.NewInt(0).SetBytes(expectBytes))

	pk := ecdsa.BytesToPrivateKey(key.PrivateKey, masterKey.Param.Curve())

	require.NoError(t, err)

	pubKey := ecdsa.PublicKeyBytes(&pk.PublicKey)

	println(hex.EncodeToString(key.PublicKey), hex.EncodeToString(pubKey), PublicKeyToAddress(pubKey))
}

func PublicKeyToAddress(pubkey []byte) string {
	pubBytes := pubkey

	hasher := sha3.NewLegacyKeccak256()

	hasher.Write(pubBytes[1:])

	pubBytes = hasher.Sum(nil)[12:]

	if len(pubBytes) > 20 {
		pubBytes = pubBytes[len(pubBytes)-20:]
	}

	address := make([]byte, 20)

	copy(address[20-len(pubBytes):], pubBytes)

	unchecksummed := hex.EncodeToString(address)

	sha := sha3.NewLegacyKeccak256()

	sha.Write([]byte(unchecksummed))

	hash := sha.Sum(nil)

	result := []byte(unchecksummed)

	for i := 0; i < len(result); i++ {
		hashByte := hash[i/2]
		if i%2 == 0 {
			hashByte = hashByte >> 4
		} else {
			hashByte &= 0xf
		}
		if result[i] > '9' && hashByte > 7 {
			result[i] -= 32
		}
	}

	return "0x" + string(result)
}
