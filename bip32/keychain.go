package bip32

import (
	"bytes"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"math/big"

	"github.com/libs4go/crypto/bip44"
	"github.com/libs4go/errors"
)

// DrivedKey .
type DrivedKey struct {
	Param      KeyParam
	PublicKey  []byte // 33 bytes
	PrivateKey []byte // 32 bytes
	ChainCode  []byte // 32 bytes
}

// KeyParam .
type KeyParam interface {
	// PrivateToPublic(privateKey []byte) []byte
	Curve() elliptic.Curve
}

type keyParamImpl struct {
	c elliptic.Curve
}

func (kp *keyParamImpl) Curve() elliptic.Curve {
	return kp.c
}

func FromCurve(curve elliptic.Curve) KeyParam {
	return &keyParamImpl{
		c: curve,
	}
}

func privateKeyToPublicKey(curve elliptic.Curve, privateKey []byte) []byte {
	x, y := curve.ScalarBaseMult(privateKey)

	return elliptic.MarshalCompressed(curve, x, y)
}

// NewMasterKey create new master key from seed
func NewMasterKey(seed []byte, param KeyParam) (*DrivedKey, error) {
	hmac := hmac.New(sha512.New, []byte("Bitcoin seed"))

	_, err := hmac.Write(seed)

	if err != nil {
		return nil, errors.Wrap(err, "hmac error")
	}

	intermediary := hmac.Sum(nil)

	keyBytes := intermediary[:32]
	chainCode := intermediary[32:]

	return &DrivedKey{
		Param:      param,
		PublicKey:  privateKeyToPublicKey(param.Curve(), keyBytes),
		PrivateKey: keyBytes,
		ChainCode:  chainCode,
	}, nil
}

func getPrivateKeyByte33(pk []byte) []byte {
	buff := make([]byte, 33)

	copy(buff[33-len(pk):], pk)

	return buff
}

// ChildKey get child key
func (key *DrivedKey) ChildKey(index bip44.Number) (*DrivedKey, error) {
	indexBytes := uint32Bytes(uint32(index))

	var buff bytes.Buffer

	if index.IsHardened() {
		buff.Write(getPrivateKeyByte33(key.PrivateKey))
	} else {
		buff.Write(key.PublicKey)
	}

	buff.Write(indexBytes)

	seed := buff.Bytes()

	dig := hmac.New(sha512.New, key.ChainCode)

	_, err := dig.Write(seed)

	if err != nil {
		return nil, err
	}

	intermediary := dig.Sum(nil)

	keyBytes := intermediary[:32]
	chainCode := intermediary[32:]

	newkey := key.addPrivKeys(keyBytes, key.PrivateKey)

	return &DrivedKey{
		Param:      key.Param,
		PublicKey:  privateKeyToPublicKey(key.Param.Curve(), newkey),
		PrivateKey: newkey,
		ChainCode:  chainCode,
	}, nil
}

func (key *DrivedKey) addPrivKeys(k1, k2 []byte) []byte {
	i1 := big.NewInt(0).SetBytes(k1)
	i2 := big.NewInt(0).SetBytes(k2)
	i1.Add(i1, i2)
	i1.Mod(i1, key.Param.Curve().Params().N)
	k := i1.Bytes()
	zero, _ := hex.DecodeString("00")
	return append(zero, k...)
}

func uint32Bytes(i uint32) []byte {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, i)
	return bytes
}
