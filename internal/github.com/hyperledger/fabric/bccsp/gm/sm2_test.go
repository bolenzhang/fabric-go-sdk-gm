/*
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package gm

import (
	"crypto/elliptic"
	"crypto/sha256"
	"github.com/tjfoc/gmsm/sm2"
	"math/big"
	"testing"

	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/stretchr/testify/assert"
)

func TestSignSM2BadParameter(t *testing.T) {
	// Generate a key
	lowLevelKey, err := sm2.GenerateKey()
	assert.NoError(t, err)

	// Induce an error on the underlying ecdsa algorithm
	msg := []byte("hello world")
	oldN := lowLevelKey.Params().N
	defer func() { lowLevelKey.Params().N = oldN }()
	lowLevelKey.Params().N = big.NewInt(0)
	_, err = signSM2(lowLevelKey, msg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "zero parameter")
	lowLevelKey.Params().N = oldN
}

func TestVerifySM2(t *testing.T) {
	t.Parallel()

	// Generate a key
	lowLevelKey, err := sm2.GenerateKey()
	assert.NoError(t, err)

	msg := []byte("hello world")
	sigma, err := signSM2(lowLevelKey, msg, nil)
	assert.NoError(t, err)

	//valid, err := verifySM2(&lowLevelKey.PublicKey, sigma, msg, nil)
	//assert.NoError(t, err)
	//assert.True(t, valid)
	//
	//_, err = verifySM2(&lowLevelKey.PublicKey, nil, msg, nil)
	//assert.Error(t, err)
	//assert.Contains(t, err.Error(), "Failed unmashalling signature [")
	//
	//_, err = verifySM2(&lowLevelKey.PublicKey, nil, msg, nil)
	//assert.Error(t, err)
	//assert.Contains(t, err.Error(), "Failed unmashalling signature [")

	R, S, err := utils.UnmarshalECDSASignature(sigma)
	assert.NoError(t, err)
	S.Add(utils.GetCurveHalfOrdersAt(elliptic.P256()), big.NewInt(1))
	sigmaWrongS, err := utils.MarshalECDSASignature(R, S)
	assert.NoError(t, err)
	_, err = verifySM2(&lowLevelKey.PublicKey, sigmaWrongS, msg, nil)
	//assert.Error(t, err)
	//assert.Contains(t, err.Error(), "Invalid S. Must be smaller than half the order [")
}

func TestSm2SignerSign(t *testing.T) {
	t.Parallel()

	signer := &sm2Signer{}
	verifierPrivateKey := &sm2PrivateKeyVerifier{}
	verifierPublicKey := &sm2PublicKeyKeyVerifier{}

	// Generate a key
	lowLevelKey, err := sm2.GenerateKey()
	assert.NoError(t, err)
	k := &sm2PrivateKey{lowLevelKey}
	pk, err := k.PublicKey()
	assert.NoError(t, err)

	// Sign
	msg := []byte("Hello World")
	sigma, err := signer.Sign(k, msg, nil)
	assert.NoError(t, err)
	assert.NotNil(t, sigma)

	// Verify
	valid, err := verifySM2(&lowLevelKey.PublicKey, sigma, msg, nil)
	assert.NoError(t, err)
	assert.True(t, valid)

	valid, err = verifierPrivateKey.Verify(k, sigma, msg, nil)
	assert.NoError(t, err)
	assert.True(t, valid)

	valid, err = verifierPublicKey.Verify(pk, sigma, msg, nil)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestSm2PrivateKey(t *testing.T) {
	t.Parallel()

	lowLevelKey, err := sm2.GenerateKey()
	assert.NoError(t, err)
	k := &sm2PrivateKey{lowLevelKey}

	assert.False(t, k.Symmetric())
	assert.True(t, k.Private())

	_, err = k.Bytes()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Not supported.")

	k.privKey = nil
	ski := k.SKI()
	assert.Nil(t, ski)

	k.privKey = lowLevelKey
	ski = k.SKI()
	raw := elliptic.Marshal(k.privKey.Curve, k.privKey.PublicKey.X, k.privKey.PublicKey.Y)
	hash := sha256.New()
	hash.Write(raw)
	ski2 := hash.Sum(nil)
	assert.Equal(t, ski2, ski, "SKI is not computed in the right way.")

	pk, err := k.PublicKey()
	assert.NoError(t, err)
	assert.NotNil(t, pk)
	ecdsaPK, ok := pk.(*sm2PublicKey)
	assert.True(t, ok)
	assert.Equal(t, &lowLevelKey.PublicKey, ecdsaPK.pubKey)
}

func TestSm2PublicKey(t *testing.T) {
	t.Parallel()

	lowLevelKey, err := sm2.GenerateKey()
	assert.NoError(t, err)
	k := &sm2PublicKey{&lowLevelKey.PublicKey}

	assert.False(t, k.Symmetric())
	assert.False(t, k.Private())

	k.pubKey = nil
	ski := k.SKI()
	assert.Nil(t, ski)

	k.pubKey = &lowLevelKey.PublicKey
	ski = k.SKI()
	raw := elliptic.Marshal(k.pubKey.Curve, k.pubKey.X, k.pubKey.Y)
	hash := sha256.New()
	hash.Write(raw)
	ski2 := hash.Sum(nil)
	assert.Equal(t, ski, ski2, "SKI is not computed in the right way.")

	pk, err := k.PublicKey()
	assert.NoError(t, err)
	assert.Equal(t, k, pk)

	bytes, err := k.Bytes()
	//assert.NoError(t, err)
	bytes2, err := sm2.MarshalPKIXPublicKey(k.pubKey)
	assert.Equal(t, bytes2, bytes, "bytes are not computed in the right way.")

	invalidCurve := &elliptic.CurveParams{Name: "P-Invalid"}
	invalidCurve.BitSize = 1024
	k.pubKey = &sm2.PublicKey{Curve: invalidCurve, X: big.NewInt(1), Y: big.NewInt(1)}
	_, err = k.Bytes()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed marshalling key [")
}
