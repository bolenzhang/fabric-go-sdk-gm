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
/*
Notice: This file has been modified for Hyperledger Fabric SDK Go usage.
Please review third_party pinning scripts and patches for more details.
*/

package sw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"crypto/rsa"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/tjfoc/gmsm/sm2"
)


type ecdsaKeyGenerator struct {
	curve elliptic.Curve
}

func (keygen *ecdsaKeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := ecdsa.GenerateKey(keygen.curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("Failed generating ECDSA key for [%v]: [%s]", keygen.curve, err)
	}

	return &ecdsaPrivateKey{privKey}, nil
}

type aesKeyGenerator struct {
	length int
}

func (keygen *aesKeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	lowLevelKey, err := GetRandomBytes(int(keygen.length))
	if err != nil {
		return nil, fmt.Errorf("Failed generating AES %d key [%s]", keygen.length, err)
	}

	return &aesPrivateKey{lowLevelKey, false}, nil
}

type rsaKeyGenerator struct {
	length int
}

func (keygen *rsaKeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	lowLevelKey, err := rsa.GenerateKey(rand.Reader, int(keygen.length))

	if err != nil {
		return nil, fmt.Errorf("Failed generating RSA %d key [%s]", keygen.length, err)
	}

	return &rsaPrivateKey{lowLevelKey}, nil
}

// 定义国密SM2 keygen 结构体， 实现 KeyGenerator接口
// TODO: 应该不需要sm2的KeyGen
type sm2KeyGenerator struct {
	//curve elliptic.Curve
}

func (keygen *sm2KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := sm2.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("Failed generating SM2 key for [%s]", err)
	}

	return &sm2PrivateKey{privKey}, nil
}

type sm4KeyGenerator struct {
	length int
}

func (keygen *sm4KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	lowLevelKey, err := GetRandomBytes(int(keygen.length))
	if err != nil {
		return nil, fmt.Errorf("Failed generating AES %d key [%s]", keygen.length, err)
	}

	return &sm4PrivateKey{lowLevelKey, false}, nil
}