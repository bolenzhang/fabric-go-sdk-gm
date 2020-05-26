/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package gm

import (
	"crypto/sha256"
	"crypto/sha512"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/tjfoc/gmsm/sm3"
	"reflect"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
)

// NewDefaultSecurityLevel returns a new instance of the software-based BCCSP
// at security level 256, hash family SHA2 and using FolderBasedKeyStore as KeyStore.
func NewDefaultSecurityLevel(keyStorePath string) (bccsp.BCCSP, error) {
	ks := &fileBasedKeyStore{}
	if err := ks.Init(nil, keyStorePath, false); err != nil {
		return nil, errors.Wrapf(err, "Failed initializing key store at [%v]", keyStorePath)
	}

	return NewWithParams(256, "SHA2", ks)
}

// NewDefaultSecurityLevel returns a new instance of the software-based BCCSP
// at security level 256, hash family SHA2 and using the passed KeyStore.
func NewDefaultSecurityLevelWithKeystore(keyStore bccsp.KeyStore) (bccsp.BCCSP, error) {
	return NewWithParams(256, "SHA2", keyStore)
}

// NewWithParams returns a new instance of the software-based BCCSP
// set at the passed security level, hash family and KeyStore.
func NewWithParams(securityLevel int, hashFamily string, keyStore bccsp.KeyStore) (bccsp.BCCSP, error) {
	// Init config
	conf := &config{}
	err := conf.setSecurityLevel(securityLevel, hashFamily)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed initializing configuration at [%v,%v]", securityLevel, hashFamily)
	}

	swbccsp, err := New(keyStore)
	if err != nil {
		return nil, err
	}

	// Notice that errors are ignored here because some test will fail if one
	// of the following call fails.

	// Set the Encryptors
	swbccsp.AddWrapper(reflect.TypeOf(&sm4PrivateKey{}), &sm4Encryptor{}) // sm4 加密

	// Set the Decryptors
	swbccsp.AddWrapper(reflect.TypeOf(&sm4PrivateKey{}), &sm4Decryptor{}) // sm4 解密

	// Set the Signers
	swbccsp.AddWrapper(reflect.TypeOf(&sm2PrivateKey{}), &sm2Signer{}) // sm2 国密签名
	swbccsp.AddWrapper(reflect.TypeOf(&ecdsaPrivateKey{}), &ecdsaSigner{})

	// Set the Verifiers
	swbccsp.AddWrapper(reflect.TypeOf(&ecdsaPrivateKey{}), &ecdsaPrivateKeyVerifier{})
	swbccsp.AddWrapper(reflect.TypeOf(&ecdsaPublicKey{}), &ecdsaPublicKeyKeyVerifier{})
	swbccsp.AddWrapper(reflect.TypeOf(&sm2PrivateKey{}), &sm2PrivateKeyVerifier{}) // sm2 私钥验证
	swbccsp.AddWrapper(reflect.TypeOf(&sm2PublicKey{}), &sm2PublicKeyKeyVerifier{}) // sm2 公钥验证

	// Set the Hashers
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SHAOpts{}), &hasher{hash: conf.hashFunction})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SHA256Opts{}), &hasher{hash: sm3.New}) // sm3 Hash选项
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SHA256Opts{}), &hasher{hash: sha256.New})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SHA384Opts{}), &hasher{hash: sha512.New384})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SHA3_256Opts{}), &hasher{hash: sha3.New256})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SHA3_384Opts{}), &hasher{hash: sha3.New384})

	// Set the key generators
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM2KeyGenOpts{}), &sm2KeyGenerator{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM4KeyGenOpts{}), &sm4KeyGenerator{length: 32})

	// Set the key generators


	// Set the key importers
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM4ImportKeyOpts{}), &sm4ImportKeyOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM2PrivateKeyImportOpts{}), &sm2PrivateKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM2PublicKeyImportOpts{}), &sm2PublicKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.ECDSAPKIXPublicKeyImportOpts{}), &ecdsaPKIXPublicKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.ECDSAPrivateKeyImportOpts{}), &ecdsaPrivateKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.ECDSAGoPublicKeyImportOpts{}), &ecdsaGoPublicKeyImportOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.X509PublicKeyImportOpts{}), &x509PublicKeyImportOptsKeyImporter{bccsp: swbccsp})

	return swbccsp, nil
}
