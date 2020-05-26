/*
Copyright IBM Corp. 2016 All Rights Reserved.

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
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/tjfoc/gmsm/sm4"
)

// GetRandomBytes returns len random looking bytes
func GetRandomBytes(len int) ([]byte, error) {
	if len < 0 {
		return nil, errors.New("Len must be larger than 0")
	}

	buffer := make([]byte, len)

	n, err := rand.Read(buffer)
	if err != nil {
		return nil, err
	}
	if n != len {
		return nil, fmt.Errorf("Buffer not filled. Requested [%d], got [%d]", len, n)
	}

	return buffer, nil
}

func pkcs5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func pkcs5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length - 1])
	return src[:(length - unpadding)]
}
//
//func sm4CBCEncrypt(key, s []byte) ([]byte, error) {
//	return sm4CBCEncryptWithRand(rand.Reader, key, s)
//}
//
//func sm4CBCEncryptWithRand(prng io.Reader, key, s []byte) ([]byte, error) {
//	if len(s)%sm4.BlockSize != 0 {
//		return nil, errors.New("Invalid plaintext. It must be a multiple of the block size")
//	}
//
//	block, err := sm4.NewCipher(key)
//	if err != nil {
//		return nil, err
//	}
//
//	ciphertext := make([]byte, sm4.BlockSize+len(s))
//	iv := ciphertext[:sm4.BlockSize]
//	if _, err := io.ReadFull(prng, iv); err != nil {
//		return nil, err
//	}
//
//	mode := cipher.NewCBCEncrypter(block, iv)
//	mode.CryptBlocks(ciphertext[sm4.BlockSize:], s)
//
//	return ciphertext, nil
//}
//
//func sm4CBCEncryptWithIV(IV []byte, key, s []byte) ([]byte, error) {
//	if len(s)%sm4.BlockSize != 0 {
//		return nil, errors.New("Invalid plaintext. It must be a multiple of the block size")
//	}
//
//	if len(IV) != sm4.BlockSize {
//		return nil, errors.New("Invalid IV. It must have length the block size")
//	}
//
//	block, err := sm4.NewCipher(key)
//	if err != nil {
//		return nil, err
//	}
//
//	ciphertext := make([]byte, sm4.BlockSize+len(s))
//	copy(ciphertext[:sm4.BlockSize], IV)
//
//	mode := cipher.NewCBCEncrypter(block, IV)
//	mode.CryptBlocks(ciphertext[sm4.BlockSize:], s)
//
//	return ciphertext, nil
//}
//
//func sm4CBCDecrypt(key, src []byte) ([]byte, error) {
//	block, err := sm4.NewCipher(key)
//	if err != nil {
//		return nil, err
//	}
//
//	if len(src) < sm4.BlockSize {
//		return nil, errors.New("Invalid ciphertext. It must be a multiple of the block size")
//	}
//	iv := src[:sm4.BlockSize]
//	src = src[sm4.BlockSize:]
//
//	if len(src)%sm4.BlockSize != 0 {
//		return nil, errors.New("Invalid ciphertext. It must be a multiple of the block size")
//	}
//
//	mode := cipher.NewCBCDecrypter(block, iv)
//
//	mode.CryptBlocks(src, src)
//
//	return src, nil
//}

// SM4CBCPKCS7Encrypt combines CBC encryption and PKCS7 padding
func SM4Encrypt(key, src []byte) ([]byte, error) {
	//// First pad
	//tmp := pkcs7Padding(src)
	//
	//// Then encrypt
	//return sm4CBCEncrypt(key, tmp)
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("newCrypther faild ! [%s]", err)
	}

	origData := pkcs5Padding(src, block.BlockSize())
	dst := make([]byte, len(origData))
	blockMode := cipher.NewCBCEncrypter(block, make([]byte, sm4.BlockSize))
	blockMode.CryptBlocks(dst, origData)

	return dst, nil
}

//// SM4CBCPKCS7Encrypt combines CBC encryption and PKCS7 padding using as prng the passed to the function
//func SM4CBCPKCS7EncryptWithRand(prng io.Reader, key, src []byte) ([]byte, error) {
//	// First pad
//	tmp := pkcs7Padding(src)
//
//	// Then encrypt
//	return sm4CBCEncryptWithRand(prng, key, tmp)
//}
//
//// SM4CBCPKCS7Encrypt combines CBC encryption and PKCS7 padding, the IV used is the one passed to the function
//func SM4CBCPKCS7EncryptWithIV(IV []byte, key, src []byte) ([]byte, error) {
//	// First pad
//	tmp := pkcs7Padding(src)
//
//	// Then encrypt
//	return sm4CBCEncryptWithIV(IV, key, tmp)
//}

// SM4CBCPKCS7Decrypt combines CBC decryption and PKCS7 unpadding
func SM4Decrypt(key, src []byte) ([]byte, error) {
	//// First decrypt
	//pt, err := sm4CBCDecrypt(key, src)
	//if err == nil {
	//	return pkcs7UnPadding(pt)
	//}
	//return nil, err
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key[:block.BlockSize()])
	origData := make([]byte, len(src))
	blockMode.CryptBlocks(origData, src)
	origData = pkcs5UnPadding(origData)
	return origData, nil
}

type sm4Encryptor struct{}

func (e *sm4Encryptor) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) ([]byte, error) {
	//switch o := opts.(type) {
	//case *bccsp.AESCBCPKCS7ModeOpts:
	//	// AES in CBC mode with PKCS7 padding
	//
	//	if len(o.IV) != 0 && o.PRNG != nil {
	//		return nil, errors.New("Invalid options. Either IV or PRNG should be different from nil, or both nil.")
	//	}
	//
	//	if len(o.IV) != 0 {
	//		// Encrypt with the passed IV
	//		return SM4CBCPKCS7EncryptWithIV(o.IV, k.(*sm4PrivateKey).privKey, plaintext)
	//	} else if o.PRNG != nil {
	//		// Encrypt with PRNG
	//		return SM4CBCPKCS7EncryptWithRand(o.PRNG, k.(*sm4PrivateKey).privKey, plaintext)
	//	}
	//	// AES in CBC mode with PKCS7 padding
	//	return SM4CBCPKCS7Encrypt(k.(*sm4PrivateKey).privKey, plaintext)
	//case bccsp.AESCBCPKCS7ModeOpts:
	//	return e.Encrypt(k, plaintext, &o)
	//default:
	//	return nil, fmt.Errorf("Mode not recognized [%s]", opts)
	//}
	return SM4Encrypt(k.(*sm4PrivateKey).privKey, plaintext)
}

type sm4Decryptor struct{}

func (*sm4Decryptor) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) ([]byte, error) {
	//// check for mode
	//switch opts.(type) {
	//case *bccsp.AESCBCPKCS7ModeOpts, bccsp.AESCBCPKCS7ModeOpts:
	//	// AES in CBC mode with PKCS7 padding
	//	return SM4CBCPKCS7Decrypt(k.(*sm4PrivateKey).privKey, ciphertext)
	//default:
	//	return nil, fmt.Errorf("Mode not recognized [%s]", opts)
	//}
	return SM4Decrypt(k.(*sm4PrivateKey).privKey, ciphertext)
}
