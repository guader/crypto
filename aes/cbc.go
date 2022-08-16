package aes

import (
	"crypto/aes"
	"crypto/cipher"
)

func EncryptCBC(pad PaddingFunc, key, iv, plaintext []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext = pad(plaintext)
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(c, iv).CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

func DecryptCBC(unpad PaddingFunc, key, iv, ciphertext []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(c, iv).CryptBlocks(plaintext, ciphertext)
	plaintext = unpad(plaintext)
	return plaintext, nil
}
