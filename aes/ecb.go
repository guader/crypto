package aes

import (
	"crypto/aes"
)

func EncryptECB(pad PaddingFunc, key, plaintext []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext = pad(plaintext)
	l := len(plaintext)
	ciphertext := make([]byte, l, l)
	i := 0
	for i < l {
		j := i + aes.BlockSize
		cipher.Encrypt(ciphertext[i:j], plaintext[i:j])
		i = j
	}
	return ciphertext, nil
}

func DecryptECB(unpad PaddingFunc, key, ciphertext []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	l := len(ciphertext)
	plaintext := make([]byte, l, l)
	i := 0
	for i < l {
		j := i + aes.BlockSize
		cipher.Decrypt(plaintext[i:j], ciphertext[i:j])
		i = j
	}
	plaintext = unpad(plaintext)
	return plaintext, nil
}
