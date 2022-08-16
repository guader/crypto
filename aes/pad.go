package aes

import (
	"bytes"
	"crypto/aes"
)

type PaddingFunc func([]byte) []byte

func PadPKCS7(data []byte) []byte {
	padding := aes.BlockSize - len(data)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

func UnpadPKCS7(data []byte) []byte {
	length := len(data)
	unpadding := int(data[length-1])
	return data[:(length - unpadding)]
}

func PadZero(data []byte) []byte {
	padding := aes.BlockSize - len(data)%aes.BlockSize
	return append(data, make([]byte, padding, padding)...)
}

func UnpadZero(data []byte) []byte {
	return bytes.TrimRightFunc(data, func(r rune) bool {
		return r == rune(0)
	})
}
