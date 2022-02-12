package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

func AESBase64Encrypt(origin_data string, key []byte, iv []byte) (base64_result string, err error) {

	var block cipher.Block
	if block, err = aes.NewCipher(key); err != nil {
		return
	}
	encrypt := cipher.NewCBCEncrypter(block, iv)
	var source []byte = PKCS5Padding([]byte(origin_data), 16)
	var dst []byte = make([]byte, len(source))
	encrypt.CryptBlocks(dst, source)
	base64_result = base64.StdEncoding.EncodeToString(dst)
	return
}

func AESBase64Decrypt(encrypt_data string, key []byte, iv []byte) (origin_data string, err error) {
	var block cipher.Block
	defer func() {
		if Derr := recover(); Derr != nil {
			err = fmt.Errorf(fmt.Sprintf("%v", Derr))
		}
	}()
	if block, err = aes.NewCipher(key); err != nil {
		return
	}
	encrypt := cipher.NewCBCDecrypter(block, iv)

	var source []byte
	if source, err = base64.StdEncoding.DecodeString(encrypt_data); err != nil {
		return
	}
	var dst []byte = make([]byte, len(source))
	encrypt.CryptBlocks(dst, source)
	originDataBytes, err := PKCS5UnPadding(dst, 16)
	if err != nil {
		return
	}
	origin_data = string(originDataBytes)
	return
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	PaddedText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, PaddedText...)
}

func PKCS5UnPadding(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	if len(data)%blocklen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}
	paddinglen := int(data[len(data)-1])
	if paddinglen > blocklen || paddinglen == 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	pad := data[len(data)-paddinglen:]
	for i := 0; i < paddinglen; i++ {
		if pad[i] != byte(paddinglen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return data[:len(data)-paddinglen], nil
}
