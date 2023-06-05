package util

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"io/ioutil"
)

func GenRandomStringByLength(length int) string {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(b)[:length]
}

// AESEncryptECB AES-ECB解密
func AESEncryptECB(origData []byte, key []byte) (encrypted []byte) {
	cipher, _ := aes.NewCipher(key)
	length := (len(origData) + aes.BlockSize) / aes.BlockSize
	plain := make([]byte, length*aes.BlockSize)
	copy(plain, origData)
	pad := byte(len(plain) - len(origData))
	for i := len(origData); i < len(plain); i++ {
		plain[i] = pad
	}
	encrypted = make([]byte, len(plain))
	// 分组分块加密
	for bs, be := 0, cipher.BlockSize(); bs <= len(origData); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
		cipher.Encrypt(encrypted[bs:be], plain[bs:be])
	}
	return encrypted
}

// AESDecryptECB AES ECB模式解密
func AESDecryptECB(encrypted []byte, key []byte) (decrypted []byte) {
	cpr, _ := aes.NewCipher(key)
	decrypted = make([]byte, len(encrypted))
	for bs, be := 0, cpr.BlockSize(); bs < len(encrypted); bs, be = bs+cpr.BlockSize(), be+cpr.BlockSize() {
		cpr.Decrypt(decrypted[bs:be], encrypted[bs:be])
	}
	trim := 0
	if len(decrypted) > 0 {
		trim = len(decrypted) - int(decrypted[len(decrypted)-1])
	}
	return decrypted[:trim]
}

// RSAEncryptECB .cer公钥文件 RSA加密 (plainText 需要加密的信息, path 公钥证书地址)
func RSAEncryptECB(plainText []byte, path string) ([]byte, error) {
	// 读公钥文件
	cerKey, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	certificate, err := x509.ParseCertificate(cerKey)
	if err != nil {
		return nil, err
	}
	// 对明文进行加密
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, certificate.PublicKey.(*rsa.PublicKey), plainText)
	if err != nil {
		return nil, err
	}

	// 返回密文
	return cipherText, nil
}
