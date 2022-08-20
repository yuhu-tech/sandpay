package sandpay

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"golang.org/x/crypto/pkcs12"
)

const OK = "000000"

// PaddingMode aes padding mode
type PaddingMode string

const (
	// ZERO zero padding mode
	ZERO PaddingMode = "ZERO"
	// PKCS5 PKCS#5 padding mode
	PKCS5 PaddingMode = "PKCS#5"
	// PKCS7 PKCS#7 padding mode
	PKCS7 PaddingMode = "PKCS#7"
)

// PemBlockType pem block type which taken from the preamble.
type PemBlockType string

const (
	// RSAPKCS1 private key in PKCS#1
	RSAPKCS1 PemBlockType = "RSA PRIVATE KEY"
	// RSAPKCS8 private key in PKCS#8
	RSAPKCS8 PemBlockType = "PRIVATE KEY"
)

type X map[string]string

type Data struct {
	Head X `json:"head"`
	Body X `json:"body"`
}

// MD5 calculates the md5 hash of a string.
func MD5(s string) string {
	h := md5.New()
	h.Write([]byte(s))

	return hex.EncodeToString(h.Sum(nil))
}

// PrivateKey RSA private key
type PrivateKey struct {
	key *rsa.PrivateKey
}

// Decrypt rsa decrypt with PKCS #1 v1.5
func (pk *PrivateKey) Decrypt(cipherText []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, pk.key, cipherText)
}

// Sign returns sha-with-rsa signature.
func (pk *PrivateKey) Sign(hash crypto.Hash, data []byte) ([]byte, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("crypto: requested hash function (%s) is unavailable", hash.String())
	}

	h := hash.New()
	h.Write(data)

	signature, err := rsa.SignPKCS1v15(rand.Reader, pk.key, hash, h.Sum(nil))

	if err != nil {
		return nil, err
	}

	return signature, nil
}

// ParsePrivateKeyFromPfxFile parses private key from pfx(p12) file.
func ParsePrivateKeyFromPfxFile(pfxFile, password string) (*PrivateKey, error) {
	cert, err := LoadCertFromPfxFile(pfxFile, password)

	if err != nil {
		return nil, err
	}

	return &PrivateKey{key: cert.PrivateKey.(*rsa.PrivateKey)}, nil
}

// PublicKey RSA public key
type PublicKey struct {
	key *rsa.PublicKey
}

// Encrypt rsa encrypt with PKCS #1 v1.5
func (pk *PublicKey) Encrypt(plainText []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, pk.key, plainText)
}

// Verify verifies the sha-with-rsa signature.
func (pk *PublicKey) Verify(hash crypto.Hash, data, signature []byte) error {
	if !hash.Available() {
		return fmt.Errorf("crypto: requested hash function (%s) is unavailable", hash.String())
	}

	h := hash.New()
	h.Write(data)

	return rsa.VerifyPKCS1v15(pk.key, hash, h.Sum(nil), signature)
}

// ParsePublicKeyFromDerFile parses public key from DER (.cer) file.
func ParsePublicKeyFromDerFile(certFile string) (*PublicKey, error) {
	keyPath, err := filepath.Abs(certFile)

	if err != nil {
		return nil, err
	}

	f, err := os.Open(keyPath)

	if err != nil {
		return nil, err
	}

	defer f.Close()

	b, err := ioutil.ReadAll(f)

	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(b)

	if err != nil {
		return nil, err
	}

	return &PublicKey{key: cert.PublicKey.(*rsa.PublicKey)}, nil
}

// LoadCertFromPfxFile returns tls certificate from pfx(p12) file.
func LoadCertFromPfxFile(pfxFile, password string) (tls.Certificate, error) {
	fail := func(err error) (tls.Certificate, error) { return tls.Certificate{}, err }

	certPath, err := filepath.Abs(filepath.Clean(pfxFile))

	if err != nil {
		return fail(err)
	}

	b, err := ioutil.ReadFile(certPath)

	if err != nil {
		return fail(err)
	}

	blocks, err := pkcs12.ToPEM(b, password)

	if err != nil {
		return fail(err)
	}

	pemData := make([]byte, 0)

	for _, b := range blocks {
		pemData = append(pemData, pem.EncodeToMemory(b)...)
	}

	return tls.X509KeyPair(pemData, pemData)
}

type ECBCrypto struct {
	key  []byte
	mode PaddingMode
}

func (c *ECBCrypto) Encrypt(plainText []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)

	if err != nil {
		return nil, err
	}

	switch c.mode {
	case ZERO:
		plainText = ZeroPadding(plainText, block.BlockSize())
	case PKCS5:
		plainText = PKCS5Padding(plainText, block.BlockSize())
	case PKCS7:
		plainText = PKCS5Padding(plainText, len(c.key))
	}

	cipherText := make([]byte, len(plainText))

	blockMode := NewECBEncrypter(block)
	blockMode.CryptBlocks(cipherText, plainText)

	return cipherText, nil
}

func (c *ECBCrypto) Decrypt(cipherText []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)

	if err != nil {
		return nil, err
	}

	plainText := make([]byte, len(cipherText))

	blockMode := NewECBDecrypter(block)
	blockMode.CryptBlocks(plainText, cipherText)

	switch c.mode {
	case ZERO:
		plainText = ZeroUnPadding(plainText)
	case PKCS5:
		plainText = PKCS5Unpadding(plainText, block.BlockSize())
	case PKCS7:
		plainText = PKCS5Unpadding(plainText, len(c.key))
	}

	return plainText, nil
}

// NewECBCrypto returns a new aes-ecb crypto.
func NewECBCrypto(key []byte, mode PaddingMode) *ECBCrypto {
	return &ECBCrypto{
		key:  key,
		mode: mode,
	}
}

func ZeroPadding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{0}, padding)

	return append(cipherText, padText...)
}

func ZeroUnPadding(plainText []byte) []byte {
	return bytes.TrimRightFunc(plainText, func(r rune) bool {
		return r == rune(0)
	})
}

func PKCS5Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize

	if padding == 0 {
		padding = blockSize
	}

	padText := bytes.Repeat([]byte{byte(padding)}, padding)

	return append(cipherText, padText...)
}

func PKCS5Unpadding(plainText []byte, blockSize int) []byte {
	l := len(plainText)
	unpadding := int(plainText[l-1])

	if unpadding < 1 || unpadding > blockSize {
		unpadding = 0
	}

	return plainText[:(l - unpadding)]
}

// ------------- AES-256-ECB -------------

type ecb struct {
	b         cipher.Block
	blockSize int
}

func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

type ecbEncrypter ecb

// NewECBEncrypter returns a BlockMode which encrypts in electronic code book mode, using the given Block.
func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(newECB(b))
}

func (x *ecbEncrypter) BlockSize() int { return x.blockSize }

func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}

	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}

	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

type ecbDecrypter ecb

// NewECBDecrypter returns a BlockMode which decrypts in electronic code book mode, using the given Block.
func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(newECB(b))
}

func (x *ecbDecrypter) BlockSize() int { return x.blockSize }

func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}

	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}

	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])

		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}
