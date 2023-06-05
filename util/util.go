package util

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strconv"
)

// TODO: split to more little package

// RSAPaddingMode pem block type which taken from the preamble.
type RSAPaddingMode int

const (
	// RSA_PKCS1 this kind of key is commonly encoded in PEM blocks of type "RSA PRIVATE KEY" and "RSA PUBLIC KEY"
	RSA_PKCS1 RSAPaddingMode = iota
	// RSA_PKCS8 this kind of key is commonly encoded in PEM blocks of type "PRIVATE KEY" and "PUBLIC KEY"
	RSA_PKCS8
)

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
		return nil, fmt.Errorf("crypto: requested hash function (%s) is unavailable", HashToString(hash))
	}

	h := hash.New()
	h.Write(data)

	signature, err := rsa.SignPKCS1v15(rand.Reader, pk.key, hash, h.Sum(nil))

	if err != nil {
		return nil, err
	}

	return signature, nil
}

// NewPrivateKeyFromPemBlock returns new private key with pem block.
func NewPrivateKeyFromPemBlock(mode RSAPaddingMode, pemBlock []byte) (*PrivateKey, error) {
	block, _ := pem.Decode(pemBlock)

	if block == nil {
		return nil, errors.New("no PEM data is found")
	}

	var (
		pk  interface{}
		err error
	)

	switch mode {
	case RSA_PKCS1:
		pk, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case RSA_PKCS8:
		pk, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}

	if err != nil {
		return nil, err
	}

	return &PrivateKey{key: pk.(*rsa.PrivateKey)}, nil
}

// NewPrivateKeyFromPemFile returns new private key with pem file.
func NewPrivateKeyFromPemFile(mode RSAPaddingMode, pemFile string) (*PrivateKey, error) {
	keyPath, err := filepath.Abs(pemFile)

	if err != nil {
		return nil, err
	}

	b, err := ioutil.ReadFile(keyPath)

	if err != nil {
		return nil, err
	}

	return NewPrivateKeyFromPemBlock(mode, b)
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
		return fmt.Errorf("crypto: requested hash function (%s) is unavailable", HashToString(hash))
	}

	h := hash.New()
	h.Write(data)

	return rsa.VerifyPKCS1v15(pk.key, hash, h.Sum(nil), signature)
}

// NewPublicKeyFromPemBlock returns new public key with pem block.
func NewPublicKeyFromPemBlock(mode RSAPaddingMode, pemBlock []byte) (*PublicKey, error) {
	block, _ := pem.Decode(pemBlock)

	if block == nil {
		return nil, errors.New("no PEM data is found")
	}

	var (
		pk  interface{}
		err error
	)

	switch mode {
	case RSA_PKCS1:
		pk, err = x509.ParsePKCS1PublicKey(block.Bytes)
	case RSA_PKCS8:
		pk, err = x509.ParsePKIXPublicKey(block.Bytes)
	}

	if err != nil {
		return nil, err
	}

	return &PublicKey{key: pk.(*rsa.PublicKey)}, nil
}

// NewPublicKeyFromPemFile returns new public key with pem file.
func NewPublicKeyFromPemFile(mode RSAPaddingMode, pemFile string) (*PublicKey, error) {
	keyPath, err := filepath.Abs(pemFile)

	if err != nil {
		return nil, err
	}

	b, err := ioutil.ReadFile(keyPath)

	if err != nil {
		return nil, err
	}

	return NewPublicKeyFromPemBlock(mode, b)
}

// NewPublicKeyFromDerBlock returns public key with DER block.
// NOTE: PEM format with -----BEGIN CERTIFICATE----- | -----END CERTIFICATE-----
// CMD: openssl x509 -inform der -in cert.cer -out cert.pem
func NewPublicKeyFromDerBlock(pemBlock []byte) (*PublicKey, error) {
	block, _ := pem.Decode(pemBlock)

	if block == nil {
		return nil, errors.New("no PEM data is found")
	}

	cert, err := x509.ParseCertificate(block.Bytes)

	if err != nil {
		return nil, err
	}

	return &PublicKey{key: cert.PublicKey.(*rsa.PublicKey)}, nil
}

// NewPublicKeyFromDerFile returns public key with DER file.
// NOTE: PEM format with -----BEGIN CERTIFICATE----- | -----END CERTIFICATE-----
// CMD: openssl x509 -inform der -in cert.cer -out cert.pem
func NewPublicKeyFromDerFile(pemFile string) (*PublicKey, error) {
	keyPath, err := filepath.Abs(pemFile)

	if err != nil {
		return nil, err
	}

	b, err := ioutil.ReadFile(keyPath)

	if err != nil {
		return nil, err
	}

	return NewPublicKeyFromDerBlock(b)
}

// MarshalNoEscapeHTML marshal with no escape HTML
func MarshalNoEscapeHTML(v interface{}) ([]byte, error) {
	buf := bytes.NewBuffer(nil)

	jsonEncoder := json.NewEncoder(buf)
	jsonEncoder.SetEscapeHTML(false)

	if err := jsonEncoder.Encode(v); err != nil {
		return nil, err
	}

	b := buf.Bytes()

	// 去掉 go std 给末尾加的 '\n'
	// @see https://github.com/golang/go/issues/7767
	if l := len(b); l != 0 && b[l-1] == '\n' {
		b = b[:l-1]
	}

	return b, nil
}

func HashToString(h crypto.Hash) string {
	switch h {
	case crypto.MD4:
		return "MD4"
	case crypto.MD5:
		return "MD5"
	case crypto.SHA1:
		return "SHA-1"
	case crypto.SHA224:
		return "SHA-224"
	case crypto.SHA256:
		return "SHA-256"
	case crypto.SHA384:
		return "SHA-384"
	case crypto.SHA512:
		return "SHA-512"
	case crypto.MD5SHA1:
		return "MD5+SHA1"
	case crypto.RIPEMD160:
		return "RIPEMD-160"
	case crypto.SHA3_224:
		return "SHA3-224"
	case crypto.SHA3_256:
		return "SHA3-256"
	case crypto.SHA3_384:
		return "SHA3-384"
	case crypto.SHA3_512:
		return "SHA3-512"
	case crypto.SHA512_224:
		return "SHA-512/224"
	case crypto.SHA512_256:
		return "SHA-512/256"
	case crypto.BLAKE2s_256:
		return "BLAKE2s-256"
	case crypto.BLAKE2b_256:
		return "BLAKE2b-256"
	case crypto.BLAKE2b_384:
		return "BLAKE2b-384"
	case crypto.BLAKE2b_512:
		return "BLAKE2b-512"
	default:
		return "unknown hash value " + strconv.Itoa(int(h))
	}
}
