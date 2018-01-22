package keygen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"path"
)

var basicPath string

// GenRsaKey 生成Rsa密钥
func GenRsaKey(bits int, user string) error {
	p, err := genFilder(user)
	if err != nil {
		return err
	}
	// 生成私钥文件
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "私钥",
		Bytes: derStream,
	}
	pvk := path.Join(p, "private.pem")
	file, err := os.Create(pvk)
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	// 生成公钥文件
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	block = &pem.Block{
		Type:  "公钥",
		Bytes: derPkix,
	}
	pbk := path.Join(p, "public.pem")
	file, err = os.Create(pbk)
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	return nil
}

func genFilder(user string, basePath ...string) (string, error) {
	if len(basePath) == 0 {
		basicPath = "./"
	}
	for _, v := range basePath {
		basicPath = v
	}
	userPath := path.Join(basicPath, "keypool", user)
	return userPath, os.MkdirAll(userPath, os.ModePerm)
}

// GetKey 获取密钥[]byte
func GetKey(p string) ([]byte, error) {
	privateKey, err := ioutil.ReadFile(p)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error")
	}
	return block.Bytes, nil
}
