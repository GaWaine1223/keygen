package keygen

import (
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"path"
)

// Signature 返回的公钥和加密结果都是经过base64编码的
func Signature(user string, data []byte) (string, string, error) {
	pvKeyPath := path.Join(basicPath, "keypool", user, "private.pem")
	pbKeyPath := path.Join(basicPath, "keypool", user, "public.pem")
	pvKey, err := GetKey(pvKeyPath)
	pbKey, err := GetKey(pbKeyPath)
	priv, err := x509.ParsePKCS1PrivateKey(pvKey)
	if err != nil {
		return "", "", err
	}
	hashMD5 := md5.New()
	hashMD5.Write(data)
	Digest := hashMD5.Sum(nil)
	ciphertext, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.MD5, Digest)
	return base64.StdEncoding.EncodeToString(pbKey), base64.StdEncoding.EncodeToString(ciphertext), err
}

// Verify 验证发布信息属否有效
func Verify(p, c string, data []byte) error {
	pbKey, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		return err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(c)
	if err != nil {
		return err
	}
	pubv, err := x509.ParsePKIXPublicKey(pbKey)
	if err != nil {
		return err
	}
	pub := pubv.(*rsa.PublicKey)
	hashMD5 := md5.New()
	hashMD5.Write(data)
	Digest := hashMD5.Sum(nil)
	return rsa.VerifyPKCS1v15(pub, crypto.MD5, Digest, ciphertext)
}
