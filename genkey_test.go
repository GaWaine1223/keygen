package keygen

import (
	"encoding/base64"
	"fmt"
	"log"
	"testing"
)

func TestGenFilder(t *testing.T) {
	p, err := genFilder("111")
	if err != nil {
		println(err.Error())
	}
	println(p)
}

func TestGenRsaKey(t *testing.T) {
	bits := 1024
	if err := GenRsaKey(bits, "路达"); err != nil {
		log.Fatal("fail密钥文件生成失败！", err)
	}
	log.Println("密钥文件生成成功！")
}

func TestSignature(t *testing.T) {
	pub, ciphertext, err := Signature("路达", []byte("向优格特转账1000000"))
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}
	fmt.Println(string(pub))
	fmt.Println(ciphertext)
}

func TestVerify(t *testing.T) {
	data := "向优格特转账1000000"
	pub, ciphertext, err := Signature("路达", []byte(data))
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}
	pbKey, err := base64.StdEncoding.DecodeString(pub)
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}
	pbKey = pbKey[:]
	pub = base64.StdEncoding.EncodeToString(pbKey)
	err = Verify(pub, ciphertext, []byte(data))
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}
}
