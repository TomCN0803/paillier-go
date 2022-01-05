package paillier

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

func Test() {
	fmt.Println("\n--------Paillier test--------")

	scheme := GetInstance(rand.Reader, 128)
	privateKey := scheme.GenKeypair()

	s1 := scheme.Encrypt(privateKey.PublicKey, &PrivateValue{Val: big.NewInt(102)})
	fmt.Println("Encrypted data 102:", s1)
	fmt.Println("Decrypted data 102:", scheme.Decrypt(privateKey, s1).Val.Int64())

	s2 := scheme.Encrypt(privateKey.PublicKey, &PrivateValue{Val: big.NewInt(200)})
	fmt.Println("Encrypted data 102:", s2)
	fmt.Println("Decrypted data 102:", scheme.Decrypt(privateKey, s2).Val.Int64())

	s := scheme.Add(s1, s2, privateKey.PublicKey)
	fmt.Println("Decrypted sum:", scheme.Decrypt(privateKey, s).Val.Int64())

	ss := scheme.Mul(s1, big.NewInt(100), privateKey.PublicKey)
	fmt.Println("Mul on unencrypted val", scheme.Decrypt(privateKey, ss).Val.Int64())

	sss := scheme.Sub(s2, s1, privateKey.PublicKey)
	fmt.Println("Decrypted sub:", scheme.Decrypt(privateKey, sss).Val.Int64())

	var cnt = 0

	for i := 0; i < 1000; i++ {
		val, _ := rand.Int(rand.Reader, big.NewInt(1000000000))
		enc := scheme.Encrypt(privateKey.PublicKey, &PrivateValue{Val: val})
		dec := scheme.Decrypt(privateKey, enc).Val

		if val.Cmp(dec) != 0 {
			cnt++
			fmt.Println(val, dec, enc)
		}
	}

	fmt.Println(cnt)

	fmt.Println("--------Paillier test end--------\n\n\n")
}

