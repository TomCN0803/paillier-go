package paillier

import (
	"crypto/rand"
	"io"
	"math/big"
)

const defaultKeySize int = 128

type PublicKey struct {
	P_n  *big.Int
	P_nn *big.Int
	P_g  *big.Int
}

type PrivateKey struct {
	PublicKey *PublicKey
	P_h       *big.Int
	P_u       *big.Int
}

type PublicValue struct {
	Val *big.Int
}

type PrivateValue struct {
	Val *big.Int
}

type InverseError struct {
}

func (e InverseError) Error() string {
	return "Mod inverse error!"
}

type PaillierScheme interface {
	Encrypt(key *PublicKey, m *PrivateValue) *PublicValue

	Decrypt(key *PrivateKey, c *PublicValue) *PrivateValue

	GenKeypair() *PrivateKey

	Add(a *PublicValue, b *PublicValue, key *PublicKey) *PublicValue

	Mul(a *PublicValue, b *big.Int, key *PublicKey) *PublicValue

	Sub(a *PublicValue, b *PublicValue, key *PublicKey) *PublicValue
}

type paillier struct {
	P            *big.Int
	Q            *big.Int
	randomReader io.Reader
}

func (p *paillier) GenKeypair() *PrivateKey {
	n := new(big.Int).Mul(p.P, p.Q)
	nn := square(n)
	g := inc(n)

	h := lcm(dec(p.P), dec(p.Q))
	u, err := rev(l(pow(g, h, nn), n), n)

	if err != nil {
		panic(err)
	}

	return &PrivateKey{
		PublicKey: &PublicKey{
			P_n:  n,
			P_nn: nn,
			P_g:  g,
		},
		P_h: h,
		P_u: u,
	}
}

func (p *paillier) Encrypt(key *PublicKey, m *PrivateValue) *PublicValue {
	r, err := rand.Int(p.randomReader, key.P_n)
	if err != nil {
		panic(err)
	}

	s1 := pow(key.P_g, m.Val, key.P_nn)
	s2 := pow(r, key.P_n, key.P_nn)
	return &PublicValue{bigMul(s1, s2, key.P_nn)}
}

func (p *paillier) Decrypt(key *PrivateKey, c *PublicValue) *PrivateValue {
	ch := pow(c.Val, key.P_h, key.PublicKey.P_nn)
	lVal := l(ch, key.PublicKey.P_n)
	return &PrivateValue{bigMul(lVal, key.P_u, key.PublicKey.P_n)}
}

func (p *paillier) Add(a *PublicValue, b *PublicValue, key *PublicKey) *PublicValue {
	return &PublicValue{Val: bigMul(a.Val, b.Val, key.P_nn)}
}

func (p *paillier) Mul(a *PublicValue, b *big.Int, key *PublicKey) *PublicValue {
	return &PublicValue{Val: pow(a.Val, b, key.P_nn)}
}

func (p *paillier) Sub(a *PublicValue, b *PublicValue, key *PublicKey) *PublicValue {
	revB, err := rev(b.Val, key.P_nn)
	if err != nil {
		panic(err)
	}

	return &PublicValue{Val: bigMul(a.Val, revB, key.P_nn)}
}

func GetDefaultInstance() PaillierScheme {
	var instance = paillier{randomReader: rand.Reader}

	p, err := rand.Prime(rand.Reader, defaultKeySize)
	if err != nil {
		panic(err)
	}

	q, err := rand.Prime(rand.Reader, defaultKeySize)
	if err != nil {
		panic(err)
	}

	instance.P, instance.Q = p, q
	return &instance
}

func GetInstance(random io.Reader, keySize int) PaillierScheme {
	var instance = paillier{randomReader: random}

	p, err := rand.Prime(random, keySize)
	if err != nil {
		panic(err)
	}

	q, err := rand.Prime(random, keySize)
	if err != nil {
		panic(err)
	}

	instance.P, instance.Q = p, q
	return &instance
}
