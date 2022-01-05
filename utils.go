package paillier

import (
	"fmt"
	"math/big"
)

func equals(a *big.Int, b int64) bool {
	return a.Cmp(big.NewInt(b)) == 0
}

func bigMul(a, b, mod *big.Int) *big.Int {
	bigAB := new(big.Int).Mul(a, b)
	return bigAB.Mod(bigAB, mod)
}

func pow(a, step, mod *big.Int) *big.Int {
	return new(big.Int).Exp(a, step, mod)
}

func gcd(a, b *big.Int) *big.Int {
	return new(big.Int).GCD(nil, nil, a, b)
}

func lcm(a, b *big.Int) *big.Int {
	g := gcd(a, b)
	h := new(big.Int).Div(a, g)
	return h.Mul(h, b)
}

func dec(a *big.Int) *big.Int {
	return new(big.Int).Sub(a, big.NewInt(1))
}

func inc(a *big.Int) *big.Int {
	return new(big.Int).Add(a, big.NewInt(1))
}

func square(a *big.Int) *big.Int {
	return new(big.Int).Mul(a, a)
}

func l(u, n *big.Int) *big.Int {
	h1 := dec(u)
	return h1.Div(h1, n)
}

func rev(a, n *big.Int) (*big.Int, error) {
	result := new(big.Int).ModInverse(a, n)

	if result == nil {
		fmt.Println("Mod Inverse operation error!")
		return nil, InverseError{}
	} else {
		return result, nil
	}
}

