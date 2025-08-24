package crypto

import (
	"crypto/rsa"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/malivvan/aegis/mgrd"
	"github.com/malivvan/aegis/opgp/gocrypto/openpgp/ecdh"
	"github.com/malivvan/aegis/opgp/gocrypto/openpgp/eddsa"
	"github.com/malivvan/aegis/opgp/profile"

	"github.com/stretchr/testify/assert"
)

const testTime = 1557754627 // 2019-05-13T13:37:07+00:00
const testMessage = "Hello world!"

var testPGP *PGPHandle
var testProfiles []*profile.Custom
var testProfileNames []string

func readTestFile(name string, trimNewlines bool) string {
	data, err := os.ReadFile("testdata/" + name) //nolint
	if err != nil {
		mgrd.SafePanic(err)
	}
	if trimNewlines {
		return strings.TrimRight(string(data), "\n")
	}
	return string(data)
}

func init() {
	testPGP = PGP()
	testPGP.defaultTime = NewConstantClock(testTime) // 2019-05-13T13:37:07+00:00
	testProfiles = []*profile.Custom{profile.Default(), profile.RFC4880(), profile.RFC9580()}
	testProfileNames = []string{"Default", "RFC4880", "RFC9580"}
	initEncDecTest()
	initGenerateKeys()
	initArmoredKeys()
	initKeyRings()
}

func assertBigIntCleared(t *testing.T, x *big.Int) {
	w := x.Bits()
	for k := range w {
		assert.Exactly(t, big.Word(0x00), w[k])
	}
}

func assertMemCleared(t *testing.T, b []byte) {
	for k := range b {
		assert.Exactly(t, uint8(0x00), b[k])
	}
}

func assertRSACleared(t *testing.T, rsaPriv *rsa.PrivateKey) {
	assertBigIntCleared(t, rsaPriv.D)
	for idx := range rsaPriv.Primes {
		assertBigIntCleared(t, rsaPriv.Primes[idx])
	}
	assertBigIntCleared(t, rsaPriv.Precomputed.Qinv)
	assertBigIntCleared(t, rsaPriv.Precomputed.Dp)
	assertBigIntCleared(t, rsaPriv.Precomputed.Dq)
}

func assertEdDSACleared(t *testing.T, priv *eddsa.PrivateKey) {
	assertMemCleared(t, priv.D)
}

func assertECDHCleared(t *testing.T, priv *ecdh.PrivateKey) {
	assertMemCleared(t, priv.D)
}
