// go-multikeypair/keypair.go
//
// Based on IPFS go-multihash, with the aim of being a potential
// addition to the suite of multiformat project types.

// TODO CLI tool for working with multikeypairs.
// TODO: Investigate cosign/minisign for generating, encoding/decoding?

package multikeypair

import (
	"encoding/binary"

	//"fmt"

	b58 "github.com/mr-tron/base58/base58"
	varint "github.com/multiformats/go-varint"
	cryptobyte "golang.org/x/crypto/cryptobyte"
)

// Ciphers
// -----------------------------------------------------------------------------

// Support ciphers. Accepting PRs for more!
const ()

// RecursiveNames is a mapping from cipher name to code.
var RecursiveNames = map[string]uint64{}

// RecursiveCodes is a mapping from cipher code to name.
var RecursiveCodes = map[uint64]string{}

// Recursivekey
// -----------------------------------------------------------------------------

// Recursivekey is a master key unpacked into a struct for easy access.
type Recursivekey struct {
	// Cipher identification code.
	Code uint64
	// Human-readable cipher name.
	Name string
	// Raw master key bytes.
	Master []byte
	// Length in bytes of master key.
	MasterLength int
	// Number of children
	ChildrenNum int
	// Derived children keypairs
	Children []Keypair
}

// Multirecursivekey
// -----------------------------------------------------------------------------

// Multirecusivekey is a byte slice with the following form:
// [length] (24-bit length prefix)
//   [code length]<code> (16-bit length prefix, uvarint code)
//   [master key length]<master key> (16-bit length prefix)
//   [childrenLen key length]<children number> (16-bit length prefix)
//   [children key length]<child keys> (16-bit length prefix)
type Multirecursivekey []byte

// Implementation
// -----------------------------------------------------------------------------

//
// ENCODE
//

func RecursiveEncode(master []byte, children []Keypair, code uint64) (Multirecursivekey, error) {
	if err := validRecursiveCode(code); err != nil {
		return Multirecursivekey{}, err
	}
	b := encodeRecursivekey(master, children, code)
	return Multirecursivekey(b), nil
}

// EncodeName encodes a keypair into a Multikeypair, specifying the keypair
// type using a string name instead of an integer code.
func EncodeRecursiveName(master []byte, children []Keypair, name string) (Multirecursivekey, error) {
	code := Names[name]
	return RecursiveEncode(master, children, code)
}

// Encode a Keypair struct into a Multikeypair.
func (k Recursivekey) RecursiveEncode() (Multirecursivekey, error) {
	if err := validRecursiveCode(k.Code); err != nil {
		return Multirecursivekey{}, err
	}
	return RecursiveEncode(k.Master, k.Children, k.Code)
}

// Check that the supplied code is one we recognize.
func validRecursiveCode(code uint64) error {
	for k := range RecursiveCodes {
		if k == code {
			return nil
		}
	}
	return ErrUnknownCode
}

// Pack key material and code type into an array of bytes.
func encodeRecursivekey(master []byte, children []Keypair, code uint64) []byte {
	codeBuf := PackCode(code)
	lenBuf := PackLen(len(children))

	var b cryptobyte.Builder

	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		// Store the code (packed as varint) with a length prefix.
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(codeBuf)
		})
		// Store the private key with a length prefix.
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(master)
		})

		// Store the children number.
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(lenBuf)
		})

		for _, child := range children {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(encodeKeypair(child.Private, child.Public, child.Code))
			})
		}
	})

	result, err := b.Bytes()
	if err != nil {
		panic(err)
	}

	return result
}

//
// DECODE
//

// Decode unpacks a multirecursivekey into a Recursivekey struct.
func RecursiveDecode(m Multirecursivekey) (Recursivekey, error) {
	keypair, err := decodeRecursivekey([]byte(m))
	if err != nil {
		return Recursivekey{}, err
	}

	return *keypair, nil
}

// Decode unpacks a multirecursivekey into a Recursivekey struct.
func (m Multirecursivekey) Decode() (Recursivekey, error) {
	return RecursiveDecode(m)
}

func decodeRecursivekey(buf []byte) (*Recursivekey, error) {
	input := cryptobyte.String(buf)

	// Extract the overall length of the data.
	var values cryptobyte.String
	if !input.ReadUint24LengthPrefixed(&values) || !input.Empty() {
		return nil, ErrInvalidMultikeypair
	}

	// Extract the code (packed as a varint)
	var code cryptobyte.String
	if !values.ReadUint16LengthPrefixed(&code) {
		return nil, ErrInvalidMultikeypair
	}
	// Code is a varint that needs to be unpacked into a uint64.
	numCode, err := UnpackCode(code)
	if err != nil {
		return nil, err
	}

	var master cryptobyte.String
	if !values.ReadUint16LengthPrefixed(&master) {
		return nil, ErrInvalidMultikeypair
	}

	var childrenNum cryptobyte.String
	if !values.ReadUint16LengthPrefixed(&childrenNum) {
		return nil, ErrInvalidMultikeypair
	}

	childLen, err := UnpackLen(childrenNum)
	if err != nil {
		return nil, err
	}

	var keypairs []Keypair
	for i := 0; i < childLen; i++ {
		var children cryptobyte.String
		if !values.ReadUint16LengthPrefixed(&children) {
			return nil, ErrInvalidMultikeypair
		}
		kp, err := decodeKeypair(children)
		if err != nil {
			return nil, err
		}
		keypairs = append(keypairs, *kp)
	}

	// Check that the cipher type code we decoded is valid.
	if err := validCode(numCode); err != nil {
		return nil, err
	}
	name := Codes[numCode]
	masterLength := len(master)

	keypair := &Recursivekey{
		Code:         numCode,
		Name:         name,
		Master:       master,
		MasterLength: masterLength,
		ChildrenNum:  childLen,
		Children:     keypairs,
	}

	return keypair, nil
}

func castRecursivekey(buf []byte) (Multirecursivekey, error) {
	_, err := decodeRecursivekey(buf)
	if err != nil {
		return Multirecursivekey{}, err
	}

	return Multirecursivekey(buf), nil
}

//
// Base-58
//

// B58String generates a base58-encoded version of a Multirecursive.
func (m Multirecursivekey) B58String() string {
	return b58.Encode([]byte(m))
}

// MultirecursivekeyFromB58 parses a base58-encoded hex string into a Multirecursivekey.
func MultirecursiveFromB58(s string) (Multirecursivekey, error) {
	b, err := b58.Decode(s)
	if err != nil {
		return Multirecursivekey{}, ErrInvalidMultikeypair
	}

	// Test if is valid by attempting to decode as Keypair.
	_, err = decodeKeypair(b)
	if err != nil {
		return Multirecursivekey{}, err
	}

	return castRecursivekey(b)
}

// MultirecursivekeyFromB58 parses a base58-encoded hex string into a Recursivekey.
func RecursivekeyFromB58(s string) (Recursivekey, error) {
	rk, err := MultirecursiveFromB58(s)
	if err != nil {
		return Recursivekey{}, err
	}

	// Now we have a nominal Multirecursivekey we can decode into a
	// Keypair struct.
	kp, err := rk.Decode()
	if err != nil {
		return Recursivekey{}, err
	}

	return kp, nil
}

// Utility functions
// -----------------------------------------------------------------------------

// PackLen packs a cipher code as varint.
func PackLen(len int) []byte {
	// Encode a uint64 into a buffer and return number of bytes
	// written. Panics if the buffer is too small.
	// l := *(*uint64)(unsafe.Pointer(&len))
	l := uint64(len)
	size := varint.UvarintSize(l)
	buf := make([]byte, size)
	varint.PutUvarint(buf, l)
	return buf
}

// UnpackLen unpacks a varint cipher code.
func UnpackLen(buf []byte) (int, error) {
	// Returns number of bytes read if successful. On error the
	// value is 0 and the of bytes is <= 0, meaning:
	// n == 0: buffer too small
	// n < 0: value larger than 64 bits (overflow)
	childLen, n := binary.Uvarint(buf)

	if n == 0 {
		return 0, ErrVarintBufferShort
	} else if n < 0 {
		return 0, ErrVarintTooLong
	} else {
		return int(childLen), nil
	}
}
