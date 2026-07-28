package internal

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/nacl/box"
)

// EncryptedPayload matches the shape produced by the platform reporter.
type EncryptedPayload struct {
	FormatVersion string `json:"v"`
	KeyID         string `json:"kid"`
	CiphertextB64 string `json:"ct"`
}

// KeyStore holds Ed25519 private keys indexed by key ID. The function needs
// the private key that corresponds to the public key embedded in the platform
// binary.
type KeyStore struct {
	keys map[string][64]byte // Ed25519 expanded private key
}

// NewKeyStore builds a keystore from a comma-separated list of private keys.
// Each key may be hex-encoded (128 chars for expanded Ed25519) or base64.
func NewKeyStore(raw string) (*KeyStore, error) {
	ks := &KeyStore{keys: make(map[string][64]byte)}
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("no private keys configured")
	}
	for i, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		pk, err := decodeEd25519PrivateKey(part)
		if err != nil {
			return nil, fmt.Errorf("key %d: %w", i, err)
		}
		ks.keys[fmt.Sprintf("v%d", i+1)] = pk
	}
	if len(ks.keys) == 0 {
		return nil, errors.New("no valid private keys decoded")
	}
	return ks, nil
}

// Decrypt verifies and decrypts a payload.
func (ks *KeyStore) Decrypt(payload *EncryptedPayload) ([]byte, error) {
	if payload.FormatVersion != "1" {
		return nil, fmt.Errorf("unsupported format version %q", payload.FormatVersion)
	}
	edPriv, ok := ks.keys[payload.KeyID]
	if !ok {
		return nil, fmt.Errorf("unknown key id %q", payload.KeyID)
	}
	curvePriv, err := ed25519PrivateKeyToCurve25519(edPriv[:])
	if err != nil {
		return nil, err
	}
	curvePub, err := ed25519PublicKeyToCurve25519(edPriv[32:])
	if err != nil {
		return nil, err
	}
	ct, err := base64.StdEncoding.DecodeString(payload.CiphertextB64)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	plaintext, ok := box.OpenAnonymous(nil, ct, &curvePub, &curvePriv)
	if !ok {
		return nil, errors.New("decryption failed")
	}
	return plaintext, nil
}

// decodeEd25519PrivateKey accepts a hex or base64 Ed25519 expanded private key
// (64 bytes). If a 32-byte seed is provided, it is expanded.
func decodeEd25519PrivateKey(raw string) ([64]byte, error) {
	var out [64]byte
	var b []byte
	var err error
	if len(raw) == 128 {
		b, err = hex.DecodeString(raw)
	} else if len(raw) == 64 {
		b, err = hex.DecodeString(raw)
		if err != nil {
			b, err = base64.StdEncoding.DecodeString(raw)
		}
	} else {
		b, err = base64.StdEncoding.DecodeString(raw)
	}
	if err != nil {
		return out, fmt.Errorf("decode private key: %w", err)
	}
	if len(b) == 32 {
		return out, errors.New("32-byte seed keys are not supported; provide the 64-byte expanded Ed25519 private key")
	}
	if len(b) != 64 {
		return out, fmt.Errorf("private key must be 64 bytes, got %d", len(b))
	}
	copy(out[:], b)
	return out, nil
}

// ed25519PublicKeyToCurve25519 converts an Ed25519 public key to Curve25519.
func ed25519PublicKeyToCurve25519(edPub []byte) ([32]byte, error) {
	var curvePub [32]byte
	if len(edPub) != 32 {
		return curvePub, fmt.Errorf("ed25519 public key must be 32 bytes, got %d", len(edPub))
	}
	p, err := new(edwards25519.Point).SetBytes(edPub)
	if err != nil {
		return curvePub, fmt.Errorf("parse edwards point: %w", err)
	}
	copy(curvePub[:], p.BytesMontgomery())
	return curvePub, nil
}

// ed25519PrivateKeyToCurve25519 converts an Ed25519 expanded private key
// (64 bytes) to a Curve25519 private key.
func ed25519PrivateKeyToCurve25519(edPriv []byte) ([32]byte, error) {
	var curvePriv [32]byte
	if len(edPriv) != 64 && len(edPriv) != 32 {
		return curvePriv, fmt.Errorf("ed25519 private key must be 32 or 64 bytes, got %d", len(edPriv))
	}
	seed := edPriv[:32]
	h := sha512.Sum512(seed)
	copy(curvePriv[:], h[:])
	curvePriv[0] &= 248
	curvePriv[31] &= 127
	curvePriv[31] |= 64
	return curvePriv, nil
}

// DecodeEncryptedBody parses the HTTP request body into an EncryptedPayload.
func DecodeEncryptedBody(body []byte) (*EncryptedPayload, error) {
	// The platform sends the encrypted payload directly as a JSON object.
	var payload EncryptedPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("parse payload: %w", err)
	}
	return &payload, nil
}
