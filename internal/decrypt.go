package internal

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/nacl/box"
)

const maxCiphertextSize = maxReportBatchSize + box.AnonymousOverhead

var ErrDecryptionFailed = errors.New("decryption failed")

type EncryptedPayload struct {
	FormatVersion string `json:"v"`
	KeyID         string `json:"kid"`
	CiphertextB64 string `json:"ct"`
}
type encryptionKey struct{ public, private [32]byte }

// KeyStore holds immutable, precomputed X25519 key pairs.
// It is safe for concurrent decryption.
type KeyStore struct{ keys map[string]encryptionKey }

// NewKeyStore accepts comma-separated hex or base64 Ed25519 seeds or
// 64-byte seed||public keys. Optional kid=key entries support stable rotation;
// bare keys preserve the original positional v1, v2, ... identifiers.
func NewKeyStore(raw string) (*KeyStore, error) {
	ks := &KeyStore{keys: make(map[string]encryptionKey)}
	for i, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kid := fmt.Sprintf("v%d", i+1)
		// Base64 padding can contain '=', so only recognize a nonempty value
		// following a separator and validate the explicit identifier.
		if a, b, ok := strings.Cut(part, "="); ok && strings.Trim(b, "=") != "" {
			kid = strings.TrimSpace(a)
			part = strings.TrimSpace(b)
		}
		if !validKeyID(kid) {
			return nil, fmt.Errorf("key %d: invalid key ID", i+1)
		}
		if _, ok := ks.keys[kid]; ok {
			return nil, fmt.Errorf("key %d: duplicate key ID", i+1)
		}
		key, err := decodeEncryptionKey(part)
		if err != nil {
			return nil, fmt.Errorf("key %d: %w", i+1, err)
		}
		ks.keys[kid] = key
	}
	if len(ks.keys) == 0 {
		return nil, errors.New("no private keys configured")
	}
	return ks, nil
}
func validKeyID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}
func decodeEncryptionKey(raw string) (encryptionKey, error) {
	var key encryptionKey
	if len(raw) > 128 {
		return key, errors.New("invalid private key length")
	}
	var b []byte
	var err error
	if len(raw) == 64 || len(raw) == 128 {
		b, err = hex.DecodeString(raw)
	}
	if b == nil || err != nil {
		b, err = base64.StdEncoding.Strict().DecodeString(raw)
		if err != nil {
			b, err = base64.RawStdEncoding.Strict().DecodeString(raw)
		}
	}
	if err != nil {
		return key, errors.New("invalid private key encoding")
	}
	defer clear(b)
	if len(b) != ed25519.SeedSize && len(b) != ed25519.PrivateKeySize {
		return key, errors.New("private key must be 32 or 64 bytes")
	}
	ed := ed25519.NewKeyFromSeed(b[:ed25519.SeedSize])
	defer clear(ed)
	if len(b) == ed25519.PrivateKeySize && subtle.ConstantTimeCompare(b, ed) != 1 {
		return key, errors.New("inconsistent Ed25519 private key")
	}
	digest := sha512.Sum512(b[:ed25519.SeedSize])
	defer clear(digest[:])
	copy(key.private[:], digest[:32])
	key.private[0] &= 248
	key.private[31] &= 127
	key.private[31] |= 64
	priv, err := ecdh.X25519().NewPrivateKey(key.private[:])
	if err != nil {
		return encryptionKey{}, errors.New("invalid converted key")
	}
	copy(key.public[:], priv.PublicKey().Bytes())
	return key, nil
}

// Decrypt authenticates ciphertext integrity, not sender identity.
func (ks *KeyStore) Decrypt(payload *EncryptedPayload) ([]byte, error) {
	if ks == nil || payload == nil || payload.FormatVersion != "1" || !validKeyID(payload.KeyID) {
		return nil, ErrDecryptionFailed
	}
	key, ok := ks.keys[payload.KeyID]
	if !ok {
		return nil, ErrDecryptionFailed
	}
	if len(payload.CiphertextB64) > base64.StdEncoding.EncodedLen(maxCiphertextSize) {
		return nil, ErrDecryptionFailed
	}
	ct, err := base64.StdEncoding.Strict().DecodeString(payload.CiphertextB64)
	if err != nil || len(ct) < box.AnonymousOverhead || len(ct) > maxCiphertextSize {
		return nil, ErrDecryptionFailed
	}
	plaintext, ok := box.OpenAnonymous(nil, ct, &key.public, &key.private)
	if !ok {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}

// DecodeEncryptedBody validates the envelope. Also enforce HTTP body limits
// before reading the body into memory.
func DecodeEncryptedBody(body []byte) (*EncryptedPayload, error) {
	if len(body) > base64.StdEncoding.EncodedLen(maxCiphertextSize)+4096 {
		return nil, errors.New("encrypted body too large")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var payload *EncryptedPayload
	if err := dec.Decode(&payload); err != nil {
		return nil, fmt.Errorf("parse payload: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, ErrTrailingData
	}
	if payload == nil || payload.FormatVersion != "1" || !validKeyID(payload.KeyID) || payload.CiphertextB64 == "" || len(payload.CiphertextB64) > base64.StdEncoding.EncodedLen(maxCiphertextSize) {
		return nil, errors.New("invalid encrypted payload")
	}
	return payload, nil
}
