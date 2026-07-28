package internal

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func generateEd25519Keypair(t *testing.T) (expandedPrivHex, pubHex string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	// priv is 64 bytes: seed + public key
	return hex.EncodeToString(priv.Seed()) + hex.EncodeToString(priv.Public().(ed25519.PublicKey)), hex.EncodeToString(priv.Public().(ed25519.PublicKey))
}

func TestKeyStore_DecryptRoundTrip(t *testing.T) {
	edPrivHex, edPubHex := generateEd25519Keypair(t)
	ks, err := NewKeyStore(edPrivHex)
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}

	edPub, err := hex.DecodeString(edPubHex)
	if err != nil {
		t.Fatalf("decode ed pub: %v", err)
	}
	curvePub, err := ed25519PublicKeyToCurve25519(edPub)
	if err != nil {
		t.Fatalf("convert pub: %v", err)
	}

	plaintext, _ := json.Marshal(map[string]string{"msg": "hello"})
	ciphertext, err := box.SealAnonymous(nil, plaintext, &curvePub, rand.Reader)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	payload := &EncryptedPayload{
		FormatVersion: "1",
		KeyID:         "v1",
		CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
	}
	decrypted, err := ks.Decrypt(payload)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted = %s, want %s", decrypted, plaintext)
	}
}

func TestKeyStore_UnknownKeyID(t *testing.T) {
	edPrivHex, _ := generateEd25519Keypair(t)
	ks, _ := NewKeyStore(edPrivHex)
	_, err := ks.Decrypt(&EncryptedPayload{FormatVersion: "1", KeyID: "v99"})
	if err == nil {
		t.Error("expected error for unknown key id")
	}
}

func TestKeyStore_WrongPrivateKey(t *testing.T) {
	edPrivHex, _ := generateEd25519Keypair(t)
	ks, _ := NewKeyStore(edPrivHex)

	// Encrypt with a different public key.
	_, otherPriv, _ := box.GenerateKey(rand.Reader)
	pub, _, _ := box.GenerateKey(rand.Reader)
	_ = otherPriv
	plaintext := []byte("secret")
	ciphertext, _ := box.SealAnonymous(nil, plaintext, pub, rand.Reader)

	_, err := ks.Decrypt(&EncryptedPayload{FormatVersion: "1", KeyID: "v1", CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext)})
	if err == nil {
		t.Error("expected decryption failure with wrong key")
	}
}
