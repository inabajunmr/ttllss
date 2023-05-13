package key

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

type ClientKeys struct {
	curve                  elliptic.Curve
	clientPrivateKey       ecdsa.PrivateKey
	serverPubX, serverPubY *big.Int
}

func (k *ClientKeys) SetCurve(curve elliptic.Curve) {
	k.curve = curve
}

func (k *ClientKeys) SetClientPrivateKey(privateKey ecdsa.PrivateKey) {
	k.clientPrivateKey = privateKey
}

func (k *ClientKeys) SetServerPublicKey(serverPubX, serverPubY *big.Int) {
	k.serverPubX = serverPubX
	k.serverPubY = serverPubY
}

func (k ClientKeys) GetECDHESharedKey() []byte {
	x, _ := k.curve.ScalarMult(k.serverPubX, k.serverPubY, k.clientPrivateKey.D.Bytes())
	return x.Bytes()
}

// TODO test
// 0
// |
// v
// PSK ->  HKDF-Extract = Early Secret
func (k ClientKeys) GetEarlySecret() []byte {
	hash := sha256.New
	return hkdf.Extract(hash, make([]byte, 32), []byte{})
}

// |
// +-----> Derive-Secret(., "ext binder" | "res binder", "")
// |                     = binder_key
// |
// +-----> Derive-Secret(., "c e traffic", ClientHello)
// |                     = client_early_traffic_secret
// |
// +-----> Derive-Secret(., "e exp master", ClientHello)
// |                     = early_exporter_master_secret
// v
// Derive-Secret(., "derived", "")
// |
// v
// (EC)DHE -> HKDF-Extract = Handshake Secret
func (k ClientKeys) GetHandshakeSecret() []byte {
	return hkdf.Extract(sha256.New, k.GetECDHESharedKey(), DeriveSecret(k.GetEarlySecret(), []byte("derived"), []byte{}))
}

// |
// +-----> Derive-Secret(., "c hs traffic",
// |                     ClientHello...ServerHello)
// |                     = client_handshake_traffic_secret
// |
// +-----> Derive-Secret(., "s hs traffic",
// |                     ClientHello...ServerHello)
// |                     = server_handshake_traffic_secret
func (k ClientKeys) GetServerHandshakeTrafficSecret(messages ...[]byte) []byte {
	return DeriveSecret(k.GetHandshakeSecret(), []byte("s hs traffic"), messages...)
}

// v
// Derive-Secret(., "derived", "")
// |
// v
// 0 -> HKDF-Extract = Master Secret
// |
// +-----> Derive-Secret(., "c ap traffic",
// |                     ClientHello...server Finished)
// |                     = client_application_traffic_secret_0
// |
// +-----> Derive-Secret(., "s ap traffic",
// |                     ClientHello...server Finished)
// |                     = server_application_traffic_secret_0
// |
// +-----> Derive-Secret(., "exp master",
// |                     ClientHello...server Finished)
// |                     = exporter_master_secret
// |
// +-----> Derive-Secret(., "res master",
// 					  ClientHello...client Finished)
// 					  = resumption_master_secret
