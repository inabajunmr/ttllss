package handshake

// ref. https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.3

// struct {
// 	ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
// 	Random random;
// 	opaque legacy_session_id_echo<0..32>;
// 	CipherSuite cipher_suite;
// 	uint8 legacy_compression_method = 0;
// 	Extension extensions<6..2^16-1>;
// } ServerHello;

type ServerHello struct {
	legacyVersion           ProtocolVersion
	random                  [32]byte
	legacySessionIdEcho     []byte
	cipherSuite             CipherSuite
	legacyCompressionMethod byte
	extensions              []Extension
}

func NewServerHello(
	legacyVersion ProtocolVersion,
	random [32]byte,
	legacySessionIdEcho []byte,
	cipherSuite CipherSuite,
	legacyCompressionMethod byte,
	extensions []Extension) ServerHello {
	return ServerHello{
		legacyVersion:           legacyVersion,
		random:                  random,
		legacySessionIdEcho:     legacySessionIdEcho,
		cipherSuite:             cipherSuite,
		legacyCompressionMethod: legacyCompressionMethod,
		extensions:              extensions,
	}
}

func (sh ServerHello) Encode() []byte {
	encoded := []byte{}

	// legacyVersion
	encoded = append(encoded, sh.legacyVersion.Encode()...)

	// random
	encoded = append(encoded, sh.random[:]...)

	// legacySessionId
	encoded = append(encoded, byte(len(sh.legacySessionIdEcho)))
	encoded = append(encoded, sh.legacySessionIdEcho[:]...)

	// cipherSuite
	encoded = append(encoded, sh.cipherSuite.Encode()...)

	// legacyCompressionMethod
	encoded = append(encoded, sh.legacyCompressionMethod)

	// extensions
	encoded = append(encoded, EncodeExtensions(sh.extensions)...)

	return encoded

}

func DecodeServerHello(data []byte) ServerHello {
	// legacyVersion
	data, legacyVersion := DecodeProtocolVersion(data)

	// random
	var random [32]byte
	copy(random[:], data[:32])
	data = data[32:]

	// legacySessionId
	legacySessionIdLength := data[0]
	data = data[1:]
	legacySessionId := data[:legacySessionIdLength]
	data = data[legacySessionIdLength:]

	// legacySessionIdEcho
	var cipherSuite CipherSuite
	data, cipherSuite = DecodeCipherSuite(data)

	// legacyCompressionMethod
	legacyCompressionMethod := data[0]
	data = data[1:]

	// extensions
	_, extensions := DecodeExtensions(data, false)

	return ServerHello{
		legacyVersion:           legacyVersion,
		random:                  random,
		legacySessionIdEcho:     legacySessionId,
		cipherSuite:             cipherSuite,
		legacyCompressionMethod: legacyCompressionMethod,
		extensions:              extensions,
	}
}
