package handshake

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
)

// ref. https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
// struct {
// 	ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
// 	Random random;
// 	opaque legacy_session_id<0..32>;
// 	CipherSuite cipher_suites<2..2^16-2>;
// 	opaque legacy_compression_methods<1..2^8-1>;
// 	Extension extensions<8..2^16-1>;
// } ClientHello;

type ClientHello struct {
	// In previous versions of TLS, this field was used for version negotiation and represented the highest version number supported by the client. Experience has shown that many servers do not properly implement version negotiation, leading to "version intolerance" in which the server rejects an otherwise acceptable ClientHello with a version number higher than it supports. In TLS 1.3, the client indicates its version preferences in the "supported_versions" extension (Section 4.2.1) and the legacy_version field MUST be set to 0x0303, which is the version number for TLS 1.2. TLS 1.3 ClientHellos are identified as having a legacy_version of 0x0303 and a supported_versions extension present with 0x0304 as the highest version indicated therein. (See Appendix D for details about backward compatibility.)
	legacyVersion ProtocolVersion
	// 32 bytes generated by a secure random number generator. See Appendix C for additional information.
	random [32]byte
	// Versions of TLS before TLS 1.3 supported a "session resumption" feature which has been merged with pre-shared keys in this version (see Section 2.2). A client which has a cached session ID set by a pre-TLS 1.3 server SHOULD set this field to that value. In compatibility mode (see Appendix D.4), this field MUST be non-empty, so a client not offering a pre-TLS 1.3 session MUST generate a new 32-byte value. This value need not be random but SHOULD be unpredictable to avoid implementations fixating on a specific value (also known as ossification). Otherwise, it MUST be set as a zero-length vector (i.e., a zero-valued single byte length field).
	legacySessionId []byte
	// A list of the symmetric cipher options supported by the client, specifically the record protection algorithm (including secret key length) and a hash to be used with HKDF, in descending order of client preference. Values are defined in Appendix B.4. If the list contains cipher suites that the server does not recognize, support, or wish to use, the server MUST ignore those cipher suites and process the remaining ones as usual. If the client is attempting a PSK key establishment, it SHOULD advertise at least one cipher suite indicating a Hash associated with the PSK.
	cipherSuites []CipherSuite
	// Versions of TLS before 1.3 supported compression with the list of supported compression methods being sent in this field. For every TLS 1.3 ClientHello, this vector MUST contain exactly one byte, set to zero, which corresponds to the "null" compression method in prior versions of TLS. If a TLS 1.3 ClientHello is received with any other value in this field, the server MUST abort the handshake with an "illegal_parameter" alert. Note that TLS 1.3 servers might receive TLS 1.2 or prior ClientHellos which contain other compression methods and (if negotiating such a prior version) MUST follow the procedures for the appropriate prior version of TLS.
	legacyCompressionMethods []byte
	// Clients request extended functionality from servers by sending data in the extensions field. The actual "Extension" format is defined in Section 4.2. In TLS 1.3, the use of certain extensions is mandatory, as functionality has moved into extensions to preserve ClientHello compatibility with previous versions of TLS. Servers MUST ignore unrecognized extensions.
	extensions []Extension
}

func NewClientHello(cipherSuites []CipherSuite, extensions []Extension) ClientHello {

	var random [32]byte
	rand.Read(random[:])
	var legacySessionId [32]byte
	rand.Read(legacySessionId[:])

	return ClientHello{
		legacyVersion:            0x0303,
		random:                   random,
		legacySessionId:          legacySessionId[:],
		cipherSuites:             cipherSuites,
		legacyCompressionMethods: []byte{0},
		extensions:               extensions,
	}
}

func (ch ClientHello) Encode() []byte {
	encoded := []byte{}

	// legacyVersion
	encoded = append(encoded, ch.legacyVersion.Encode()...)

	// random
	encoded = append(encoded, ch.random[:]...)

	// legacySessionId
	encoded = append(encoded, byte(len(ch.legacySessionId)))
	encoded = append(encoded, ch.legacySessionId[:]...)

	// cipherSuites
	cipherSuitesLenBytes := make([]byte, 2)
	cipherSuitesLen := uint16(len(ch.cipherSuites) * 2) // * 2 because 1 cipher suite accounts for 2 bytes
	binary.BigEndian.PutUint16(cipherSuitesLenBytes, cipherSuitesLen)
	encoded = append(encoded, cipherSuitesLenBytes...)

	for _, v := range ch.cipherSuites {
		encoded = append(encoded, v.Encode()...)
	}

	// legacyCompressionMethods
	encoded = append(encoded, byte(len(ch.legacyCompressionMethods)))
	encoded = append(encoded, ch.legacyCompressionMethods[:]...)

	// extensions
	encoded = append(encoded, EncodeExtensions(ch.extensions)...)

	return encoded
}

func DecodeClientHello(data []byte) ClientHello {
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

	// cipherSuites
	cipherSuitesLengthByte := data[:2]
	var cipherSuitesLength uint16
	binary.Read(bytes.NewReader(cipherSuitesLengthByte), binary.BigEndian, &cipherSuitesLength)
	data = data[2:]

	var cipherSuites []CipherSuite
	// cipher suite accounts for 2 bytes so cipherSuitesLength/2 = len(CihperSuites)
	for i := 0; i < int(cipherSuitesLength/2); i++ {
		var cipherSuite CipherSuite
		data, cipherSuite = DecodeCipherSuite(data)
		cipherSuites = append(cipherSuites, cipherSuite)
	}

	// legacyCompressionMethods
	legacyCompressionMethodsLength := data[0]
	data = data[1:]
	legacyCompressionMethods := data[:legacyCompressionMethodsLength]
	data = data[legacyCompressionMethodsLength:]

	// extensions
	_, extensions := DecodeExtensions(data, true)

	return ClientHello{
		legacyVersion:            legacyVersion,
		random:                   random,
		legacySessionId:          legacySessionId,
		cipherSuites:             cipherSuites,
		legacyCompressionMethods: legacyCompressionMethods,
		extensions:               extensions,
	}
}
