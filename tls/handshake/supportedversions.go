package handshake

// https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.1

// struct {
// 	select (Handshake.msg_type) {
// 		case client_hello:
// 			 ProtocolVersion versions<2..254>;

// 		case server_hello: /* and HelloRetryRequest */
// 			 ProtocolVersion selected_version;
// 	};
// } SupportedVersions;

type SupportedVersionsExtention struct {
	isClientHello   bool
	versions        []ProtocolVersion
	selectedVersion ProtocolVersion
}

func NewSupportedVersionsForClient(versions []ProtocolVersion) SupportedVersionsExtention {
	return SupportedVersionsExtention{isClientHello: true, versions: versions}
}

func (s SupportedVersionsExtention) Encode() []byte {
	encoded := []byte{}
	encoded = append(encoded, SupportedVersions.Encode()...)

	if s.isClientHello {
		// length
		encoded = append(encoded, byte(len(s.versions)))
		for _, v := range s.versions {
			encoded = append(encoded, v.Encode()...)
		}
	} else {
		encoded = append(encoded, s.selectedVersion.Encode()...)
	}

	return encoded
}
