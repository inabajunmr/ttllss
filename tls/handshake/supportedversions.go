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

type SupportedVersions struct {
	isClient        bool
	versions        []ProtocolVersion
	selectedVersion ProtocolVersion
}

func NewSupportedVersionsForClient(versions []ProtocolVersion) SupportedVersions {
	return SupportedVersions{isClient: true, versions: versions}
}

func (s SupportedVersions) Encode() []byte {
	encoded := []byte{}

	if s.isClient {
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
