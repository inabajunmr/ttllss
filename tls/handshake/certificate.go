package handshake

//	enum {
//	    X509(0),
//	    RawPublicKey(2),
//	    (255)
//	} CertificateType;

const (
	X509         CertificateType = 0
	RawPublicKey CertificateType = 2
)

type CertificateType byte

// struct {
//     select (certificate_type) {
//         case RawPublicKey:
//           /* From RFC 7250 ASN.1_subjectPublicKeyInfo */
//           opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;

//         case X509:
//           opaque cert_data<1..2^24-1>;
//     };
//     Extension extensions<0..2^16-1>;
// } CertificateEntry;

type CertificateEntry struct {
	// ASN1_subjectPublicKeyInfo
	certData   []byte
	extensions []Extension
}

func (e CertificateEntry) encode() []byte {

	encoded := []byte{}

	var certDataLength [3]byte
	certDataLenInt := len(e.certData)
	certDataLength[0] = byte(certDataLenInt >> 16 & 0xFF)
	certDataLength[1] = byte(certDataLenInt >> 8 & 0xFF)
	certDataLength[2] = byte(certDataLenInt & 0xFF)
	encoded = append(encoded, certDataLength[:]...)

	encoded = append(encoded, e.certData...)

	for _, v := range e.extensions {
		encoded = append(encoded, v.Encode()...)
	}
	return encoded
}

func decodeCertificateEntry(data []byte) CertificateEntry {
	var length [3]byte
	copy(length[:], data[:3])
	lengthInt := int(length[0])<<16 | int(length[1])<<8 | int(length[2])

	data = data[3:]

	certData := data[:lengthInt]
	remain := data[lengthInt:]

	_, extensions := DecodeExtensions(remain, false)

	return CertificateEntry{
		certData:   certData,
		extensions: extensions,
	}
}

// struct {
//     opaque certificate_request_context<0..2^8-1>;
//     CertificateEntry certificate_list<0..2^24-1>;
// } Certificate;

type Certificate struct {
	certificateRequestContext []byte
	certificateList           []CertificateEntry
}

func (c Certificate) Encode() []byte {
	encoded := []byte{}
	encoded = append(encoded, byte(len(c.certificateRequestContext)))
	encoded = append(encoded, c.certificateRequestContext...)

	encodedCertificateList := []byte{}
	for _, v := range c.certificateList {
		encodedCertificateList = append(encodedCertificateList, v.encode()...)
	}

	var certificateListLength [3]byte
	certificateListLengthByte := len(encodedCertificateList)
	certificateListLength[0] = byte(certificateListLengthByte >> 16 & 0xFF)
	certificateListLength[1] = byte(certificateListLengthByte >> 8 & 0xFF)
	certificateListLength[2] = byte(certificateListLengthByte & 0xFF)
	encoded = append(encoded, certificateListLength[:]...)

	encoded = append(encoded, encodedCertificateList...)

	return encoded
}

func DecodeCertificate(data []byte) Certificate {
	// TODO ここから

	return Certificate{}
}
