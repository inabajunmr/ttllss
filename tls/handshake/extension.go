package handshake

// ref. https://datatracker.ietf.org/doc/html/rfc8446#section-4.2

type Extension interface {
	Encode() []byte
}
