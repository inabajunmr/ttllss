package handshake

// https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.4
// struct {
//     opaque verify_data[Hash.length];
// } Finished;

type Finished struct {
	VerifyData []byte
}

func (ch Finished) Encode() []byte {
	return ch.VerifyData

}

func DecodeFinished(data []byte) Finished {
	return Finished{VerifyData: data}
}
