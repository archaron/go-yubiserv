package common

type testVector struct {
	AESKey []byte
	Text   string
	OTP
}

// TestVectors for OTP testing.
var TestVectors = map[string]testVector{ //nolint:gochecknoglobals
	"dvgtiblfkbgturecfllberrvkinnctnn": {
		AESKey: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
		OTP: OTP{
			PrivateID:        [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			UsageCounter:     1,
			TimestampCounter: [3]byte{0x01, 0x00, 0x01},
			SessionCounter:   1,
			CRC:              0xfe36, //nolint:mnd
		},
		Text: "OTP: PrivateID: 010203040506, Usage counter: 0001, Session counter: 01, Timestamp couner: 010001, Random: 0000, CRC: fe36",
	},
	"rnibcnfhdninbrdebccrndfhjgnhftee": {
		AESKey: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
		OTP: OTP{
			PrivateID:        [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			UsageCounter:     1,
			TimestampCounter: [3]byte{0x01, 0x00, 0x01},
			SessionCounter:   2,      //nolint:mnd
			CRC:              0x1152, //nolint:mnd
		},
		Text: "OTP: PrivateID: 010203040506, Usage counter: 0001, Session counter: 02, Timestamp couner: 010001, Random: 0000, CRC: 1152",
	},
	"iikkijbdknrrdhfdrjltvgrbkkjblcbh": {
		AESKey: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
		OTP: OTP{
			PrivateID:        [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			UsageCounter:     0x0fff, //nolint:mnd
			TimestampCounter: [3]byte{0x01, 0x00, 0x01},
			SessionCounter:   1,
			CRC:              0x9454, //nolint:mnd
		},
		Text: "OTP: PrivateID: 010203040506, Usage counter: 0fff, Session counter: 01, Timestamp couner: 010001, Random: 0000, CRC: 9454",
	},
	"dcihgvrhjeucvrinhdfddbjhfjftjdei": {
		AESKey: []byte{0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88},
		OTP: OTP{
			PrivateID:        [6]byte{0x88, 0x88, 0x88, 0x88, 0x88, 0x88},
			UsageCounter:     0x8888, //nolint:mnd
			TimestampCounter: [3]byte{0x88, 0x88, 0x88},
			SessionCounter:   0x88,   //nolint:mnd
			Random:           0x8888, //nolint:mnd
			CRC:              0xd3b6, //nolint:mnd
		},
		Text: "OTP: PrivateID: 888888888888, Usage counter: 8888, Session counter: 88, Timestamp couner: 888888, Random: 8888, CRC: d3b6",
	},
	"kkkncjnvcnenkjvjgncjihljiibgbhbh": {
		AESKey: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		OTP: OTP{
			PrivateID:        [6]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			TimestampCounter: [3]byte{0x00, 0x00, 0x00},
			CRC:              0xa96a, //nolint:mnd
		},
		Text: "OTP: PrivateID: 000000000000, Usage counter: 0000, Session counter: 00, Timestamp couner: 000000, Random: 0000, CRC: a96a",
	},
	"iucvrkjiegbhidrcicvlgrcgkgurhjnj": {
		AESKey: []byte{0xc4, 0x42, 0x28, 0x90, 0x65, 0x30, 0x76, 0xcd, 0xe7, 0x3d, 0x44, 0x9b, 0x19, 0x1b, 0x41, 0x6a},
		OTP: OTP{
			PrivateID:        [6]byte{0x33, 0xc6, 0x9e, 0x7f, 0x24, 0x9e},
			UsageCounter:     0x01, //nolint:mnd
			TimestampCounter: [3]byte{0x24, 0x13, 0xa7},
			Random:           0xc63c, //nolint:mnd
			CRC:              0x1c86, //nolint:mnd
		},
		Text: "OTP: PrivateID: 33c69e7f249e, Usage counter: 0001, Session counter: 00, Timestamp couner: 2413a7, Random: c63c, CRC: 1c86",
	},
}
