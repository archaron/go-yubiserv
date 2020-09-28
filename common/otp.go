package common

import (
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/archaron/go-yubiserv/misc"
	"github.com/howeyc/crc16"
	"gopkg.in/errgo.v2/fmt/errors"
)

type (
	OTP struct {
		PrivateID        [6]byte
		UsageCounter     uint16
		TimestampCounter [3]byte
		SessionCounter   uint8
		Random           uint16
		CRC              uint16
	}
)

func (O *OTP) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 16)
	copy(data, O.PrivateID[:])
	binary.LittleEndian.PutUint16(data[6:8], O.UsageCounter)
	data[8] = O.TimestampCounter[2]
	data[9] = O.TimestampCounter[1]
	data[10] = O.TimestampCounter[0]
	data[11] = O.SessionCounter
	binary.LittleEndian.PutUint16(data[12:14], O.Random)
	binary.LittleEndian.PutUint16(data[14:16], crc16.ChecksumCCITT(data[:14]))
	return data, nil
}

func (O *OTP) String() string {
	return fmt.Sprintf("OTP: PrivateID: %012x, Usage counter: %02x, Session counter: %02x, Timestamp couner: %6x, Random: %04x, CRC: %2x", O.PrivateID, O.UsageCounter, O.SessionCounter, O.TimestampCounter, O.Random, O.CRC)
}

func (O *OTP) UnmarshalBinary(data []byte) error {

	// Read CRC first and check if OTP is valid
	O.CRC = binary.LittleEndian.Uint16(data[14:16])

	if crc := crc16.ChecksumCCITT(data[:14]); crc != O.CRC {
		return errors.Newf("OTP CRC mismatch must be 0x%04x but is 0x%04x", O.CRC, crc)
	}

	// Read the remaining data
	copy(O.PrivateID[:], data[:6])                           // Private identifier
	O.UsageCounter = binary.LittleEndian.Uint16(data[6:8])   // Usage counter
	O.TimestampCounter = [3]byte{data[10], data[9], data[8]} // Timestamp counter
	O.SessionCounter = data[11]                              // Session counter
	O.Random = binary.LittleEndian.Uint16(data[12:14])       // Random padding

	return nil
}

func (O *OTP) Decrypt(key []byte, payload []byte) error {
	a, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	decrypted := make([]byte, len(payload))
	a.Decrypt(decrypted, payload)

	if err := O.UnmarshalBinary(decrypted); err != nil {
		return err
	}

	return nil
}

func (O *OTP) Encrypt(key []byte) ([]byte, error) {
	a, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	payload, err := O.MarshalBinary()
	if err != nil {
		return nil, err
	}

	result := make([]byte, len(payload))
	a.Encrypt(result, payload)

	return result, nil
}

func (O *OTP) EncryptToModhex(key []byte) (string, error) {
	data, err := O.Encrypt(key)
	if err != nil {
		return "", err
	}

	return misc.Hex2modhex(hex.EncodeToString(data)), nil
}
