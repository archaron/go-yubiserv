package common

import (
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/howeyc/crc16"
	"gopkg.in/errgo.v2/fmt/errors"

	"github.com/archaron/go-yubiserv/misc"
)

// OTP yubikey's otp record representation.
type OTP struct {
	PrivateID        [6]byte
	UsageCounter     uint16
	TimestampCounter [3]byte
	SessionCounter   uint8
	Random           uint16
	CRC              uint16
}

// MarshalBinary marshals OTP structure to slice of bytes.
func (o *OTP) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 16)
	copy(data, o.PrivateID[:])
	binary.LittleEndian.PutUint16(data[6:8], o.UsageCounter)
	data[8] = o.TimestampCounter[2]
	data[9] = o.TimestampCounter[1]
	data[10] = o.TimestampCounter[0]
	data[11] = o.SessionCounter
	binary.LittleEndian.PutUint16(data[12:14], o.Random)
	binary.LittleEndian.PutUint16(data[14:16], crc16.ChecksumCCITT(data[:14]))
	return data, nil
}

func (o *OTP) String() string {
	return fmt.Sprintf("OTP: PrivateID: %012x, Usage counter: %04x, Session counter: %02x, Timestamp couner: %6x, "+
		"Random: %04x, CRC: %2x", o.PrivateID, o.UsageCounter, o.SessionCounter, o.TimestampCounter, o.Random, o.CRC)
}

// UnmarshalBinary unmarshalls OTP from binary bytes.
func (o *OTP) UnmarshalBinary(data []byte) error {
	// Read CRC first and check if OTP is valid
	o.CRC = binary.LittleEndian.Uint16(data[14:16])

	if crc := crc16.ChecksumCCITT(data[:14]); crc != o.CRC {
		return errors.Newf("OTP CRC mismatch must be 0x%04x but is 0x%04x", o.CRC, crc)
	}

	// Read the remaining data
	copy(o.PrivateID[:], data[:6])                           // Private identifier
	o.UsageCounter = binary.LittleEndian.Uint16(data[6:8])   // Usage counter
	o.TimestampCounter = [3]byte{data[10], data[9], data[8]} // Timestamp counter
	o.SessionCounter = data[11]                              // Session counter
	o.Random = binary.LittleEndian.Uint16(data[12:14])       // Random padding

	return nil
}

// Decrypt decrypts encrypted OTP with given encryption key from payload and unmarshalls it.
func (o *OTP) Decrypt(key []byte, payload []byte) error {
	a, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	decrypted := make([]byte, len(payload))
	a.Decrypt(decrypted, payload)

	if err := o.UnmarshalBinary(decrypted); err != nil {
		return err
	}

	return nil
}

// Encrypt encrypts current OTP structure with given encryption key and returns encrypted bytes.
func (o *OTP) Encrypt(key []byte) ([]byte, error) {
	a, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	payload, _ := o.MarshalBinary() // always returns nil as error

	result := make([]byte, len(payload))
	a.Encrypt(result, payload)

	return result, nil
}

// EncryptToModhex encrypts current OTP structure with given encryption key and returns encrypted modhex representation.
func (o *OTP) EncryptToModhex(key []byte) (string, error) {
	data, err := o.Encrypt(key)
	if err != nil {
		return "", err
	}

	return misc.HexToModHex(hex.EncodeToString(data)), nil
}
