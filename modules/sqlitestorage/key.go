package sqlitestorage

import (
	"fmt"
)

// Key represents a YubiKey record in the SQLite database.
// It contains all necessary fields for OTP validation and key management.
//
// The struct tags follow database column naming conventions for ORM mapping.
type Key struct {
	ID        uint64 `db:"id"`         // Unique database identifier
	PublicID  string `db:"public_id"`  // Public identity (12-byte modhex string)
	Created   string `db:"created"`    // Creation timestamp in ISO8601 format
	PrivateID string `db:"private_id"` // Private identity (6-byte hex string)
	AESKey    string `db:"aes_key"`    // AES-128 key (32-byte hex string)
	LockCode  string `db:"lock_code"`  // Lock/unlock code (optional)
	Active    bool   `db:"active"`     // Activation status
}

// String implements fmt.Stringer interface for pretty-printing Key records.
// The output format is optimized for logging and debugging purposes.
//
// Example output:
// YubiKey[ID:000000000001 Pub:vveirvt... Priv:abc123 AES:0123... Active:true]
func (k *Key) String() string {
	return fmt.Sprintf("YubiKey[ID:%012x Pub:%.6s... Priv:%.6s AES:%.6s... Active:%t]",
		k.ID,
		k.PublicID,
		k.PrivateID,
		k.AESKey,
		k.Active,
	)
}
