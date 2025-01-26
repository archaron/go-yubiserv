package sqlitestorage

import (
	"fmt"
)

type (
	Key struct {
		ID        uint64 `db:"id"`
		PublicID  string `db:"public_id"`
		Created   string `db:"created"`
		PrivateID string `db:"private_id"`
		AESKey    string `db:"aes_key"`
		LockCode  string `db:"lock_code"`
		Active    bool   `db:"active"`
	}
)

func (k *Key) String() string {
	return fmt.Sprintf("YubiKey: ID: %012x, PublicID: %s, PrivateID: %s, AESKey: %s, LockCode: %s Active: %t Created: %s",
		k.ID,
		k.PublicID,
		k.PrivateID,
		k.AESKey,
		k.LockCode,
		k.Active,
		k.Created,
	)
}
