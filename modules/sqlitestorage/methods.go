package sqlitestorage

import (
	"database/sql"
	"encoding/hex"
	"fmt"

	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/archaron/go-yubiserv/common"
	"github.com/archaron/go-yubiserv/misc"
)

// DecryptOTP Decrypt OTP using stored private AES for specified public identifier.
func (s *Service) DecryptOTP(publicID, token string) (*common.OTP, error) {
	log := s.log.With(
		zap.String("public_id", publicID),
		zap.String("token", token),
	)

	key, err := s.getKeyFunc(publicID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, common.ErrStorageNoKey
		}

		return nil, err
	}

	if !key.Active {
		return nil, common.ErrStorageKeyInactive
	}

	aesKey, err := hex.DecodeString(key.AESKey)
	if err != nil {
		s.log.Error("failed to decode AES key", zap.Error(err))

		return nil, common.ErrStorageDecryptFail
	}

	binToken, err := hex.DecodeString(misc.ModHexToHex(token))
	if err != nil {
		s.log.Error("failed to decode token", zap.Error(err))

		return nil, common.ErrStorageDecryptFail
	}

	otp := &common.OTP{}

	if err = otp.Decrypt(aesKey, binToken); err != nil {
		log.Error("AES decryption failed")

		return nil, common.ErrStorageDecryptFail
	}

	if hex.EncodeToString(otp.PrivateID[:]) != key.PrivateID {
		log.Error("private ID mismatch",
			zap.String("opt_private_id", hex.EncodeToString(otp.PrivateID[:])),
			zap.String("key_private_id", key.PrivateID),
		)

		return nil, common.ErrStorageDecryptFail
	}

	return otp, nil
}

// StoreKey stores given key into the database.
func (s *Service) StoreKey(k *Key) error {
	if _, err := s.db.Exec("REPLACE INTO Keys (id, public_id, created, private_id, lock_code, aes_key, active) VALUES (?,?,?,?,?,?,?)",
		k.ID,
		k.PublicID,
		k.Created,
		k.PrivateID,
		k.LockCode,
		k.AESKey,
		k.Active,
	); err != nil {
		return fmt.Errorf("cannot store key: %w", err)
	}

	return nil
}

// GetKey retrieves key with given publicID from storage.
func (s *Service) GetKey(publicID string) (*Key, error) {
	key := Key{}
	row := s.db.QueryRowx("SELECT id, public_id, created, private_id, lock_code, aes_key, active FROM Keys WHERE public_id=?", publicID)

	if err := row.StructScan(&key); err != nil {
		return nil, fmt.Errorf("cannot get key: %w", err)
	}

	return &key, nil
}

// TestCreateDatabase creates a new database for testing.
func (s *Service) TestCreateDatabase() error {
	return s.createDatabase()
}

// createDatabase initializes the SQLite database schema required for YubiKey storage.
// It creates the main Keys table with all necessary columns and constraints.
//
// The table structure includes:
//   - public_id: YubiKey public identifier (modhex, 12 chars + 4 chars reserved)
//   - id: Unique numeric identifier
//   - created: ISO-8601 formatted timestamp
//   - private_id: Private identifier (6-byte hex)
//   - lock_code: Device lock code (optional)
//   - aes_key: AES-128 key material (32-byte hex)
//   - active: Key activation status
//
// Returns:
//   - error if table creation fails, wrapped with context
func (s *Service) createDatabase() error {
	const createTableSQL = `
CREATE TABLE IF NOT EXISTS Keys (
    public_id  VARCHAR(16)  PRIMARY KEY,  -- YubiKey public ID
    id         INTEGER      NOT NULL,     -- Sequential ID
    created    VARCHAR(24)  NOT NULL,     -- ISO8601 timestamp
    private_id VARCHAR(12)  NOT NULL,     -- Private ID (6 bytes hex)
    lock_code  VARCHAR(12)  NOT NULL,     -- Lock code
    aes_key    VARCHAR(32)  NOT NULL,     -- AES-128 key (16 bytes hex)
    active     BOOLEAN      DEFAULT TRUE, -- Activation flag
    CONSTRAINT chk_public_id CHECK (LENGTH(public_id) = 12),
    CONSTRAINT chk_private_id CHECK (LENGTH(private_id) = 12),
    CONSTRAINT chk_aes_key CHECK (LENGTH(aes_key) = 32)
)`

	if _, err := s.db.Exec(createTableSQL); err != nil {
		return fmt.Errorf("failed to create Keys table: %w", err)
	}
	return nil
}
