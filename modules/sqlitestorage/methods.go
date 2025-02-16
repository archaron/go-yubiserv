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

// StoreKey stores given key into database.
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

func (s *Service) createDatabase() error {
	// Ensure tables are created
	_, err := s.db.Exec("create table if not exists Keys (" +
		"public_id varchar(16)," +
		"id int not null," +
		"created  varchar(24) not null," +
		"private_id varchar(12) not null," +
		"lock_code varchar(12) not null," +
		"aes_key varchar(32) not null," +
		"active boolean default true," +
		"primary key (public_id)" +
		")")
	if err != nil {
		return errors.Wrap(err, "failed to create table")
	}

	return nil
}
