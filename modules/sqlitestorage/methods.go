package sqlitestorage

import (
	"database/sql"
	"encoding/hex"
	"github.com/archaron/go-yubiserv/common"
	"github.com/archaron/go-yubiserv/misc"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

// DecryptOTP Decrypt OTP using stored private AES for specified public identifier
func (s *Service) DecryptOTP(publicID, token string) (*common.OTP, error) {
	log := s.log.With(
		zap.String("public_id", publicID),
		zap.String("token", token),
	)

	key, err := s.getKey(publicID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, common.ErrStorageNoKey
		}
		return nil, err
	}

	if !key.Active {
		return nil, common.ErrStorageKeyInactive
	}

	aesKey, err := hex.DecodeString(key.AESKey)
	if err != nil {
		return nil, err
	}

	binToken, err := hex.DecodeString(misc.Modhex2hex(token))
	if err != nil {
		return nil, err
	}

	otp := &common.OTP{}
	err = otp.Decrypt(aesKey, binToken)
	if err != nil {
		log.Error("AES decryption failed")
		return nil, common.ErrStorageDecryptFail
	}

	if hex.EncodeToString(otp.PrivateID[:]) != key.PrivateID {
		log.Error("private ID mismatch", zap.String("opt_private_id", hex.EncodeToString(otp.PrivateID[:])), zap.String("key_private_id", key.PrivateID))
		return nil, common.ErrStorageDecryptFail
	}

	return otp, err
}

func (s *Service) StoreKey(k *key) error {
	_, err := s.db.Exec("REPLACE INTO Keys (id, public_id, created, private_id, lock_code, aes_key, active) VALUES (?,?,?,?,?,?,?)",
		k.ID,
		k.PublicID,
		k.Created,
		k.PrivateID,
		k.LockCode,
		k.AESKey,
		k.Active,
	)
	return errors.Wrap(err, "cannot store key")
}

func (s *Service) GetKey(publicId string) (*key, error) {
	key := key{}
	row := s.db.QueryRowx("SELECT id, public_id, created, private_id, lock_code, aes_key, active FROM Keys WHERE public_id=?", publicId)

	if err := row.StructScan(&key); err != nil {
		return nil, err
	}
	return &key, nil
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

//
//func (s *Service) UpdateCounters(publicId string, usageCounter uint16, sessionCounter uint8) error {
//	return nil
//}
