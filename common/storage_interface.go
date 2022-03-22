package common

import "errors"

// StorageInterface for implementing keys storage
type StorageInterface interface {

	// DecryptOTP using stored private AES for specified public identifier
	DecryptOTP(publicID, token string) (*OTP, error)

	// UpdateCounters in db storage
	//UpdateCounters(publicId string, usageCounter uint16, sessionCounter uint8) error
}

var (
	ErrStorageNoKey       = errors.New("client key not found")
	ErrStorageKeyInactive = errors.New("client key is not active")
	ErrStorageDecryptFail = errors.New("otp request decryption failed")
)
