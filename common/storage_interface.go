package common

import "errors"

// StorageInterface defines the interface for YubiKey OTP storage implementations.
// Implementations must provide methods for OTP decryption and key management.
type StorageInterface interface {
	// DecryptOTP decrypts a YubiKey OTP token using the AES key associated
	// with the given public ID. Returns the decrypted OTP structure or an error
	// if decryption fails or the public ID is not found.
	//
	// Parameters:
	//   publicID - The YubiKey public identifier (first 12 characters of OTP)
	//   token    - Full OTP token to decrypt
	//
	// Returns:
	//   *OTP - Decrypted OTP structure on success
	//   error - Decryption error or key not found error
	DecryptOTP(publicID, token string) (*OTP, error)
}

var (
	// ErrStorageNoKey indicates that the requested YubiKey public ID
	// was not found in the key storage.
	ErrStorageNoKey = errors.New("client key not found")

	// ErrStorageKeyInactive indicates that the YubiKey exists in storage
	// but is marked as inactive/disabled for authentication.
	ErrStorageKeyInactive = errors.New("client key is not active")

	// ErrStorageDecryptFail indicates a failure during OTP decryption,
	// typically due to:
	// - Invalid AES key for the public ID
	// - Corrupted or malformed OTP token
	// - Cryptographic verification failure
	ErrStorageDecryptFail = errors.New("otp request decryption failed")
)
