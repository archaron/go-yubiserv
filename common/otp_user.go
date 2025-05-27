package common

type (
	// OTPUsers maintains a registry of YubiKey user sessions and counters.
	// The map key represents the YubiKey public ID, while the value stores
	// the current authentication state including usage counters and timestamp.
	OTPUsers map[string]*OTPUser

	// OTPUser contains the stateful authentication counters for a YubiKey.
	// These values are used to prevent replay attacks and validate token
	// sequencing according to YubiKey OTP protocol requirements.
	//
	// Fields:
	//   UsageCounter - Increments with each OTP generation (16-bit)
	//   SessionCounter - Increments per user session (8-bit)
	//   Timestamp - Last token timestamp (3-byte binary format)
	OTPUser struct {
		UsageCounter   uint16
		SessionCounter uint8
		Timestamp      [3]byte
	}
)
