package common

type (
	// OTPUsers is a user's counters storage.
	OTPUsers map[string]*OTPUser

	// OTPUser represents user counters.
	OTPUser struct {
		UsageCounter   uint16
		SessionCounter uint8
		Timestamp      [3]byte
	}
)
