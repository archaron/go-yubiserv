package common

type (
	OTPUsers map[string]*OTPUser
	OTPUser  struct {
		UsageCounter   uint16
		SessionCounter uint8
		Timestamp      [3]byte
	}
)
