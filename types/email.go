package types

import (
	v "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"regexp"
)

type UserCreateEmailReq struct {
	To string `json:"to"`
}

type ForgotPasswordResp struct {
	Message  string `json:"message,omitempty"`
	UserID   int    `json:"user_id,omitempty"`
	Token    string `json:"token,omitempty"`
	OtpNonce string `json:"otp_nonce,omitempty"`
	Provider string `json:"provider,omitempty"`
}

type ForgotPasswordEmailReq struct {
	To     string `json:"to"`
	UserID int    `json:"user_id"`
	Token  string `json:"token"`
}

type ForgotPasswordEmailOtpReq struct {
	To  string `json:"to"`
	Otp string `json:"otp"`
}

type ForgotPasswordOtpReq struct {
	Nonce string `json:"nonce"`
	Otp   string `json:"otp"`
}

func (o ForgotPasswordOtpReq) Validate() error {
	return v.ValidateStruct(&o,
		v.Field(&o.Otp,
			v.Match(regexp.MustCompile("^[0-9]{6}$")).Error("invalid otp"),
		),
		v.Field(&o.Nonce, v.Required, is.UUID.Error("invalid nonce")),
	)
}

type ForgotPasswordOtpResp struct {
	OtpNonce string `json:"otp_nonce"`
}

type ForgotPasswordOtpResendReq struct {
	Nonce string `json:"nonce"`
}

func (o ForgotPasswordOtpResendReq) Validate() error {
	return v.ValidateStruct(&o,
		v.Field(&o.Nonce, v.Required, is.UUID.Error("invalid nonce")),
	)
}
