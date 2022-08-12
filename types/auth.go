package types

import (
	"auth/consts"
	"auth/errors"
	"auth/utils/methods"

	v "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type LoginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (u LoginReq) Validate() error {
	return v.ValidateStruct(&u,
		v.Field(&u.Email, v.Required, is.EmailFormat),
		v.Field(&u.Password, v.Required),
	)
}

type TokenRefreshReq struct {
	RefreshToken string `json:"refresh_token"`
}

type LoginResp struct {
	AccessToken        string    `json:"access_token"`
	AccessTokenExpiry  int64     `json:"access_token_expiry"`
	RefreshToken       string    `json:"refresh_token"`
	RefreshTokenExpiry int64     `json:"refresh_token_expiry"`
	User               *UserResp `json:"user"`
}

type JwtToken struct {
	UserID        int    `json:"uid"`
	AccessToken   string `json:"act"`
	RefreshToken  string `json:"rft"`
	AccessUuid    string `json:"aid"`
	RefreshUuid   string `json:"rid"`
	AccessExpiry  int64  `json:"axp"`
	RefreshExpiry int64  `json:"rxp"`
}

type ChangePasswordReq struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

func (cp ChangePasswordReq) Validate() error {
	return v.ValidateStruct(&cp,
		v.Field(&cp.OldPassword, v.Required),
		v.Field(&cp.NewPassword, v.Required, v.By(cp.isValidPasswordFormat)),
	)
}

func (cp ChangePasswordReq) isValidPasswordFormat(value interface{}) error {
	return methods.ValidatePassword(cp.NewPassword)
}

type ForgotPasswordReq struct {
	Email string `json:"email"`
}

func (f ForgotPasswordReq) Validate() error {
	return v.ValidateStruct(&f,
		v.Field(&f.Email, v.Required, is.EmailFormat),
	)
}

type VerifyResetPasswordReq struct {
	Token string `json:"token"`
	ID    int    `json:"id"`
	Otp   string `json:"otp"`
	Nonce string `json:"nonce"`
}

func (vr VerifyResetPasswordReq) Validate() error {
	return v.ValidateStruct(&vr,
		v.Field(&vr.Token, v.Required),
		v.Field(&vr.ID, v.Required),
	)
}

type ResetPasswordReq struct {
	ID       int    `json:"id"`
	Token    string `json:"token"`
	Password string `json:"password"`
}

func (rp ResetPasswordReq) Validate() error {
	return v.ValidateStruct(&rp,
		v.Field(&rp.Token, v.Required),
		v.Field(&rp.ID, v.Required),
		v.Field(&rp.Password, v.Required, v.By(rp.isValidPasswordFormat)),
	)
}

func (rp ResetPasswordReq) isValidPasswordFormat(value interface{}) error {
	return methods.ValidatePassword(rp.Password)
}

type SocialLoginReq struct {
	Token         string `json:"token"`
	LoginProvider string `json:"login_provider"`
}

func (s SocialLoginReq) Validate() error {
	return v.ValidateStruct(&s,
		v.Field(&s.Token, v.Required),
		v.Field(&s.LoginProvider, v.Required, v.By(s.loginProviderValid)),
	)
}

func (s SocialLoginReq) loginProviderValid(value interface{}) error {
	loginProviders := consts.LoginProviders()

	if _, ok := loginProviders[s.LoginProvider]; !ok {
		return errors.ErrInvalidLoginProvider
	}

	return nil
}

type SocialLoginData struct {
	Name          string `json:"name,omitempty"`
	Email         string `json:"email,omitempty"`
	LoginProvider string `json:"login_provider,omitempty"`
	Verified      bool   `json:"verified"`
}
