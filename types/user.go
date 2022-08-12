package types

import (
	"auth/errors"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"regexp"
	"strings"

	"auth/connection"
	"auth/consts"
	"auth/models"
	"auth/utils/methods"
	"github.com/dgrijalva/jwt-go"
	"gorm.io/gorm"

	v "github.com/go-ozzo/ozzo-validation/v4"
)

type LoggedInUser struct {
	ID          int    `json:"id"`
	AccessUuid  string `json:"access_uuid"`
	RefreshUuid string `json:"refresh_uuid"`
	IsAdmin     *bool  `json:"is_admin"`
}

type UserResp struct {
	ID                  int    `json:"id"`
	Name                string `json:"name"`
	UserName            string `json:"user_name"`
	Email               string `json:"email"`
	Phone               string `json:"phone"`
	Website             string `json:"website"`
	Bio                 string `json:"bio"`
	Gender              string `json:"gender"`
	ProfilePic          string `json:"profile_pic"`
	ProfilePicExtension string `json:"profile_pic_extension"`
	Verified            bool   `json:"verified"`
	IsAdmin             bool   `json:"is_admin"`
	LoginProvider       string `json:"login_provider"`
	UploadCount         int64  `json:"upload_count"`
	DownloadCount       int64  `json:"download_count"`
}

type UserCreateUpdateReq struct {
	ID            int    `json:"id"`
	Name          string `json:"name"`
	UserName      string `json:"user_name"`
	Email         string `json:"email"`
	Password      string `json:"password"`
	Phone         string `json:"phone"`
	Website       string `json:"website"`
	Bio           string `json:"bio"`
	Gender        string `json:"gender"`
	LoginProvider string `json:"login_provider"`
}

func (u UserCreateUpdateReq) Validate() error {
	return v.ValidateStruct(&u,
		v.Field(&u.Name,
			// v.Required.When(!u.isCreating() || (u.isCreating() && u.LoginProvider == consts.LoginProviderHink)),
			v.Length(3, 50),
		),
		v.Field(&u.Email,
			v.Required.When(u.isCreating()),
			is.EmailFormat,
			v.By(func(v interface{}) error {
				return u.isAlreadyRegistered("email")
			}),
			v.By(u.disallowEmailUpdate),
		),
		v.Field(&u.UserName,
			// v.Required.When(u.isCreating()),
			v.By(func(v interface{}) error {
				return u.isAlreadyRegistered("user_name")
			}),
			// v.By(u.disallowUserNameUpdate),
		),
		v.Field(&u.Password,
			v.Required.When(u.isPasswordRequired()),
			v.By(u.isValidPasswordFormat),
			v.By(u.disallowPasswordUpdate),
		),
		v.Field(&u.LoginProvider,
			v.Required.When(u.isCreating()),
			v.By(u.loginProviderValid),
		),
	)
}

func (u UserCreateUpdateReq) isCreating() bool {
	return u.ID == 0
}

func (u UserCreateUpdateReq) isAlreadyRegistered(value interface{}) error {
	// if !u.isCreating() { // no need to check while doing "update"
	// 	return nil
	// }
	dbClient := connection.DbClient()
	user := &models.User{}
	userName := strings.ToLower(u.UserName)
	var res *gorm.DB
	if userName != "" {
		res = dbClient.Select("id, user_name, email").Where("user_name = ? OR email = ?", userName, u.Email).First(&user)
	} else {
		res = dbClient.Select("id, email").Where("email = ?", u.Email).First(&user)
	}
	if res.RowsAffected > 0 {
		if user.ID != u.ID || u.ID == 0 {
			if value == "email" && user.Email == u.Email {
				return errors.ErrEmailAlreadyRegistered
			}
			if value == "user_name" && userName != "" && user.UserName == userName {
				return errors.ErrUserNameAlreadyRegistered
			}
		}
	}
	return nil
}

func (u UserCreateUpdateReq) disallowEmailUpdate(value interface{}) error {
	if !u.isCreating() && !methods.IsEmpty(u.Email) {
		return errors.ErrEmailUpdateNotAllowed
	}

	return nil
}

func (u UserCreateUpdateReq) disallowUserNameUpdate(value interface{}) error {
	if !u.isCreating() && !methods.IsEmpty(u.UserName) {
		return errors.ErrUserNameUpdateNotAllowed
	}

	return nil
}

func (u UserCreateUpdateReq) disallowPasswordUpdate(value interface{}) error {
	if !u.isCreating() && !methods.IsEmpty(u.Password) {
		return errors.ErrPasswordUpdateNotAllowed
	}

	return nil
}

func (u UserCreateUpdateReq) isValidPasswordFormat(value interface{}) error {
	if u.isCreating() && u.LoginProvider == consts.LoginProviderHink {
		return methods.ValidatePassword(u.Password)
	}

	return nil
}

func (u UserCreateUpdateReq) loginProviderValid(value interface{}) error {
	if !u.isCreating() {
		return nil
	}

	loginProviders := consts.LoginProviders()

	if _, ok := loginProviders[u.LoginProvider]; !ok {
		return errors.ErrInvalidLoginProvider
	}

	return nil
}

func (u UserCreateUpdateReq) isPasswordRequired() bool {
	if !u.isCreating() || u.LoginProvider != consts.LoginProviderHink {
		return false
	}

	return true
}

type FbTokenInfo struct {
	Email     string `json:"email"`
	Name      string `json:"name"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

type GoogleTokenInfo struct {
	jwt.StandardClaims

	Email     string `json:"email"`
	Name      string `json:"name"`
	FirstName string `json:"given_name"`
	LastName  string `json:"family_name"`
}

type AppleTokenInfo struct {
	jwt.StandardClaims

	Email string `json:"email"`
}

type IdUrlParam struct {
	ID string `json:"id"`
}

func (eid IdUrlParam) Validate() error {
	return v.ValidateStruct(&eid,
		v.Field(&eid.ID, v.Match(regexp.MustCompile("^[0-9]+$")).Error("invalid id")),
	)
}

type UserStatUpdateReq struct {
	ID              int    `json:"id"`
	DownloadCount   *int64 `json:"download_count" `
	UploadCount     *int64 `json:"upload_count"`
	IncrementUpload *bool  `json:"increment_upload"`
}

type ProfilePicUpdateReq struct {
	ID                  int     `json:"id"`
	ProfilePic          *string `json:"profile_pic"`
	ProfilePicExtension *string `json:"profile_pic_extension"`
}
