package types

import (
	"regexp"
	"strconv"
	"strings"

	"auth/config"
	"auth/conn"
	"auth/consts"
	"auth/log"
	"auth/models"
	"auth/services/redissvc"
	"auth/utils/errutil"
	"auth/utils/methodutil"
	"gorm.io/gorm"

	"github.com/dgrijalva/jwt-go"

	v "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type LoggedInUser struct {
	ID          int    `json:"user_id"`
	AccessUuid  string `json:"access_uuid"`
	RefreshUuid string `json:"refresh_uuid"`
	IsAdmin     *bool  `json:"is_admin"`
}

type UserResp struct {
	ID                  int     `json:"id"`
	Name                string  `json:"name"`
	UserName            string  `json:"user_name"`
	Email               string  `json:"email"`
	Phone               string  `json:"phone"`
	Website             string  `json:"website"`
	Bio                 string  `json:"bio"`
	Gender              string  `json:"gender"`
	ProfilePic          *string `json:"profile_pic"`
	ProfilePicExtension *string `json:"profile_pic_extension"`
	Verified            *bool   `json:"verified"`
	IsAdmin             *bool   `json:"is_admin"`
	LoginProvider       string  `json:"login_provider"`
	UploadCount         int64   `json:"upload_count"`
}

func (u *UserResp) Cache() {
	conf := config.Redis()

	if err := redissvc.SetStruct(conf.UserPrefix+strconv.Itoa(u.ID), u, conf.UserTtl); err != nil {
		log.Error(err)
	}
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
	Verified      *bool  `json:"verified"`
	LoginProvider string `json:"login_provider"`
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

type MinimalUser struct {
	ID                  int     `json:"id"`
	Name                string  `json:"name"`
	UserName            string  `json:"user_name"`
	Email               string  `json:"email"`
	Phone               string  `json:"phone"`
	Website             string  `json:"website"`
	Bio                 string  `json:"bio"`
	Gender              string  `json:"gender"`
	ProfilePic          *string `json:"profile_pic"`
	ProfilePicExtension *string `json:"profile_pic_extension"`
	LoginProvider       string  `json:"login_provider"`
	DownloadCount       int64   `json:"download_count" `
	UploadCount         int64   `json:"upload_count"`
	Verified            bool    `json:"verified"`
}

func (u UserCreateUpdateReq) isCreating() bool {
	return u.ID == 0
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

func (u *UserCreateUpdateReq) isAlreadyRegistered(value interface{}) error {
	// if !u.isCreating() { // no need to check while doing "update"
	// 	return nil
	// }

	user := &models.User{}
	userName := strings.ToLower(u.UserName)
	var res *gorm.DB
	if userName != "" {
		res = conn.Db().Where("email = ? OR user_name = ?", u.Email, userName).Find(&user)
	} else {
		res = conn.Db().Where("email = ?", u.Email).Find(&user)
	}
	if res.RowsAffected > 0 {
		if user.ID != u.ID {
			if value == "email" && user.Email == u.Email {
				return errutil.ErrEmailAlreadyRegistered
			}
			if value == "user_name" && userName != "" && user.UserName == userName {
				return errutil.ErrUserNameAlreadyRegistered
			}
		}
	}
	return nil
}

func (u *UserCreateUpdateReq) disallowEmailUpdate(value interface{}) error {
	if !u.isCreating() && !methodutil.IsEmpty(u.Email) {
		return errutil.ErrEmailUpdateNotAllowed
	}

	return nil
}

func (u *UserCreateUpdateReq) disallowUserNameUpdate(value interface{}) error {
	if !u.isCreating() && !methodutil.IsEmpty(u.UserName) {
		return errutil.ErrUserNameUpdateNotAllowed
	}

	return nil
}

func (u *UserCreateUpdateReq) disallowPasswordUpdate(value interface{}) error {
	if !u.isCreating() && !methodutil.IsEmpty(u.Password) {
		return errutil.ErrPasswordUpdateNotAllowed
	}

	return nil
}

func (u *UserCreateUpdateReq) isValidPasswordFormat(value interface{}) error {
	if u.isCreating() && u.LoginProvider == consts.LoginProviderHink {
		return methodutil.ValidatePassword(u.Password)
	}

	return nil
}

func (u *UserCreateUpdateReq) loginProviderValid(value interface{}) error {
	if !u.isCreating() {
		return nil
	}

	loginProviders := consts.LoginProviders()

	if _, ok := loginProviders[u.LoginProvider]; !ok {
		return errutil.ErrInvalidLoginProvider
	}

	return nil
}

func (u *UserCreateUpdateReq) isPasswordRequired() bool {
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
