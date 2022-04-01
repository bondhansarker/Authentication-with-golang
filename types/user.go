package types

import (
	"auth/config"
	"auth/conn"
	"auth/consts"
	"auth/log"
	"auth/models"
	"auth/services/redissvc"
	"auth/utils/errutil"
	"auth/utils/methodutil"
	"regexp"
	"strconv"

	"github.com/dgrijalva/jwt-go"

	v "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type LoggedInUser struct {
	ID          int    `json:"user_id"`
	AccessUuid  string `json:"access_uuid"`
	RefreshUuid string `json:"refresh_uuid"`
}

type UserResp struct {
	ID         int     `json:"id"`
	FirstName  string  `json:"first_name"`
	LastName   string  `json:"last_name"`
	Email      string  `json:"email"`
	Phone      *string `json:"phone"`
	ProfilePic *string `json:"profile_pic"`
	Verified   bool    `json:"verified"`
}

func (u *UserResp) Cache() {
	conf := config.Redis()

	if err := redissvc.SetStruct(conf.UserPrefix+strconv.Itoa(u.ID), u, conf.UserTtl); err != nil {
		log.Error(err)
	}
}

type UserCreateUpdateReq struct {
	ID            int     `json:"id"`
	FirstName     *string `json:"first_name"`
	LastName      *string `json:"last_name"`
	Email         string  `json:"email"`
	Password      *string `json:"password"`
	Phone         string  `json:"phone"`
	ProfilePic    *string `json:"profile_pic"`
	LoginProvider string  `json:"login_provider"`
}

func (u UserCreateUpdateReq) isCreating() bool {
	return u.ID == 0
}

func (u UserCreateUpdateReq) Validate() error {
	return v.ValidateStruct(&u,
		v.Field(&u.FirstName,
			v.Required.When(!u.isCreating() || (u.isCreating() && u.LoginProvider == consts.LoginProviderHink)),
			v.Length(3, 50),
		),
		v.Field(&u.LastName, v.Required.When(!u.isCreating() || (u.isCreating() && u.LoginProvider == consts.LoginProviderHink)),
			v.Length(3, 50),
		),
		v.Field(&u.Email,
			v.Required.When(u.isCreating()),
			is.EmailFormat,
			v.By(u.isAlreadyRegistered),
			v.By(u.disallowEmailUpdate),
		),
		v.Field(&u.Password,
			v.Required.When(u.isPasswordRequired()),
			v.By(u.isValidPasswordFormat),
			v.By(u.disallowPasswordUpdate),
		),
		v.Field(&u.Phone, v.Required),
		v.Field(&u.LoginProvider,
			v.Required.When(u.isCreating()),
			v.By(u.loginProviderValid),
		),
	)
}

func (u *UserCreateUpdateReq) isAlreadyRegistered(value interface{}) error {
	if !u.isCreating() { // no need to check while doing "update"
		return nil
	}

	user := &models.User{}

	res := conn.Db().Where("email = ?", u.Email).Find(&user)

	if res.RowsAffected > 0 {
		return errutil.ErrUserAlreadyRegistered
	}

	return nil
}

func (u *UserCreateUpdateReq) disallowEmailUpdate(value interface{}) error {
	if !u.isCreating() && !methodutil.IsEmpty(u.Email) {
		return errutil.ErrEmailUpdateNotAllowed
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
		return methodutil.ValidatePassword(*u.Password)
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
	Email     string  `json:"email"`
	Name      string  `json:"name"`
	FirstName *string `json:"first_name"`
	LastName  *string `json:"last_name"`
}

type GoogleTokenInfo struct {
	jwt.StandardClaims

	Email     string  `json:"email"`
	Name      string  `json:"name"`
	FirstName *string `json:"given_name"`
	LastName  *string `json:"family_name"`
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
