package methodutil

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"auth/log"
	"auth/utils/errutil"

	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
)

func MapToStruct(input map[string]interface{}, output interface{}) error {
	if b, err := json.Marshal(input); err == nil {
		return json.Unmarshal(b, &output)
	} else {
		return err
	}
}

func CopyStruct(input interface{}, output interface{}) error {
	if b, err := json.Marshal(input); err == nil {
		return json.Unmarshal(b, &output)
	} else {
		return err
	}
}

func InArray(needle interface{}, haystack interface{}) bool {
	switch reflect.TypeOf(haystack).Kind() {
	case reflect.Slice:
		s := reflect.ValueOf(haystack)

		for i := 0; i < s.Len(); i++ {
			if reflect.DeepEqual(needle, s.Index(i).Interface()) {
				return true
			}
		}
	}

	return false
}

func ParseParam(c echo.Context, paramName string) (string, error) {
	param := c.Param(paramName)
	if param == "" {
		return "", errors.New(fmt.Sprintf("%v: No parameter found", paramName))
	}
	return param, nil
}

func AccessTokenFromHeader(c echo.Context) (string, error) {
	header := "Authorization"
	authScheme := "Bearer"

	auth := c.Request().Header.Get(header)
	l := len(authScheme)

	if len(auth) > l+1 && auth[:l] == authScheme {
		return auth[l+1:], nil
	}

	return "", errutil.ErrInvalidAccessToken
}

func ParseJwtToken(token, secret string) (*jwt.Token, error) {
	return jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errutil.ErrInvalidJwtSigningMethod
		}
		return []byte(secret), nil
	})
}

func GenerateRandomStringOfLength(length int) string {
	rand.Seed(time.Now().UnixNano())
	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")

	if length == 0 {
		length = 8
	}

	var b strings.Builder

	for i := 0; i < length; i++ {
		b.WriteRune(chars[rand.Intn(len(chars))])
	}

	return b.String()
}

func StringToIntArray(stringArray []string) []int {
	var res []int

	for _, v := range stringArray {
		if i, err := strconv.Atoi(v); err == nil {
			res = append(res, i)
		}
	}

	return res
}

func RecoverPanic() {
	if r := recover(); r != nil {
		log.Error(r)
	}
}

const otpChars = "1234567890"

func GenerateOTP(length int) (string, error) {
	buffer := make([]byte, length)
	_, err := rand.Read(buffer)
	if err != nil {
		return "", err
	}

	otpCharsLength := len(otpChars)
	for i := 0; i < length; i++ {
		buffer[i] = otpChars[int(buffer[i])%otpCharsLength]
	}

	return string(buffer), nil
}

func IsEmpty(x interface{}) bool {
	return x == nil || reflect.DeepEqual(x, reflect.Zero(reflect.TypeOf(x)).Interface())
}

func ValidatePassword(pass string) error {
	if len(pass) < 8 {
		return errutil.ErrInvalidPasswordFormat
	}

	num := `[0-9]{1}`
	a_z := `[a-z]{1}`
	A_Z := `[A-Z]{1}`
	symbol := `[.!@#~$%^&*()+|_<>]{1}`

	if b, err := regexp.MatchString(num, pass); !b || err != nil {
		return errutil.ErrInvalidPasswordFormat
	}

	if b, err := regexp.MatchString(a_z, pass); !b || err != nil {
		return errutil.ErrInvalidPasswordFormat
	}

	if b, err := regexp.MatchString(A_Z, pass); !b || err != nil {
		return errutil.ErrInvalidPasswordFormat
	}

	if b, err := regexp.MatchString(symbol, pass); !b || err != nil {
		return errutil.ErrInvalidPasswordFormat
	}

	return nil
}
