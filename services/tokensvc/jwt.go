package tokensvc

import (
	"auth/config"
	"auth/log"
	"auth/services/redissvc"
	"auth/types"
	"auth/utils/errutil"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

func CreateToken(userId int) (*types.JwtToken, error) {
	jwtConf := config.Jwt()
	token := &types.JwtToken{}

	token.UserID = userId
	token.AccessExpiry = time.Now().Add(time.Second * jwtConf.AccessTokenExpiry).Unix()
	token.AccessUuid = uuid.New().String()

	token.RefreshExpiry = time.Now().Add(time.Second * jwtConf.RefreshTokenExpiry).Unix()
	token.RefreshUuid = uuid.New().String()

	atClaims := jwt.MapClaims{}
	atClaims["uid"] = userId
	atClaims["aid"] = token.AccessUuid
	atClaims["rid"] = token.RefreshUuid
	atClaims["exp"] = token.AccessExpiry

	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)

	var err error
	token.AccessToken, err = at.SignedString([]byte(jwtConf.AccessTokenSecret))
	if err != nil {
		log.Error(err)
		return nil, errutil.ErrAccessTokenSign
	}

	rtClaims := jwt.MapClaims{}
	rtClaims["uid"] = userId
	rtClaims["aid"] = token.AccessUuid
	rtClaims["rid"] = token.RefreshUuid
	rtClaims["exp"] = token.RefreshExpiry

	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	token.RefreshToken, err = rt.SignedString([]byte(jwtConf.RefreshTokenSecret))
	if err != nil {
		log.Error(err)
		return nil, errutil.ErrRefreshTokenSign
	}

	return token, nil
}

func StoreTokenUuid(userId int, token *types.JwtToken) error {
	now := time.Now().Unix()

	err := redissvc.Set(
		config.Redis().AccessUuidPrefix+token.AccessUuid,
		userId, time.Duration(token.AccessExpiry-now),
	)
	if err != nil {
		return err
	}

	err = redissvc.Set(
		config.Redis().RefreshUuidPrefix+token.RefreshUuid,
		userId, time.Duration(token.RefreshExpiry-now),
	)
	if err != nil {
		return err
	}

	return nil
}

func DeleteTokenUuid(uuid ...string) error {
	return redissvc.Del(uuid...)
}
