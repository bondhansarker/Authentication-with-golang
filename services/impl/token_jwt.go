package serviceImpl

import (
	"time"

	"auth/rest_errors"
	"auth/services"

	"auth/config"
	"auth/types"
	"auth/utils/log"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

type jwtService struct {
	cacheService services.ICache
}

func NewJWTService(cacheService services.ICache) services.IToken {
	return &jwtService{
		cacheService: cacheService,
	}
}

func (jts *jwtService) CreateToken(userId int) (*types.JwtToken, error) {
	token := &types.JwtToken{}
	jwtConf := config.Jwt()
	token.UserID = userId
	token.AccessExpiry = time.Now().Add(time.Second * config.Jwt().AccessTokenExpiry).Unix()
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
		return nil, rest_errors.ErrSigningAccessToken
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
		return nil, rest_errors.ErrSigningRefreshToken
	}

	return token, nil
}

func (jts *jwtService) StoreTokenUuid(userId int, token *types.JwtToken) error {
	now := time.Now().Unix()
	redisConf := config.Redis()
	err := jts.cacheService.Set(
		redisConf.AccessUuidPrefix+token.AccessUuid,
		userId, time.Duration(token.AccessExpiry-now),
	)
	if err != nil {
		return err
	}

	err = jts.cacheService.Set(
		redisConf.RefreshUuidPrefix+token.RefreshUuid,
		userId, time.Duration(token.RefreshExpiry-now),
	)
	if err != nil {
		return err
	}

	return nil
}

func (jts *jwtService) DeleteTokenUuid(uuid ...string) error {
	return jts.cacheService.Del(uuid...)
}
