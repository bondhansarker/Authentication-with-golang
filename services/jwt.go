package services

import (
	"auth/errors"
	"time"

	"auth/config"
	"auth/consts"
	"auth/repositories"
	"auth/types"
	"auth/utils/log"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

type JWTService struct {
	redisRepository *repositories.RedisRepository
	config          *config.Config
}

func NewJWTService(redisRepository *repositories.RedisRepository) *JWTService {
	return &JWTService{
		config:          config.AllConfig(),
		redisRepository: redisRepository,
	}
}

func (jwtService *JWTService) CreateToken(userId int) (*types.JwtToken, error) {
	token := &types.JwtToken{}

	token.UserID = userId
	token.AccessExpiry = time.Now().Add(time.Second * jwtService.config.Jwt.AccessTokenExpiry).Unix()
	token.AccessUuid = uuid.New().String()

	token.RefreshExpiry = time.Now().Add(time.Second * jwtService.config.Jwt.RefreshTokenExpiry).Unix()
	token.RefreshUuid = uuid.New().String()

	atClaims := jwt.MapClaims{}
	atClaims["uid"] = userId
	atClaims["aid"] = token.AccessUuid
	atClaims["rid"] = token.RefreshUuid
	atClaims["exp"] = token.AccessExpiry

	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)

	var err error
	token.AccessToken, err = at.SignedString([]byte(jwtService.config.Jwt.AccessTokenSecret))
	if err != nil {
		log.Error(err)
		return nil, errors.SignToken(consts.AccessToken)
	}

	rtClaims := jwt.MapClaims{}
	rtClaims["uid"] = userId
	rtClaims["aid"] = token.AccessUuid
	rtClaims["rid"] = token.RefreshUuid
	rtClaims["exp"] = token.RefreshExpiry

	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	token.RefreshToken, err = rt.SignedString([]byte(jwtService.config.Jwt.RefreshTokenSecret))
	if err != nil {
		log.Error(err)
		return nil, errors.SignToken(consts.RefreshToken)
	}

	return token, nil
}

func (jwtService *JWTService) StoreTokenUuid(userId int, token *types.JwtToken) error {
	now := time.Now().Unix()

	err := jwtService.redisRepository.Set(
		jwtService.config.Redis.AccessUuidPrefix+token.AccessUuid,
		userId, time.Duration(token.AccessExpiry-now),
	)
	if err != nil {
		return err
	}

	err = jwtService.redisRepository.Set(
		jwtService.config.Redis.RefreshUuidPrefix+token.RefreshUuid,
		userId, time.Duration(token.RefreshExpiry-now),
	)
	if err != nil {
		return err
	}

	return nil
}

func (jwtService *JWTService) DeleteTokenUuid(uuid ...string) error {
	return jwtService.redisRepository.Del(uuid...)
}
