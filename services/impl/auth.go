package serviceImpl

import (
	"errors"

	"auth/config"
	"auth/consts"
	"auth/repositories"
	"auth/rest_errors"
	"auth/services"
	"auth/types"
	"auth/utils/log"
	"auth/utils/methods"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis"
	"golang.org/x/crypto/bcrypt"
)

type authService struct {
	config          *config.Config
	cacheRepository repositories.ICache
	tokenRepository repositories.IToken
	userService     services.IUserService
	oAuthService    services.IOAuthService
}

func NewAuthService(config *config.Config, cacheRepository repositories.ICache, tokenRepository repositories.IToken,
	userService services.IUserService, oAuthService services.IOAuthService) services.IAuthService {
	return &authService{
		config:          config,
		cacheRepository: cacheRepository,
		tokenRepository: tokenRepository,
		userService:     userService,
		oAuthService:    oAuthService,
	}
}

func (as *authService) SignUp(req *types.UserCreateUpdateReq) (*types.UserResp, error) {
	return as.userService.CreateUser(req)
}

func (as *authService) Login(req *types.LoginReq) (*types.LoginResp, error) {
	user, err := as.userService.GetUserByEmail(req.Email)
	if err != nil {
		log.Error(err)
		return nil, rest_errors.ErrLogin
	}

	// NOTE: Only Users registered via general provider are allowed here
	if user.LoginProvider != consts.LoginProviderHink {
		return nil, errors.New(rest_errors.InvalidLoginAttempt(user.LoginProvider))
	}

	loginPass := []byte(req.Password)
	hashedPass := []byte(*user.Password)

	if err = bcrypt.CompareHashAndPassword(hashedPass, loginPass); err != nil {
		log.Error(rest_errors.InvalidPassword)
		return nil, rest_errors.ErrLogin
	}
	return as.generateLoginResponse(user.ID)
}

func (as *authService) SocialLogin(req *types.SocialLoginReq) (*types.LoginResp, error) {
	var userId int
	var err error
	switch req.LoginProvider {
	case consts.LoginProviderGoogle:
		userId, err = as.oAuthService.ProcessGoogleLogin(req.Token)
	case consts.LoginProviderFacebook:
		userId, err = as.oAuthService.ProcessFacebookLogin(req.Token)
	case consts.LoginProviderApple:
		userId, err = as.oAuthService.ProcessAppleLogin(req.Token)
	default:
		return nil, rest_errors.ErrInvalidLoginProvider
	}
	if err != nil {
		return nil, err
	}
	return as.generateLoginResponse(userId)
}

func (as *authService) Logout(user *types.LoggedInUser) error {
	redisConf := as.config.Redis
	if err := as.tokenRepository.DeleteTokenUuid(redisConf.AccessUuidPrefix+user.AccessUuid,
		redisConf.RefreshUuidPrefix+user.RefreshUuid); err != nil {
		return rest_errors.ErrLogOut
	}
	return nil
}

func (as *authService) CheckUserInCache(userId int, uuid, uuidType string) bool {
	redisConf := as.config.Redis
	prefix := redisConf.AccessUuidPrefix

	if uuidType == consts.RefreshTokenType {
		prefix = redisConf.RefreshUuidPrefix
	}

	redisKey := prefix + uuid

	redisUserId, err := as.cacheRepository.GetInt(redisKey)
	if err != nil {
		switch err {
		case redis.Nil:
			log.Error(redisKey, " not found in redis")
		default:
			log.Error(err)
		}
		return false
	}

	if userId != redisUserId {
		return false
	}

	return true
}

func (as *authService) RefreshToken(refreshToken string) (*types.LoginResp, error) {
	oldToken, err := as.ParseToken(refreshToken, consts.RefreshTokenType)
	if err != nil {
		return nil, rest_errors.InvalidRefreshToken
	}

	if !as.CheckUserInCache(oldToken.UserID, oldToken.RefreshUuid, consts.RefreshTokenType) {
		return nil, rest_errors.InvalidRefreshToken
	}

	var user *types.UserResp
	if user, err = as.userService.GetUserFromCache(oldToken.UserID, false); err != nil {
		return nil, err
	}

	var newToken *types.JwtToken

	if newToken, err = as.CreateToken(user.ID); err != nil {
		log.Error(err)
		return nil, err
	}

	redisConf := as.config.Redis
	if err = as.tokenRepository.DeleteTokenUuid(
		redisConf.AccessUuidPrefix+oldToken.AccessUuid,
		redisConf.RefreshUuidPrefix+oldToken.RefreshUuid,
	); err != nil {
		log.Error(err)
		return nil, rest_errors.ErrDeletingOldJWTToken
	}

	res := &types.LoginResp{
		AccessToken:        newToken.AccessToken,
		AccessTokenExpiry:  newToken.AccessExpiry,
		RefreshToken:       newToken.RefreshToken,
		RefreshTokenExpiry: newToken.RefreshExpiry,
		User:               user,
	}

	return res, nil
}

func (as *authService) VerifyToken(accessToken string) (*types.UserResp, error) {
	token, err := as.ParseToken(accessToken, consts.AccessTokenType)
	if err != nil {
		return nil, rest_errors.InvalidAccessToken
	}

	if !as.CheckUserInCache(token.UserID, token.AccessUuid, consts.AccessTokenType) {
		return nil, rest_errors.InvalidAccessToken
	}

	userResp, err := as.userService.GetUserFromCache(token.UserID, false)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	return userResp, nil
}

func (as *authService) CreateToken(userId int) (*types.JwtToken, error) {
	var token *types.JwtToken
	var err error

	if token, err = as.tokenRepository.CreateToken(userId); err != nil {
		log.Error(err)
		return nil, rest_errors.ErrCreatingJWTToken
	}

	if err = as.tokenRepository.StoreTokenUuid(userId, token); err != nil {
		log.Error(err)
		return nil, rest_errors.ErrStoringJWTToken
	}

	return token, nil
}

func (as *authService) ParseToken(token, tokenType string) (*types.JwtToken, error) {
	claims, err := as.ParseTokenClaim(token, tokenType)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	tokenDetails := &types.JwtToken{}

	if err := methods.MapToStruct(claims, &tokenDetails); err != nil {
		log.Error(err)
		return nil, err
	}

	if tokenDetails.UserID == 0 || tokenDetails.AccessUuid == "" || tokenDetails.RefreshUuid == "" {
		log.Error(claims)
		return nil, rest_errors.InvalidJWTToken
	}

	return tokenDetails, nil
}

func (as *authService) ParseTokenClaim(token, tokenType string) (jwt.MapClaims, error) {
	jwtConf := as.config.Jwt
	secret := jwtConf.AccessTokenSecret

	if tokenType == consts.RefreshTokenType {
		secret = jwtConf.RefreshTokenSecret
	}

	parsedToken, err := methods.ParseJwtToken(token, secret)
	if err != nil {
		log.Error(err)
		return nil, rest_errors.ErrParsingJWTToken
	}

	if _, ok := parsedToken.Claims.(jwt.Claims); !ok || !parsedToken.Valid {
		return nil, rest_errors.InvalidJWTToken
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, rest_errors.InvalidJWTToken
	}

	return claims, nil
}

// private

func (as *authService) generateLoginResponse(userId int) (*types.LoginResp, error) {
	userResp, err := as.userService.GetUserFromCache(userId, true)
	if err != nil {
		log.Error(err)
		return nil, rest_errors.ErrLogin
	}

	token, err := as.CreateToken(userId)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	if err = as.userService.UpdateLastLogin(userId); err != nil {
		log.Error(err)
		return nil, err
	}

	res := &types.LoginResp{
		AccessToken:        token.AccessToken,
		AccessTokenExpiry:  token.AccessExpiry,
		RefreshToken:       token.RefreshToken,
		RefreshTokenExpiry: token.RefreshExpiry,
		User:               userResp,
	}
	return res, nil
}
