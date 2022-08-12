package serviceImpl

import (
	"auth/config"
	"auth/consts"
	"auth/errors"
	"auth/services"
	"auth/types"
	"auth/utils/log"
	"auth/utils/methods"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis"
	"golang.org/x/crypto/bcrypt"
)

type authService struct {
	cacheService services.ICache
	tokenService services.IToken
	userService  services.IUserService
	oAuthService services.IOAuthService
}

func NewAuthService(cacheService services.ICache, tokenService services.IToken,
	userService services.IUserService, oAuthService services.IOAuthService) services.IAuthService {
	return &authService{
		cacheService: cacheService,
		tokenService: tokenService,
		userService:  userService,
		oAuthService: oAuthService,
	}
}

func (as *authService) SignUp(req *types.UserCreateUpdateReq) (*types.UserResp, error) {
	return as.userService.CreateUser(req)
}

func (as *authService) Login(req *types.LoginReq) (*types.LoginResp, error) {
	user, err := as.userService.GetUserByEmail(req.Email)
	if err != nil {
		log.Error(err)
		return nil, errors.LoginFailed()
	}

	// NOTE: Only Users registered via general provider are allowed here
	if user.LoginProvider != consts.LoginProviderHink {
		return nil, errors.InvalidLoginAttempt(user.LoginProvider)
	}

	loginPass := []byte(req.Password)
	hashedPass := []byte(*user.Password)

	if err = bcrypt.CompareHashAndPassword(hashedPass, loginPass); err != nil {
		log.Error(errors.Invalid(consts.Password))
		return nil, errors.LoginFailed()
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
		return nil, errors.ErrInvalidLoginProvider
	}
	if err != nil {
		return nil, err
	}
	return as.generateLoginResponse(userId)
}

func (as *authService) Logout(user *types.LoggedInUser) error {
	return as.tokenService.DeleteTokenUuid(
		config.Redis().AccessUuidPrefix+user.AccessUuid,
		config.Redis().RefreshUuidPrefix+user.RefreshUuid,
	)
}

func (as *authService) CheckUserInCache(userId int, uuid, uuidType string) bool {
	prefix := config.Redis().AccessUuidPrefix

	if uuidType == consts.RefreshTokenType {
		prefix = config.Redis().RefreshUuidPrefix
	}

	redisKey := prefix + uuid

	redisUserId, err := as.cacheService.GetInt(redisKey)
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
		return nil, errors.Invalid(consts.RefreshToken)
	}

	if !as.CheckUserInCache(oldToken.UserID, oldToken.RefreshUuid, consts.RefreshTokenType) {
		return nil, errors.Invalid(consts.RefreshToken)
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

	if err = as.tokenService.DeleteTokenUuid(
		config.Redis().AccessUuidPrefix+oldToken.AccessUuid,
		config.Redis().RefreshUuidPrefix+oldToken.RefreshUuid,
	); err != nil {
		log.Error(err)
		return nil, errors.Delete(consts.OldToken)
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
		return nil, errors.Invalid(consts.AccessToken)
	}

	if !as.CheckUserInCache(token.UserID, token.AccessUuid, consts.AccessTokenType) {
		return nil, errors.Invalid(consts.AccessToken)
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

	if token, err = as.tokenService.CreateToken(userId); err != nil {
		return nil, errors.Create(consts.JWTToken)
	}

	if err = as.tokenService.StoreTokenUuid(userId, token); err != nil {
		return nil, errors.Store(consts.JWTToken)
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
		return nil, errors.Invalid(consts.RefreshToken)
	}

	return tokenDetails, nil
}

func (as *authService) ParseTokenClaim(token, tokenType string) (jwt.MapClaims, error) {
	secret := config.Jwt().AccessTokenSecret

	if tokenType == consts.RefreshTokenType {
		secret = config.Jwt().RefreshTokenSecret
	}

	parsedToken, err := methods.ParseJwtToken(token, secret)
	if err != nil {
		log.Error(err)
		return nil, errors.ParseToken(consts.JWTToken)
	}

	if _, ok := parsedToken.Claims.(jwt.Claims); !ok || !parsedToken.Valid {
		return nil, errors.Invalid(consts.AccessToken)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.Invalid(consts.AccessToken)
	}

	return claims, nil
}

// private

func (as *authService) generateLoginResponse(userId int) (*types.LoginResp, error) {
	userResp, err := as.userService.GetUserFromCache(userId, true)
	if err != nil {
		log.Error(err)
		return nil, errors.LoginFailed()
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
