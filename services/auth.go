package services

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"auth/config"
	"auth/consts"
	"auth/log"
	"auth/repositories"
	"auth/types"
	"auth/utils/applekeyutil"
	"auth/utils/errutil"
	"auth/utils/methodutil"

	"gorm.io/gorm"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
)

type AuthService struct {
	config          *config.Config
	redisRepository *repositories.RedisRepository
	jwtService      *JWTService
	userService     *UserService
}

func NewAuthService(redisRepository *repositories.RedisRepository, jwtService *JWTService,
	userService *UserService) *AuthService {
	return &AuthService{
		config:          config.GetConfig(),
		redisRepository: redisRepository,
		jwtService:      jwtService,
		userService:     userService,
	}
}

func (as *AuthService) Login(req *types.LoginReq) (*types.LoginResp, error) {
	user, err := as.userService.GetUserByEmail(req.Email)
	if err != nil {
		log.Error(err)
		return nil, errutil.ErrInvalidEmail
	}

	// NOTE: Only Users registered via Hink provider are allowed here
	if user.LoginProvider != consts.LoginProviderHink {
		switch user.LoginProvider {
		case consts.LoginProviderApple:
			return nil, errutil.ErrLoginAttemptWithAppleProvider
		case consts.LoginProviderGoogle:
			return nil, errutil.ErrLoginAttemptWithGoogleProvider
		case consts.LoginProviderFacebook:
			return nil, errutil.ErrLoginAttemptWithFacebookProvider
		}
	}

	loginPass := []byte(req.Password)
	hashedPass := []byte(*user.Password)

	if err = bcrypt.CompareHashAndPassword(hashedPass, loginPass); err != nil {
		log.Error(err)
		return nil, errutil.ErrInvalidPassword
	}
	return as.login(user.ID)
}

func (as *AuthService) login(userId int) (*types.LoginResp, error) {
	userResp, err := as.userService.GetUserResponse(userId, true)
	if err != nil {
		return nil, err
	}

	token, err := as.createToken(userId)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	if err = as.userService.UpdateLastLogin(userId); err != nil {
		log.Error(err)
		return nil, errutil.ErrUpdateMetaData
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

func (as *AuthService) createToken(userId int) (*types.JwtToken, error) {
	var token *types.JwtToken
	var err error

	if token, err = as.jwtService.CreateToken(userId); err != nil {
		return nil, errutil.ErrCreateJwt
	}

	if err = as.jwtService.StoreTokenUuid(userId, token); err != nil {
		return nil, errutil.ErrStoreTokenUuid
	}

	return token, nil
}

func (as *AuthService) Logout(user *types.LoggedInUser) error {
	return as.jwtService.DeleteTokenUuid(
		as.config.Redis.AccessUuidPrefix+user.AccessUuid,
		as.config.Redis.RefreshUuidPrefix+user.RefreshUuid,
	)
}

func (as *AuthService) RefreshToken(refreshToken string) (*types.LoginResp, error) {
	oldToken, err := as.parseToken(refreshToken, consts.RefreshTokenType)
	if err != nil {
		return nil, errutil.ErrInvalidRefreshToken
	}

	if !as.userBelongsToTokenUuid(oldToken.UserID, oldToken.RefreshUuid, consts.RefreshTokenType) {
		return nil, errutil.ErrInvalidRefreshToken
	}

	var user *types.UserResp
	if user, err = as.userService.GetUserResponse(oldToken.UserID, false); err != nil {
		return nil, err
	}

	var newToken *types.JwtToken

	if newToken, err = as.createToken(user.ID); err != nil {
		log.Error(err)
		return nil, err
	}

	if err = as.jwtService.DeleteTokenUuid(
		as.config.Redis.AccessUuidPrefix+oldToken.AccessUuid,
		as.config.Redis.RefreshUuidPrefix+oldToken.RefreshUuid,
	); err != nil {
		log.Error(err)
		return nil, errutil.ErrDeleteOldTokenUuid
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

func (as *AuthService) VerifyToken(accessToken string) (*types.UserResp, error) {
	token, err := as.parseToken(accessToken, consts.AccessTokenType)
	if err != nil {
		return nil, errutil.ErrInvalidAccessToken
	}

	if !as.userBelongsToTokenUuid(token.UserID, token.AccessUuid, consts.AccessTokenType) {
		return nil, errutil.ErrInvalidAccessToken
	}

	var userResp *types.UserResp

	if userResp, err = as.userService.GetUserResponse(token.UserID, true); err != nil {
		return nil, err
	}

	return userResp, nil
}

func (as *AuthService) parseToken(token, tokenType string) (*types.JwtToken, error) {
	claims, err := as.parseTokenClaim(token, tokenType)
	if err != nil {
		return nil, err
	}

	tokenDetails := &types.JwtToken{}

	if err := methodutil.MapToStruct(claims, &tokenDetails); err != nil {
		log.Error(err)
		return nil, err
	}

	if tokenDetails.UserID == 0 || tokenDetails.AccessUuid == "" || tokenDetails.RefreshUuid == "" {
		log.Error(claims)
		return nil, errutil.ErrInvalidRefreshToken
	}

	return tokenDetails, nil
}

func (as *AuthService) parseTokenClaim(token, tokenType string) (jwt.MapClaims, error) {
	secret := as.config.Jwt.AccessTokenSecret

	if tokenType == consts.RefreshTokenType {
		secret = as.config.Jwt.RefreshTokenSecret
	}

	parsedToken, err := methodutil.ParseJwtToken(token, secret)
	if err != nil {
		log.Error(err)
		return nil, errutil.ErrParseJwt
	}

	if _, ok := parsedToken.Claims.(jwt.Claims); !ok || !parsedToken.Valid {
		return nil, errutil.ErrInvalidAccessToken
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errutil.ErrInvalidAccessToken
	}

	return claims, nil
}

func (as *AuthService) userBelongsToTokenUuid(userId int, uuid, uuidType string) bool {
	prefix := as.config.Redis.AccessUuidPrefix

	if uuidType == consts.RefreshTokenType {
		prefix = as.config.Redis.RefreshUuidPrefix
	}

	redisKey := prefix + uuid

	redisUserId, err := as.redisRepository.GetInt(redisKey)
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

func (as *AuthService) SocialLogin(data *types.SocialLoginReq) (*types.LoginResp, error) {
	switch data.LoginProvider {
	case consts.LoginProviderGoogle:
		resp, err := as.processGoogleLogin(data.Token)
		if err != nil {
			return nil, err
		}

		return resp, nil
	case consts.LoginProviderFacebook:
		resp, err := as.processFacebookLogin(data.Token)
		if err != nil {
			return nil, err
		}

		return resp, nil
	case consts.LoginProviderApple:
		resp, err := as.processAppleLogin(data.Token)
		if err != nil {
			return nil, err
		}

		return resp, nil
	default:
		return nil, errutil.ErrInvalidLoginProvider
	}
}

func (as *AuthService) processGoogleLogin(token string) (*types.LoginResp, error) {
	req := &types.SocialLoginData{}
	resp := &types.LoginResp{}

	if !as.isValidGoogleIdToken(token) {
		return nil, errutil.ErrInvalidLoginToken
	}

	googleUser, err := as.googleUserInfo(token)
	if err != nil {
		return nil, err
	}

	user, err := as.userService.GetUserByEmail(googleUser.Email)

	if err != nil && err == gorm.ErrRecordNotFound {
		req.Email = googleUser.Email
		req.LoginProvider = consts.LoginProviderGoogle
		user, err = as.userService.CreateUserForSocialLogin(req)
		if err != nil {
			return nil, err
		}
	}

	if user.LoginProvider != consts.LoginProviderGoogle {
		return nil, as.getLoginProviderError(user.LoginProvider)
	}

	loginResp, err := as.login(user.ID)
	if err != nil {
		return nil, err
	}

	respErr := methodutil.CopyStruct(loginResp, &resp)
	if respErr != nil {
		return nil, respErr
	}
	return resp, nil
}

func (as *AuthService) isValidGoogleIdToken(idToken string) bool {
	google, err := oauth2.NewService(context.Background(), option.WithAPIKey(as.config.App.GoogleApiKey))
	if err != nil {
		log.Error(err)
		return false
	}

	if _, err := google.Tokeninfo().IdToken(idToken).Do(); err != nil {
		log.Error(err)
		return false
	}

	return true
}

func (as *AuthService) googleUserInfo(idToken string) (*types.GoogleTokenInfo, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(idToken, &types.GoogleTokenInfo{})
	if err != nil {
		log.Error(err)
		return nil, err
	}

	if tokenInfo, ok := token.Claims.(*types.GoogleTokenInfo); ok {
		return tokenInfo, nil
	}

	return nil, errutil.ErrParseJwt
}

func (as *AuthService) processFacebookLogin(token string) (*types.LoginResp, error) {
	req := &types.SocialLoginData{}
	resp := &types.LoginResp{}

	fbUser, err := fbUserInfo(token)
	if err != nil {
		return nil, err
	}

	user, err := as.userService.GetUserByEmail(fbUser.Email)

	if err != nil && err == gorm.ErrRecordNotFound {
		req.Email = fbUser.Email
		req.LoginProvider = consts.LoginProviderFacebook
		user, err = as.userService.CreateUserForSocialLogin(req)
		if err != nil {
			return nil, err
		}
	}

	if user.LoginProvider != consts.LoginProviderFacebook {
		return nil, as.getLoginProviderError(user.LoginProvider)
	}

	loginResp, err := as.login(user.ID)
	if err != nil {
		return nil, err
	}

	respErr := methodutil.CopyStruct(loginResp, &resp)
	if respErr != nil {
		return nil, respErr
	}

	return resp, nil
}

func fbUserInfo(token string) (*types.FbTokenInfo, error) {
	tokenInfo := &types.FbTokenInfo{}
	url := fmt.Sprintf("https://graph.facebook.com/me?fields=name,first_name,last_name,email&access_token=%s", token)
	resp, err := http.Get(url)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, errutil.ErrInvalidLoginToken
	}

	if err := json.NewDecoder(resp.Body).Decode(tokenInfo); err != nil {
		log.Error(err)
		return nil, err
	}

	return tokenInfo, nil
}

func (as *AuthService) processAppleLogin(token string) (*types.LoginResp, error) {
	req := &types.SocialLoginData{}
	resp := &types.LoginResp{}

	if !as.isValidAppleIdToken(token) {
		return nil, errutil.ErrInvalidLoginToken
	}

	appleUser, err := as.appleUserInfo(token)
	if err != nil {
		return nil, err
	}

	user, err := as.userService.GetUserByEmail(appleUser.Email)

	if err != nil && err == gorm.ErrRecordNotFound {
		req.Email = appleUser.Email
		req.LoginProvider = consts.LoginProviderApple
		user, err = as.userService.CreateUserForSocialLogin(req)
		if err != nil {
			return nil, err
		}
	}

	if user.LoginProvider != consts.LoginProviderApple {
		return nil, as.getLoginProviderError(user.LoginProvider)
	}

	loginResp, err := as.login(user.ID)
	if err != nil {
		return nil, err
	}

	respErr := methodutil.CopyStruct(loginResp, &resp)
	if respErr != nil {
		return nil, respErr
	}

	return resp, nil
}

func (as *AuthService) isValidAppleIdToken(idToken string) bool {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return false
	}

	header := parts[0]
	claim := parts[1]
	signature := parts[2]

	claimData, err := base64.RawURLEncoding.DecodeString(claim)
	if err != nil {
		log.Error(err)
		return false
	}

	var tokenInfo types.AppleTokenInfo
	err = json.Unmarshal(claimData, &tokenInfo)
	if err != nil {
		log.Error(err)
		return false
	}

	conf := as.config.AppleLogin
	if tokenInfo.Issuer != conf.AppleIdUrl {
		log.Error(errors.New("Apple idToken issuer invalid: "), tokenInfo.Issuer)
		return false
	}

	if tokenInfo.Audience != conf.AppBundleID {
		log.Error(errors.New("Apple idToken audience invalid: "), tokenInfo.Audience)
		return false
	}

	// if tokenInfo.ExpiresAt <= time.Now().Unix() {
	//	return false
	// }

	keys, err := applekeyutil.GetApplePublicKeys(conf.ApplePublicKeyUrl, conf.ApplePublicKeyTimeout)
	if err != nil {
		log.Error(err)
		return false
	}

	token, _ := jwt.Parse(idToken, nil)

	var key applekeyutil.AppleKey
	for _, v := range keys {
		if v.Kid == token.Header["kid"].(string) {
			key = v
		}
	}

	if key.N == "" || key.E == "" {
		log.Error("No matching Apple public key found!")
		return false
	}

	publicKeyObject := applekeyutil.GetPublicKeyObject(key.N, key.E)

	payload := []byte(header + "." + claim)
	hashedPayload := sha256.Sum256(payload)
	signatureBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		log.Error(err)
		return false
	}

	err = rsa.VerifyPKCS1v15(publicKeyObject, crypto.SHA256, hashedPayload[:], signatureBytes)
	if err != nil {
		log.Error(err)
		return false
	}

	return true
}

func (as *AuthService) appleUserInfo(idToken string) (*types.AppleTokenInfo, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(idToken, &types.AppleTokenInfo{})
	if err != nil {
		log.Error(err)
		return nil, err
	}

	if tokenInfo, ok := token.Claims.(*types.AppleTokenInfo); ok {
		return tokenInfo, nil
	}

	return nil, errutil.ErrParseJwt
}

func (as *AuthService) getLoginProviderError(provider string) error {
	loginProviders := consts.LoginProviders()
	switch loginProviders[provider] {
	case consts.Apple:
		return errutil.ErrUserAlreadyRegisteredViaApple
	case consts.Facebook:
		return errutil.ErrUserAlreadyRegisteredViaFacebook
	case consts.Google:
		return errutil.ErrUserAlreadyRegisteredViaGoogle
	default:
		return errutil.ErrEmailAlreadyRegistered
	}
}
