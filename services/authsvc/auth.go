package authsvc

import (
	"auth/clients"
	"auth/config"
	"auth/consts"
	"auth/log"
	"auth/models"
	"auth/services/redissvc"
	"auth/services/tokensvc"
	"auth/services/usersvc"
	"auth/types"
	"auth/utils/applekeyutil"
	"auth/utils/errutil"
	"auth/utils/methodutil"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"gorm.io/gorm"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
)

func Login(req *types.LoginReq) (*types.LoginResp, error) {
	var user *models.User
	var err error

	if user, err = usersvc.GetUserByEmail(req.Email); err != nil {
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

	return login(user.ID, false)
}

func login(userId int, isAfterOtpVerification bool) (*types.LoginResp, error) {
	var token *types.JwtToken
	var user *types.UserResp
	var err error

	if user, err = getUserInfo(userId, false); err != nil {
		return nil, err
	}

	if token, err = createToken(user.ID); err != nil {
		log.Error(err)
		return nil, err
	}

	if err = usersvc.SetMetaDataUponLogin(userId, isAfterOtpVerification); err != nil {
		log.Error(err)
		return nil, errutil.ErrUpdateMetaData
	}

	if isAfterOtpVerification {
		// Send welcome email in background
		// email service
		go func(to string) {
			defer methodutil.RecoverPanic()
			emailBody := types.UserCreateEmailReq{
				To: to,
			}
			path := consts.UserCreateMailApiPath
			if err := clients.Email().Send(path, emailBody); err != nil {
				log.Error(err)
			}
		}(user.Email)

		user.Verified = true
		user.Cache()
	}

	res := &types.LoginResp{
		AccessToken:        token.AccessToken,
		AccessTokenExpiry:  token.AccessExpiry,
		RefreshToken:       token.RefreshToken,
		RefreshTokenExpiry: token.RefreshExpiry,
		User:               user,
	}
	return res, nil
}

func createToken(userId int) (*types.JwtToken, error) {
	var token *types.JwtToken
	var err error

	if token, err = tokensvc.CreateToken(userId); err != nil {
		return nil, errutil.ErrCreateJwt
	}

	if err = tokensvc.StoreTokenUuid(userId, token); err != nil {
		return nil, errutil.ErrStoreTokenUuid
	}

	return token, nil
}

func Logout(user *types.LoggedInUser) error {
	return tokensvc.DeleteTokenUuid(
		config.Redis().AccessUuidPrefix+user.AccessUuid,
		config.Redis().RefreshUuidPrefix+user.RefreshUuid,
	)
}

func RefreshToken(refreshToken string) (*types.LoginResp, error) {
	oldToken, err := parseToken(refreshToken, consts.RefreshTokenType)
	if err != nil {
		return nil, errutil.ErrInvalidRefreshToken
	}

	if !userBelongsToTokenUuid(oldToken.UserID, oldToken.RefreshUuid, consts.RefreshTokenType) {
		return nil, errutil.ErrInvalidRefreshToken
	}

	var user *types.UserResp
	if user, err = getUserInfo(oldToken.UserID, false); err != nil {
		return nil, err
	}

	var newToken *types.JwtToken

	if newToken, err = createToken(user.ID); err != nil {
		log.Error(err)
		return nil, err
	}

	if err = tokensvc.DeleteTokenUuid(
		config.Redis().AccessUuidPrefix+oldToken.AccessUuid,
		config.Redis().RefreshUuidPrefix+oldToken.RefreshUuid,
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

func VerifyToken(accessToken string) (*types.UserResp, error) {
	token, err := parseToken(accessToken, consts.AccessTokenType)
	if err != nil {
		return nil, errutil.ErrInvalidAccessToken
	}

	if !userBelongsToTokenUuid(token.UserID, token.AccessUuid, consts.AccessTokenType) {
		return nil, errutil.ErrInvalidAccessToken
	}

	var userResp *types.UserResp

	if userResp, err = getUserInfo(token.UserID, true); err != nil {
		return nil, err
	}

	return userResp, nil
}

func parseToken(token, tokenType string) (*types.JwtToken, error) {
	claims, err := parseTokenClaim(token, tokenType)
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

func parseTokenClaim(token, tokenType string) (jwt.MapClaims, error) {
	secret := config.Jwt().AccessTokenSecret

	if tokenType == consts.RefreshTokenType {
		secret = config.Jwt().RefreshTokenSecret
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

func getUserInfo(userId int, checkInCache bool) (*types.UserResp, error) {
	userResp := &types.UserResp{}
	var err error

	if checkInCache {
		if err = redissvc.GetStruct(config.Redis().UserPrefix+strconv.Itoa(userId), &userResp); err == nil {
			log.Info("Token user served from cache")
			return userResp, nil
		}

		log.Error(err)
	}

	userResp, err = usersvc.GetUser(userId)
	if err != nil {
		return nil, err
	}

	userResp.Cache()

	return userResp, nil
}

func userBelongsToTokenUuid(userId int, uuid, uuidType string) bool {
	prefix := config.Redis().AccessUuidPrefix

	if uuidType == consts.RefreshTokenType {
		prefix = config.Redis().RefreshUuidPrefix
	}

	redisKey := prefix + uuid

	redisUserId, err := redissvc.GetInt(redisKey)
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

func SocialLogin(data *types.SocialLoginReq) (*types.LoginResp, error) {
	switch data.LoginProvider {
	case consts.LoginProviderGoogle:
		resp, err := processGoogleLogin(data.Token)
		if err != nil {
			return nil, err
		}

		return resp, nil
	case consts.LoginProviderFacebook:
		resp, err := processFacebookLogin(data.Token)
		if err != nil {
			return nil, err
		}

		return resp, nil
	case consts.LoginProviderApple:
		resp, err := processAppleLogin(data.Token)
		if err != nil {
			return nil, err
		}

		return resp, nil
	default:
		return nil, errutil.ErrInvalidLoginProvider
	}
}

func processGoogleLogin(token string) (*types.LoginResp, error) {
	req := &types.SocialLoginData{}
	resp := &types.LoginResp{}

	if !isValidGoogleIdToken(token) {
		return nil, errutil.ErrInvalidLoginToken
	}

	googleUser, err := googleUserInfo(token)
	if err != nil {
		return nil, err
	}

	user, err := usersvc.GetUserByEmail(googleUser.Email)

	if err != nil && err == gorm.ErrRecordNotFound {
		req.Email = googleUser.Email
		req.LoginProvider = consts.LoginProviderGoogle
		user, err = usersvc.CreateUserForSocialLogin(req)
		if err != nil {
			return nil, err
		}
	}

	if user.LoginProvider != consts.LoginProviderGoogle {
		return nil, getLoginProviderError(user.LoginProvider)
	}

	loginResp, err := login(user.ID, false)
	if err != nil {
		return nil, err
	}

	respErr := methodutil.CopyStruct(loginResp, &resp)
	if respErr != nil {
		return nil, respErr
	}
	return resp, nil
}

func isValidGoogleIdToken(idToken string) bool {
	google, err := oauth2.NewService(context.Background(), option.WithAPIKey(config.App().GoogleApiKey))
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

func googleUserInfo(idToken string) (*types.GoogleTokenInfo, error) {
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

func processFacebookLogin(token string) (*types.LoginResp, error) {
	req := &types.SocialLoginData{}
	resp := &types.LoginResp{}

	fbUser, err := fbUserInfo(token)
	if err != nil {
		return nil, err
	}

	user, err := usersvc.GetUserByEmail(fbUser.Email)

	if err != nil && err == gorm.ErrRecordNotFound {
		req.Email = fbUser.Email
		req.LoginProvider = consts.LoginProviderFacebook
		user, err = usersvc.CreateUserForSocialLogin(req)
		if err != nil {
			return nil, err
		}
	}

	if user.LoginProvider != consts.LoginProviderFacebook {
		return nil, getLoginProviderError(user.LoginProvider)
	}

	loginResp, err := login(user.ID, false)
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

func processAppleLogin(token string) (*types.LoginResp, error) {
	req := &types.SocialLoginData{}
	resp := &types.LoginResp{}

	if !isValidAppleIdToken(token) {
		return nil, errutil.ErrInvalidLoginToken
	}

	appleUser, err := appleUserInfo(token)
	if err != nil {
		return nil, err
	}

	user, err := usersvc.GetUserByEmail(appleUser.Email)

	if err != nil && err == gorm.ErrRecordNotFound {
		req.Email = appleUser.Email
		req.LoginProvider = consts.LoginProviderApple
		user, err = usersvc.CreateUserForSocialLogin(req)
		if err != nil {
			return nil, err
		}
	}

	if user.LoginProvider != consts.LoginProviderApple {
		return nil, getLoginProviderError(user.LoginProvider)
	}

	loginResp, err := login(user.ID, false)
	if err != nil {
		return nil, err
	}

	respErr := methodutil.CopyStruct(loginResp, &resp)
	if respErr != nil {
		return nil, respErr
	}

	return resp, nil
}

func isValidAppleIdToken(idToken string) bool {
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

	conf := config.AppleLogin()
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

func appleUserInfo(idToken string) (*types.AppleTokenInfo, error) {
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

func getLoginProviderError(provider string) error {
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
