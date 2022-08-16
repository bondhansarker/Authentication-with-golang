package serviceImpl

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
	"auth/rest_errors"
	"auth/services"
	"auth/types"
	"auth/utils/key_generator"
	"auth/utils/log"
	"auth/utils/methods"
	"github.com/dgrijalva/jwt-go"
	"google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
)

type oAuthService struct {
	userService services.IUserService
}

func NewOAuthService(userService services.IUserService) services.IOAuthService {
	return &oAuthService{
		userService: userService,
	}
}

func (ols *oAuthService) CreateUserWithProvider(email, provider string) (int, error) {
	dbUser, err := ols.userService.GetUserByEmail(email)
	user := &types.UserResp{}

	if err != nil && methods.IsSameError(errors.New(rest_errors.UserNotFound), err) {
		req := &types.UserCreateUpdateReq{
			Email:         email,
			LoginProvider: provider,
		}
		user, err = ols.userService.CreateUser(req)
		if err != nil {
			log.Error(err)
			return consts.DefaultInt, errors.New(rest_errors.ErrLogin)
		}
	}

	if err := methods.CopyStruct(dbUser, &user); err != nil {
		log.Error(err)
		return consts.DefaultInt, errors.New(rest_errors.ErrLogin)
	}

	if user.LoginProvider != provider {
		return consts.DefaultInt, errors.New(rest_errors.InvalidLoginAttempt(user.LoginProvider))
	}
	return user.ID, nil
}

func (ols *oAuthService) ProcessGoogleLogin(token string) (int, error) {
	if !ols.IsValidGoogleIdToken(token) {
		return consts.DefaultInt, errors.New(rest_errors.InvalidSocialLoginToken)
	}
	googleUser, err := ols.FetchGoogleUserInfo(token)
	if err != nil {
		log.Error(err)
		return consts.DefaultInt, err
	}
	return ols.CreateUserWithProvider(googleUser.Email, consts.LoginProviderGoogle)
}

func (ols *oAuthService) ProcessFacebookLogin(token string) (int, error) {
	fbUser, err := ols.FetchFbUserInfo(token)
	if err != nil {
		log.Error(err)
		return consts.DefaultInt, err
	}
	return ols.CreateUserWithProvider(fbUser.Email, consts.LoginProviderFacebook)
}

func (ols *oAuthService) ProcessAppleLogin(token string) (int, error) {
	if !ols.IsValidAppleIdToken(token) {
		return consts.DefaultInt, errors.New(rest_errors.InvalidSocialLoginToken)
	}
	appleUser, err := ols.FetchAppleUserInfo(token)
	if err != nil {
		log.Error(err)
		return consts.DefaultInt, err
	}
	return ols.CreateUserWithProvider(appleUser.Email, consts.LoginProviderApple)
}

func (ols *oAuthService) FetchGoogleUserInfo(idToken string) (*types.GoogleTokenInfo, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(idToken, &types.GoogleTokenInfo{})
	if err != nil {
		log.Error(err)
		return nil, errors.New(rest_errors.InvalidSocialLoginToken)
	}
	if tokenInfo, ok := token.Claims.(*types.GoogleTokenInfo); ok {
		return tokenInfo, nil
	}
	return nil, errors.New(rest_errors.InvalidSocialLoginToken)
}

func (ols *oAuthService) FetchFbUserInfo(token string) (*types.FbTokenInfo, error) {
	tokenInfo := &types.FbTokenInfo{}
	url := fmt.Sprintf("https://graph.facebook.com/me?fields=name,first_name,last_name,email&access_token=%s", token)
	resp, err := http.Get(url)
	if err != nil {
		log.Error(err)
		return nil, errors.New(rest_errors.InvalidSocialLoginToken)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(rest_errors.InvalidSocialLoginToken)
	}

	if err := json.NewDecoder(resp.Body).Decode(tokenInfo); err != nil {
		log.Error(err)
		return nil, errors.New(rest_errors.InvalidSocialLoginToken)
	}

	return tokenInfo, nil
}

func (ols *oAuthService) FetchAppleUserInfo(token string) (*types.AppleTokenInfo, error) {
	parsedToken, _, err := new(jwt.Parser).ParseUnverified(token, &types.AppleTokenInfo{})
	if err != nil {
		log.Error(err)
		return nil, errors.New(rest_errors.InvalidSocialLoginToken)
	}
	if tokenInfo, ok := parsedToken.Claims.(*types.AppleTokenInfo); ok {
		return tokenInfo, nil
	}
	return nil, errors.New(rest_errors.InvalidSocialLoginToken)
}

func (ols *oAuthService) IsValidAppleIdToken(idToken string) bool {
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
		log.Error("invalid Apple id token issuer  ", tokenInfo.Issuer)
		return false
	}

	if tokenInfo.Audience != conf.AppBundleID {
		log.Error("invalid Apple idToken audience  ", tokenInfo.Audience)
		return false
	}

	// if tokenInfo.ExpiresAt <= time.Now().Unix() {
	//	return false
	// }

	keys, err := key_generator.GetApplePublicKeys(conf.ApplePublicKeyUrl, conf.ApplePublicKeyTimeout)
	if err != nil {
		log.Error(err)
		return false
	}

	token, _ := jwt.Parse(idToken, nil)

	var key key_generator.AppleKey
	for _, v := range keys {
		if v.Kid == token.Header["kid"].(string) {
			key = v
		}
	}

	if key.N == "" || key.E == "" {
		log.Error("No matching Apple public key found!")
		return false
	}

	publicKeyObject := key_generator.GetPublicKeyObject(key.N, key.E)

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

func (ols *oAuthService) IsValidGoogleIdToken(idToken string) bool {
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
