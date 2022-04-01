package usersvc

import (
	"auth/clients"
	"auth/config"
	"auth/conn"
	"auth/consts"
	"auth/log"
	"auth/models"
	"auth/services/redissvc"
	"auth/types"
	"auth/utils/errutil"
	"auth/utils/methodutil"
	"auth/utils/msgutil"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func CreateUser(userData *types.UserCreateUpdateReq) (*models.User, error) {
	existingUser, err := GetUserByEmail(userData.Email)

	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}

	// if user exists and verified
	if err == nil && existingUser.Verified {
		return nil, errutil.ErrUserAlreadyRegistered
	}

	// if user doesn't exist
	user := getUserModel(userData, true)
	if userData.LoginProvider == consts.LoginProviderHink {
		*user.Password = encryptPassword(*userData.Password)
	}

	if err := conn.Db().Create(&user).Error; err != nil {
		log.Error(err)
		return nil, errutil.ErrUserCreate
	}

	return user, nil
}

func UpdateUser(userData *types.UserCreateUpdateReq) error {
	user := getUserModel(userData, false)

	err := conn.Db().Model(&models.User{}).
		Where("id = ?", user.ID).
		Omit("email", "password").
		Updates(&user).
		Error
	if err != nil {
		log.Error(err)
		return errutil.ErrUserUpdate
	}

	if err := refreshUserCache(user.ID); err != nil {
		log.Error(err)
	}

	return nil
}

func refreshUserCache(userId int) error {
	userResp, err := GetUser(userId)
	if err != nil {
		return err
	}

	userResp.Cache()

	return nil
}

func GetUserByEmail(email string) (*models.User, error) {
	user := &models.User{}

	if err := conn.Db().Where("email = ?", email).First(&user).Error; err != nil {
		log.Error(err)
		return nil, err
	}

	return user, nil
}

func GetUserById(id int) (*models.User, error) {
	user := &models.User{}

	if err := conn.Db().Where("id = ?", id).First(&user).Error; err != nil {
		log.Error(err)
		return nil, err
	}

	return user, nil
}

func SetMetaDataUponLogin(userId int, isAfterOtpVerification bool) error {
	lastLoginAt := time.Now().UTC()
	updates := map[string]interface{}{
		"last_login_at": lastLoginAt,
	}

	if isAfterOtpVerification {
		updates["verified"] = 1
	}

	if err := conn.Db().Model(&models.User{}).Where("id = ?", userId).Updates(updates).Error; err != nil {
		log.Error(err)
		return err
	}

	return nil
}

func GetUserFromContext(c echo.Context) (*types.LoggedInUser, error) {
	user, ok := c.Get("user").(*types.LoggedInUser)
	if !ok {
		return nil, errutil.ErrNoContextUser
	}

	return user, nil
}

func GetUser(id int) (*types.UserResp, error) {
	user := &types.UserResp{}

	if err := conn.Db().Model(&models.User{}).Where("id = ?", id).First(&user).Error; err != nil {
		log.Error(err)
		return nil, err
	}

	return user, nil
}

func DeleteUser(id int) error {
	res := conn.Db().Where("id = ?", id).Delete(&models.User{})
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	if res.Error != nil {
		log.Error(res.Error)
		return res.Error
	}

	return nil
}

func ChangePassword(id int, data *types.ChangePasswordReq) error {
	user, err := GetUserById(id)
	if err != nil {
		return err
	}

	currentPass := []byte(*user.Password)
	if err = bcrypt.CompareHashAndPassword(currentPass, []byte(data.OldPassword)); err != nil {
		log.Error(err)
		return errutil.ErrInvalidPassword
	}

	hashedPass, _ := bcrypt.GenerateFromPassword([]byte(data.NewPassword), 8)
	updates := map[string]interface{}{
		"password": hashedPass,
	}

	err = conn.Db().Model(&user).Updates(updates).Error
	if err != nil {
		log.Error(err)
		return err
	}

	return nil
}

func ForgotPassword(email string) (*types.ForgotPasswordResp, error) {
	user, err := GetUserByEmail(email)
	if err != nil {
		return nil, err
	}

	if user.LoginProvider != consts.LoginProviderHink {
		return &types.ForgotPasswordResp{
			Provider: user.LoginProvider,
		}, nil
	}

	secret := passwordResetSecret(user)

	payload := jwt.MapClaims{}
	payload["email"] = user.Email

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	signedToken, err := token.SignedString([]byte(secret))

	if err != nil {
		log.Error(err)
		return nil, err
	}

	otpResp, err := createForgotPasswordOtp(user.ID, email)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	resp := types.ForgotPasswordResp{
		Message:  msgutil.ForgotPasswordWithOtpMsg(user.Email),
		UserID:   user.ID,
		Token:    signedToken,
		OtpNonce: otpResp.OtpNonce,
	}

	return &resp, nil
}

func VerifyResetPassword(req *types.VerifyResetPasswordReq) error {
	user, err := GetUserById(req.ID)
	if err != nil {
		log.Error(err)
		return err
	}

	secret := passwordResetSecret(user)

	parsedToken, err := methodutil.ParseJwtToken(req.Token, secret)
	if err != nil {
		log.Error(err)
		return errutil.ErrParseJwt
	}

	if _, ok := parsedToken.Claims.(jwt.Claims); !ok && !parsedToken.Valid {
		return errutil.ErrInvalidPasswordResetToken
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return errutil.ErrInvalidPasswordResetToken
	}

	parsedEmail := claims["email"].(string)
	if user.Email != parsedEmail {
		return errutil.ErrInvalidPasswordResetToken
	}

	if !methodutil.IsEmpty(req.Otp) && !methodutil.IsEmpty(req.Nonce) {
		otpReq := &types.ForgotPasswordOtpReq{
			Nonce: req.Nonce,
			Otp:   req.Otp,
		}
		if ok, err := verifyForgotPasswordOtp(otpReq); err != nil && !ok {
			return errutil.ErrInvalidOtp
		}
	}

	return nil
}

func ResetPassword(req *types.ResetPasswordReq) error {
	hashedPass, _ := bcrypt.GenerateFromPassword([]byte(req.Password), 8)
	err := conn.Db().Model(&models.User{}).
		Where("id = ?", req.ID).
		Update("password", hashedPass).
		Error

	if err != nil {
		log.Error(err)
		return err
	}

	return nil
}

func CreateUserForSocialLogin(userData *types.SocialLoginResp) (*models.User, error) {
	user := &models.User{
		Email:         userData.Email,
		FirstName:     userData.FirstName,
		LastName:      userData.LastName,
		LoginProvider: userData.LoginProvider,
		Verified:      true,
	}

	if err := conn.Db().Create(&user).Error; err != nil {
		log.Error(err)
		return nil, err
	}
	return user, nil
}

func encryptPassword(plainPass string) string {
	hashedPass, _ := bcrypt.GenerateFromPassword([]byte(plainPass), 8)

	return string(hashedPass)
}

func passwordResetSecret(user *models.User) string {
	return *user.Password + strconv.Itoa(int(user.CreatedAt.Unix()))
}

func getUserModel(userData *types.UserCreateUpdateReq, newUser bool) *models.User {
	user := &models.User{}

	switch newUser {
	case true:
		user.Email = userData.Email
		user.Phone = userData.Phone
		user.LoginProvider = userData.LoginProvider

		if userData.LoginProvider == consts.LoginProviderHink {
			user.Password = userData.Password
		}
	case false:
		user.ID = userData.ID
	}

	user.FirstName = userData.FirstName
	user.LastName = userData.LastName
	user.ProfilePic = userData.ProfilePic

	return user
}

func createForgotPasswordOtp(userId int, email string) (*types.ForgotPasswordOtpResp, error) {
	redisConf := config.Redis()
	otpKey := redisConf.OtpPrefix + consts.UserForgotPasswordOtp + strconv.Itoa(userId)

	nonce := uuid.New().String()

	otp, err := methodutil.GenerateOTP(6)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	// NOTE: "nonce" key will be deleted upon otp verification or resend otp
	if err := redissvc.Set(redisConf.OtpNoncePrefix+consts.UserForgotPasswordOtp+nonce, userId, redisConf.OtpNonceTtl); err != nil {
		log.Error(err)
		return nil, err
	}

	// NOTE: "otp" key will be deleted upon otp verification
	if err := redissvc.Set(otpKey, otp, redisConf.OtpTtl); err != nil {
		log.Error(err)
		return nil, err
	}

	// email service
	go func(email, otp string) {
		defer methodutil.RecoverPanic()
		emailBody := types.ForgotPasswordEmailOtpReq{
			To:  email,
			Otp: otp,
		}
		path := consts.UserForgotPasswordWithOtpApiPath
		if err := clients.Email().Send(path, emailBody); err != nil {
			log.Error(err)
		}
	}(email, otp)

	return &types.ForgotPasswordOtpResp{OtpNonce: nonce}, nil
}

func verifyForgotPasswordOtp(data *types.ForgotPasswordOtpReq) (bool, error) {
	redisConf := config.Redis()

	nonceKey := redisConf.OtpNoncePrefix + consts.UserForgotPasswordOtp + data.Nonce
	userId, err := redissvc.GetInt(nonceKey)
	if err != nil {
		log.Error(err)
		return false, errutil.ErrInvalidOtpNonce
	}

	otpKey := redisConf.OtpPrefix + consts.UserForgotPasswordOtp + strconv.Itoa(userId)
	otp, err := redissvc.Get(otpKey)
	if err != nil || otp != data.Otp {
		log.Error(err)
		return false, errutil.ErrInvalidOtp
	}

	_ = redissvc.Del(nonceKey, otpKey)

	return true, nil
}

func ResendForgotPasswordOtp(nonce string) (*types.ForgotPasswordOtpResp, error) {
	redisConf := config.Redis()

	nonceKey := redisConf.OtpNoncePrefix + consts.UserForgotPasswordOtp + nonce

	userId, err := redissvc.GetInt(nonceKey)
	if err != nil {
		log.Error(err)
		return nil, errutil.ErrInvalidOtpNonce
	}

	otpKey := redisConf.OtpPrefix + consts.UserForgotPasswordOtp + strconv.Itoa(userId)

	// getting user detail using userid
	userDetail, err := GetUser(userId)
	if err != nil {
		return nil, err
	}

	// delete current otp and nonce key
	_ = redissvc.Del(nonceKey, otpKey)

	resp, err := createForgotPasswordOtp(userId, userDetail.Email)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
