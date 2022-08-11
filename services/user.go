package services

import (
	errors2 "auth/errors"
	"strconv"
	"strings"
	"time"

	"auth/config"
	"auth/consts"
	"auth/models"
	"auth/repositories"
	"auth/types"
	"auth/utils/log"
	"auth/utils/methods"
	"github.com/google/uuid"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

type UserService struct {
	config          *config.Config
	redisRepository *repositories.RedisRepository
	userRepository  *repositories.UserRepository
}

func NewUserService(redisRepository *repositories.RedisRepository,
	userRepository *repositories.UserRepository) *UserService {
	return &UserService{
		config:          config.AllConfig(),
		redisRepository: redisRepository,
		userRepository:  userRepository,
	}
}

func initUser(userData interface{}) (*models.User, error) {
	user := &models.User{}
	err := methods.CopyStruct(userData, &user)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	user.UserName = strings.ToLower(user.UserName)
	return user, nil
}

func (us *UserService) Create(userData interface{}) (*models.User, error) {
	user, err := initUser(userData)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	if user.LoginProvider == consts.LoginProviderHink {
		*user.Password = encryptPassword(*user.Password)
	} else {
		*user.Verified = true
	}

	if err := us.userRepository.Create(user); err != nil {
		log.Error(err)
		return nil, err
	}
	return user, nil
}

func (us *UserService) Update(userData interface{}) (*types.UserResp, error) {
	user, err := initUser(userData)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	if err = us.userRepository.Update(user); err != nil {
		log.Error(err)
		return nil, err
	}

	userResp, err := us.refreshUserCache(user.ID)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	return userResp, nil
}

func (us *UserService) UpdateUserStat(userStat *types.UserStatUpdateReq) (*types.UserResp, error) {
	user, err := initUser(userStat)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	dbUser, err := us.GetUserResponse(user.ID, true)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	if user.UploadCount != 0 {
		if *userStat.IncrementUpload {
			user.UploadCount = dbUser.UploadCount + user.UploadCount
		} else {
			user.UploadCount = dbUser.UploadCount - user.UploadCount
		}
	}

	err = us.userRepository.Update(user)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	userResp, err := us.refreshUserCache(user.ID)
	if err != nil {
		log.Error(err)
		return nil, errors2.UpdateCache(consts.User)
	}

	return userResp, nil
}

func (us *UserService) refreshUserCache(userId int) (*types.UserResp, error) {
	userResp := &types.UserResp{}
	user, err := us.GetUserById(userId)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	err = methods.CopyStruct(user, &userResp)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	if err := us.redisRepository.SetStruct(us.config.Redis.UserPrefix+strconv.Itoa(userResp.ID), userResp, us.config.Redis.UserTtl); err != nil {
		log.Error(err)
		return nil, errors2.UpdateCache(consts.User)
	}

	return userResp, nil
}

func (us *UserService) GetUserByEmail(email string) (*models.User, error) {
	user, err := us.userRepository.FindBy("email", email)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return user, nil
}

func (us *UserService) GetUserById(id int) (*models.User, error) {
	user, err := us.userRepository.FindBy("id", id)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return user, nil
}

func (us *UserService) UpdateLastLogin(userId int) error {
	lastLoginAt := time.Now().UTC()
	data := map[string]interface{}{
		"last_login_at": lastLoginAt,
	}
	if err := us.userRepository.UpdateByInterface(userId, data); err != nil {
		log.Error(err)
		return errors2.Update(consts.MetaData)
	}
	return nil
}

func (us *UserService) GetUserResponse(userId int, checkInCache bool) (*types.UserResp, error) {
	userResp := &types.UserResp{}
	var err error

	if checkInCache {
		if err = us.redisRepository.GetStruct(us.config.Redis.UserPrefix+strconv.Itoa(userId), &userResp); err == nil {
			log.Info("Token user served from cache")
			return userResp, nil
		}
		log.Error(err)
	}

	if userResp, err = us.refreshUserCache(userId); err != nil {
		log.Error(err)
		return nil, err
	}

	return userResp, nil
}

func (us *UserService) GetUsers(pagination *types.Pagination) error {
	pagination.QueryTargetFields = []string{"name", "user_name", "email"}
	users, err := us.userRepository.All(pagination)
	if err != nil {
		log.Error(err)
		return err
	}
	var usersResp []*types.UserResp
	err = methods.CopyStruct(users, &usersResp)
	if err != nil {
		log.Error(err)
		return err
	}
	pagination.Rows = usersResp
	return nil
}

func (us *UserService) DeleteUser(id int) error {
	if err := us.userRepository.Delete(id); err != nil {
		log.Error(err)
		return err
	}
	return nil
}

func (us *UserService) ChangePassword(userId int, req *types.ChangePasswordReq) error {
	user, err := us.GetUserById(userId)
	if err != nil {
		log.Error(err)
		return err
	}

	currentPass := []byte(*user.Password)
	if err = bcrypt.CompareHashAndPassword(currentPass, []byte(req.OldPassword)); err != nil {
		log.Error(err)
		return errors2.Invalid(consts.Password)
	}

	hashedPass, _ := bcrypt.GenerateFromPassword([]byte(req.NewPassword), 8)
	data := map[string]interface{}{
		"password": hashedPass,
	}

	if err := us.userRepository.UpdateByInterface(userId, data); err != nil {
		log.Error(err)
		return errors2.Update(consts.Password)
	}
	return nil
}

func (us *UserService) ForgotPassword(email string) (*types.ForgotPasswordResp, error) {
	user, err := us.GetUserByEmail(email)
	if err != nil {
		log.Error(err)
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

	otpResp, err := us.createForgotPasswordOtp(user.ID, email)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	resp := types.ForgotPasswordResp{
		UserID:   user.ID,
		Token:    signedToken,
		OtpNonce: otpResp.OtpNonce,
	}

	return &resp, nil
}

func (us *UserService) VerifyResetPassword(req *types.VerifyResetPasswordReq) error {
	user, err := us.GetUserById(req.ID)
	if err != nil {
		log.Error(err)
		return err
	}

	secret := passwordResetSecret(user)

	parsedToken, err := methods.ParseJwtToken(req.Token, secret)
	if err != nil {
		log.Error(err)
		return errors2.ParseToken(consts.JWTToken)
	}

	if _, ok := parsedToken.Claims.(jwt.Claims); !ok && !parsedToken.Valid {
		return errors2.Invalid(consts.ResetToken)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return errors2.Invalid(consts.ResetToken)
	}

	parsedEmail := claims["email"].(string)
	if user.Email != parsedEmail {
		return errors2.Invalid(consts.ResetToken)
	}

	if !methods.IsEmpty(req.Otp) && !methods.IsEmpty(req.Nonce) {
		otpReq := &types.ForgotPasswordOtpReq{
			Nonce: req.Nonce,
			Otp:   req.Otp,
		}
		if ok, err := us.verifyForgotPasswordOtp(otpReq); err != nil && !ok {
			return errors2.Invalid(consts.OTP)
		}
	}

	return nil
}

func (us *UserService) ResetPassword(req *types.ResetPasswordReq) error {
	hashedPass, _ := bcrypt.GenerateFromPassword([]byte(req.Password), 8)
	data := map[string]interface{}{
		"password": hashedPass,
	}
	if err := us.userRepository.UpdateByInterface(req.ID, data); err != nil {
		log.Error(err)
		return errors2.ResetPassword()
	}

	return nil
}

func (us *UserService) ResendForgotPasswordOtp(nonce string) (*types.ForgotPasswordOtpResp, error) {
	redisConf := us.config.Redis
	nonceKey := redisConf.OtpNoncePrefix + consts.UserForgotPasswordOtp + nonce

	userId, err := us.redisRepository.GetInt(nonceKey)
	if err != nil {
		log.Error(err)
		return nil, errors2.Invalid(consts.OTPNonce)
	}

	otpKey := redisConf.OtpPrefix + consts.UserForgotPasswordOtp + strconv.Itoa(userId)

	// getting user detail using userid
	userDetail, err := us.GetUserResponse(userId, true)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	// delete current otp and nonce key
	_ = us.redisRepository.Del(nonceKey, otpKey)

	resp, err := us.createForgotPasswordOtp(userId, userDetail.Email)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	return resp, nil
}

func encryptPassword(plainPass string) string {
	hashedPass, _ := bcrypt.GenerateFromPassword([]byte(plainPass), 8)
	return string(hashedPass)
}

func passwordResetSecret(user *models.User) string {
	return *user.Password + strconv.Itoa(int(user.CreatedAt.Unix()))
}

func (us *UserService) createForgotPasswordOtp(userId int, email string) (*types.ForgotPasswordOtpResp, error) {
	redisConf := us.config.Redis
	otpKey := redisConf.OtpPrefix + consts.UserForgotPasswordOtp + strconv.Itoa(userId)

	nonce := uuid.New().String()

	otp, err := methods.GenerateOTP(6)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	// NOTE: "nonce" key will be deleted upon otp verification or resend otp
	if err := us.redisRepository.Set(redisConf.OtpNoncePrefix+consts.UserForgotPasswordOtp+nonce, userId, redisConf.OtpNonceTtl); err != nil {
		log.Error(err)
		return nil, err
	}

	// NOTE: "otp" key will be deleted upon otp verification
	if err := us.redisRepository.Set(otpKey, otp, redisConf.OtpTtl); err != nil {
		log.Error(err)
		return nil, err
	}

	return &types.ForgotPasswordOtpResp{OtpNonce: nonce}, nil
}

func (us *UserService) verifyForgotPasswordOtp(data *types.ForgotPasswordOtpReq) (bool, error) {
	redisConf := us.config.Redis

	nonceKey := redisConf.OtpNoncePrefix + consts.UserForgotPasswordOtp + data.Nonce
	userId, err := us.redisRepository.GetInt(nonceKey)
	if err != nil {
		log.Error(err)
		return false, errors2.Invalid(consts.OTPNonce)
	}

	otpKey := redisConf.OtpPrefix + consts.UserForgotPasswordOtp + strconv.Itoa(userId)
	otp, err := us.redisRepository.Get(otpKey)
	if err != nil || otp != data.Otp {
		log.Error(err)
		return false, errors2.Invalid(consts.OTPNonce)
	}

	if err = us.redisRepository.Del(nonceKey, otpKey); err != nil {
		log.Error(err)
	}

	return true, nil
}
