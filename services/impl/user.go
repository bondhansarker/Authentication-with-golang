package serviceImpl

import (
	"strconv"
	"time"

	"auth/repositories"
	"auth/rest_errors"
	"auth/services"

	"auth/config"
	"auth/consts"
	"auth/models"
	"auth/types"
	"auth/utils/log"
	"auth/utils/methods"
	"github.com/google/uuid"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

type userService struct {
	cacheService   services.ICache
	userRepository repositories.IUserRepository
}

func NewUserService(cacheService services.ICache,
	userRepository repositories.IUserRepository) services.IUserService {
	return &userService{
		cacheService:   cacheService,
		userRepository: userRepository,
	}
}

func (us *userService) CreateUser(userCreateReq *types.UserCreateUpdateReq) (*types.UserResp, error) {
	user, err := us.userRepository.New(userCreateReq)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	if user.LoginProvider == consts.LoginProviderHink {
		*user.Password = encryptPassword(*user.Password)
	} else {
		trueValue := true
		user.Verified = &trueValue
	}

	if err := us.userRepository.Create(user); err != nil {
		log.Error(err)
		return nil, err
	}

	return us.GetUserFromCache(user.ID, false)
}

func (us *userService) UpdateUser(userUpdateReq *types.UserCreateUpdateReq) (*types.UserResp, error) {
	user, err := us.userRepository.New(userUpdateReq)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return us.update(user)
}

func (us *userService) UpdateUserProfilePic(userProfilePic *types.ProfilePicUpdateReq) (*types.UserResp, error) {
	user, err := us.userRepository.New(userProfilePic)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	userResp, err := us.update(user)
	if err != nil {
		return nil, rest_errors.ErrUpdatingUserProfilePic
	}
	return userResp, nil
}

func (us *userService) UpdateUserStat(userStat *types.UserStatUpdateReq) (*types.UserResp, error) {
	user, err := us.userRepository.New(userStat)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	dbUser, err := us.GetUserFromCache(user.ID, false)
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

	userResp, err := us.update(user)
	if err != nil {
		return nil, rest_errors.ErrUpdatingUserStat
	}
	return userResp, nil
}

func (us *userService) UpdateLastLogin(userId int) error {
	lastLoginAt := time.Now().UTC()
	data := map[string]interface{}{
		"last_login_at": lastLoginAt,
	}
	if err := us.userRepository.UpdateByInterface(userId, data); err != nil {
		log.Error(err)
		return rest_errors.ErrUpdatingUserMetaData
	}
	return nil
}

func (us *userService) UpdateUserCache(userId int) (*types.UserResp, error) {
	userResp := &types.UserResp{}
	user, err := us.userRepository.FindBy("id", userId)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	err = methods.CopyStruct(user, &userResp)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	redisConf := config.Redis()
	if err := us.cacheService.SetStruct(redisConf.UserPrefix+strconv.Itoa(userResp.ID), userResp, redisConf.UserTtl); err != nil {
		log.Error(err)
		return nil, rest_errors.ErrUpdatingCacheUser
	}

	return userResp, nil
}

func (us *userService) DeleteUser(userDeleteReq *types.UserDeleteReq) error {
	user, err := us.userRepository.New(userDeleteReq)
	if err != nil {
		log.Error(err)
		return err
	}
	return us.userRepository.Delete(user.ID)
}

func (us *userService) GetUserByEmail(email string) (*models.User, error) {
	user, err := us.userRepository.FindBy("email", email)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return user, nil
}

func (us *userService) GetUserById(id int) (*models.User, error) {
	user, err := us.userRepository.FindBy("id", id)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return user, nil
}

func (us *userService) GetUserFromCache(userId int, checkInCache bool) (*types.UserResp, error) {
	userResp := &types.UserResp{}
	var err error

	if checkInCache {
		if err = us.cacheService.GetStruct(config.Redis().UserPrefix+strconv.Itoa(userId), &userResp); err == nil {
			log.Info("Token user served from cache")
			return userResp, nil
		}
		log.Error(err)
	}

	if userResp, err = us.UpdateUserCache(userId); err != nil {
		log.Error(err)
		return nil, err
	}

	return userResp, nil
}

func (us *userService) GetUsers(pagination *types.Pagination) error {
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

func (us *userService) ChangePassword(userId int, req *types.ChangePasswordReq) error {
	user, err := us.GetUserById(userId)
	if err != nil {
		log.Error(err)
		return err
	}

	currentPass := []byte(*user.Password)
	if err = bcrypt.CompareHashAndPassword(currentPass, []byte(req.OldPassword)); err != nil {
		log.Error(err)
		return rest_errors.InvalidPassword
	}

	hashedPass, _ := bcrypt.GenerateFromPassword([]byte(req.NewPassword), 8)
	data := map[string]interface{}{
		"password": hashedPass,
	}

	if err := us.userRepository.UpdateByInterface(userId, data); err != nil {
		log.Error(err)
		return rest_errors.ErrUpdatingUserPassword
	}
	return nil
}

func (us *userService) ForgotPassword(email string) (*types.ForgotPasswordResp, error) {
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
		return nil, rest_errors.ErrCreatingForgotPasswordOTP
	}

	otpResp, err := us.CreateForgotPasswordOtp(user.ID, email)
	if err != nil {
		log.Error(err)
		return nil, rest_errors.ErrCreatingForgotPasswordOTP
	}

	resp := types.ForgotPasswordResp{
		UserID:   user.ID,
		Token:    signedToken,
		OtpNonce: otpResp.OtpNonce,
	}

	return &resp, nil
}

func (us *userService) VerifyResetPassword(req *types.VerifyResetPasswordReq) error {
	user, err := us.GetUserById(req.ID)
	if err != nil {
		log.Error(err)
		return err
	}

	secret := passwordResetSecret(user)

	parsedToken, err := methods.ParseJwtToken(req.Token, secret)
	if err != nil {
		log.Error(err)
		return rest_errors.ErrParsingJWTToken
	}

	if _, ok := parsedToken.Claims.(jwt.Claims); !ok && !parsedToken.Valid {
		return rest_errors.InvalidResetToken
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return rest_errors.InvalidResetToken
	}

	parsedEmail := claims["email"].(string)
	if user.Email != parsedEmail {
		return rest_errors.InvalidResetToken
	}

	if !methods.IsEmpty(req.Otp) && !methods.IsEmpty(req.Nonce) {
		otpReq := &types.ForgotPasswordOtpReq{
			Nonce: req.Nonce,
			Otp:   req.Otp,
		}
		if ok, err := us.VerifyForgotPasswordOtp(otpReq); err != nil && !ok {
			return rest_errors.InvalidOTP
		}
	}

	return nil
}

func (us *userService) ResetPassword(req *types.ResetPasswordReq) error {
	hashedPass, _ := bcrypt.GenerateFromPassword([]byte(req.Password), 8)
	data := map[string]interface{}{
		"password": hashedPass,
	}
	if err := us.userRepository.UpdateByInterface(req.ID, data); err != nil {
		log.Error(err)
		return rest_errors.ErrResettingUserPassword
	}

	return nil
}

func (us *userService) ResendForgotPasswordOtp(nonce string) (*types.ForgotPasswordOtpResp, error) {
	redisConf := config.Redis()
	nonceKey := redisConf.OtpNoncePrefix + consts.UserForgotPasswordOtp + nonce

	userId, err := us.cacheService.GetInt(nonceKey)
	if err != nil {
		log.Error(err)
		return nil, rest_errors.InvalidOTPNonce
	}

	otpKey := redisConf.OtpPrefix + consts.UserForgotPasswordOtp + strconv.Itoa(userId)

	// getting user detail using userid
	userDetail, err := us.GetUserFromCache(userId, true)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	// delete current otp and nonce key
	_ = us.cacheService.Del(nonceKey, otpKey)

	resp, err := us.CreateForgotPasswordOtp(userId, userDetail.Email)
	if err != nil {
		log.Error(err)
		return nil, rest_errors.ErrResendingForgotPasswordOTP
	}

	return resp, nil
}

func (us *userService) CreateForgotPasswordOtp(userId int, email string) (*types.ForgotPasswordOtpResp, error) {
	redisConf := config.Redis()
	otpKey := redisConf.OtpPrefix + consts.UserForgotPasswordOtp + strconv.Itoa(userId)

	nonce := uuid.New().String()

	otp, err := methods.GenerateOTP(6)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	// NOTE: "nonce" key will be deleted upon otp verification or resend otp
	if err := us.cacheService.Set(redisConf.OtpNoncePrefix+consts.UserForgotPasswordOtp+nonce, userId, redisConf.OtpNonceTtl); err != nil {
		log.Error(err)
		return nil, err
	}

	// NOTE: "otp" key will be deleted upon otp verification
	if err := us.cacheService.Set(otpKey, otp, redisConf.OtpTtl); err != nil {
		log.Error(err)
		return nil, err
	}

	return &types.ForgotPasswordOtpResp{OtpNonce: nonce}, nil
}

func (us *userService) VerifyForgotPasswordOtp(data *types.ForgotPasswordOtpReq) (bool, error) {
	redisConf := config.Redis()

	nonceKey := redisConf.OtpNoncePrefix + consts.UserForgotPasswordOtp + data.Nonce
	userId, err := us.cacheService.GetInt(nonceKey)
	if err != nil {
		log.Error(err)
		return false, rest_errors.InvalidOTPNonce
	}

	otpKey := redisConf.OtpPrefix + consts.UserForgotPasswordOtp + strconv.Itoa(userId)
	otp, err := us.cacheService.Get(otpKey)
	if err != nil || otp != data.Otp {
		log.Error(err)
		return false, rest_errors.InvalidOTPNonce
	}

	if err = us.cacheService.Del(nonceKey, otpKey); err != nil {
		log.Error(err)
	}

	return true, nil
}

// private

func (us *userService) update(user *models.User) (*types.UserResp, error) {
	if err := us.userRepository.Update(user); err != nil {
		log.Error(err)
		return nil, err
	}
	return us.UpdateUserCache(user.ID)
}

func encryptPassword(plainPass string) string {
	hashedPass, _ := bcrypt.GenerateFromPassword([]byte(plainPass), 8)
	return string(hashedPass)
}

func passwordResetSecret(user *models.User) string {
	return *user.Password + strconv.Itoa(int(user.CreatedAt.Unix()))
}
