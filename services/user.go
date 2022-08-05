package services

import (
	"strconv"
	"strings"
	"time"

	"auth/config"
	"auth/consts"
	"auth/log"
	"auth/models"
	"auth/repositories"
	"auth/types"
	"auth/utils/errutil"
	"auth/utils/methodutil"
	"auth/utils/msgutil"
	"github.com/google/uuid"

	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
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
		config:          config.GetConfig(),
		redisRepository: redisRepository,
		userRepository:  userRepository,
	}
}

func (us *UserService) CreateUser(userData *types.UserCreateUpdateReq) error {
	// if user doesn't exist
	user, err := initializeUser(userData)
	if err != nil {
		log.Error(err.Error())
		return err
	}

	if userData.LoginProvider == consts.LoginProviderHink {
		*user.Password = encryptPassword(userData.Password)
	}

	return us.userRepository.Create(user)
}

func (us *UserService) UpdateUser(userData *types.UserCreateUpdateReq) (*types.UserResp, error) {
	user, err := initializeUser(userData)
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}

	err = us.userRepository.Update(user)
	if err != nil {
		return nil, err
	}

	userResp, err := us.refreshUserCache(user.ID)
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}

	return userResp, nil
}

func (us *UserService) UpdateProfilePic(profilePicData *types.ProfilePicUpdateReq) (*types.UserResp, error) {
	user := &models.User{}
	err := methodutil.CopyStruct(profilePicData, &user)
	if err != nil {
		return nil, err
	}

	err = us.userRepository.Update(user)
	if err != nil {
		return nil, err
	}

	userResp, err := us.refreshUserCache(user.ID)
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}

	return userResp, nil
}

func (us *UserService) UpdateUserStat(userStat *types.UserStatUpdateReq) (*types.UserResp, error) {
	user := &models.User{}
	err := methodutil.CopyStruct(userStat, &user)
	if err != nil {
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
		return nil, err
	}

	userResp, err := us.refreshUserCache(user.ID)
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}

	return userResp, nil
}

func (us *UserService) refreshUserCache(userId int) (*types.UserResp, error) {
	userResp := &types.UserResp{}
	user, err := us.GetUserById(userId)
	if err != nil {
		return nil, err
	}

	err = methodutil.CopyStruct(user, &userResp)
	if err != nil {
		return nil, err
	}

	if err := us.redisRepository.SetStruct(us.config.Redis.UserPrefix+strconv.Itoa(userResp.ID), userResp, us.config.Redis.UserTtl); err != nil {
		log.Error(err)
	}

	return userResp, nil
}

func (us *UserService) GetUserByEmail(email string) (*models.User, error) {
	user, err := us.userRepository.FindBy("email", email)
	if err != nil {
		log.Error(err.Error())
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
	if err := us.userRepository.SetMetaData(userId, data); err != nil {
		log.Error(err)
		return err
	}
	return nil
}

func (us *UserService) GetUserFromContext(c *echo.Context) (*types.LoggedInUser, error) {
	user, ok := (*c).Get("user").(*types.LoggedInUser)
	if !ok {
		return nil, errutil.ErrNoContextUser
	}

	return user, nil
}

func (us *UserService) GetUserFromHeader(c *echo.Context) (*types.LoggedInUser, error) {
	userIDString := (*c).Request().Header.Get(consts.UserIDHeader)
	userID, _ := strconv.Atoi(userIDString)
	if userID == 0 {
		return nil, errutil.ErrNoContextUser
	}
	currentUser := &types.LoggedInUser{
		ID: userID,
	}
	return currentUser, nil
}

func (us *UserService) IsAdmin(c *echo.Context) (bool, error) {
	user, err := us.GetUserFromContext(c)
	if err != nil {
		log.Error(err)
		return false, err
	}
	if user.IsAdmin == nil || *user.IsAdmin == false {
		log.Error("this is not an admin")
		return false, nil
	}
	return true, nil
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

	userResp, err = us.refreshUserCache(userId)
	if err != nil {
		log.Error(err)
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
	err = methodutil.CopyStruct(users, &usersResp)
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
		return err
	}

	currentPass := []byte(*user.Password)
	if err = bcrypt.CompareHashAndPassword(currentPass, []byte(req.OldPassword)); err != nil {
		log.Error(err)
		return errutil.ErrInvalidPassword
	}

	hashedPass, _ := bcrypt.GenerateFromPassword([]byte(req.NewPassword), 8)
	data := map[string]interface{}{
		"password": hashedPass,
	}

	if err := us.userRepository.SetMetaData(userId, data); err != nil {
		log.Error(err)
		return err
	}
	return nil
}

func (us *UserService) ForgotPassword(email string) (*types.ForgotPasswordResp, error) {
	user, err := us.GetUserByEmail(email)
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

	otpResp, err := us.createForgotPasswordOtp(user.ID, email)
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

func (us *UserService) VerifyResetPassword(req *types.VerifyResetPasswordReq) error {
	user, err := us.GetUserById(req.ID)
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
		if ok, err := us.verifyForgotPasswordOtp(otpReq); err != nil && !ok {
			return errutil.ErrInvalidOtp
		}
	}

	return nil
}

func (us *UserService) ResetPassword(req *types.ResetPasswordReq) error {
	hashedPass, _ := bcrypt.GenerateFromPassword([]byte(req.Password), 8)
	data := map[string]interface{}{
		"password": hashedPass,
	}
	if err := us.userRepository.SetMetaData(req.ID, data); err != nil {
		log.Error(err)
		return err
	}

	return nil
}

func (us *UserService) CreateUserForSocialLogin(userData *types.SocialLoginData) (*models.User, error) {
	user := models.User{}
	respErr := methodutil.CopyStruct(userData, &user)
	if respErr != nil {
		return nil, respErr
	}
	verified := true
	user.Verified = &verified
	if err := us.userRepository.Create(&user); err != nil {
		log.Error(err.Error())
		return nil, err
	}
	return &user, nil
}

func (us *UserService) ResendForgotPasswordOtp(nonce string) (*types.ForgotPasswordOtpResp, error) {
	redisConf := us.config.Redis
	nonceKey := redisConf.OtpNoncePrefix + consts.UserForgotPasswordOtp + nonce

	userId, err := us.redisRepository.GetInt(nonceKey)
	if err != nil {
		log.Error(err)
		return nil, errutil.ErrInvalidOtpNonce
	}

	otpKey := redisConf.OtpPrefix + consts.UserForgotPasswordOtp + strconv.Itoa(userId)

	// getting user detail using userid
	userDetail, err := us.GetUserResponse(userId, true)
	if err != nil {
		return nil, err
	}

	// delete current otp and nonce key
	_ = us.redisRepository.Del(nonceKey, otpKey)

	resp, err := us.createForgotPasswordOtp(userId, userDetail.Email)
	if err != nil {
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

func initializeUser(userData interface{}) (*models.User, error) {
	user := &models.User{}
	err := methodutil.CopyStruct(userData, &user)
	if err != nil {
		log.Error(err.Error())
		return nil, err
	}
	user.UserName = strings.ToLower(user.UserName)
	return user, nil
}

func (us *UserService) createForgotPasswordOtp(userId int, email string) (*types.ForgotPasswordOtpResp, error) {
	redisConf := us.config.Redis
	otpKey := redisConf.OtpPrefix + consts.UserForgotPasswordOtp + strconv.Itoa(userId)

	nonce := uuid.New().String()

	otp, err := methodutil.GenerateOTP(6)
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
		return false, errutil.ErrInvalidOtpNonce
	}

	otpKey := redisConf.OtpPrefix + consts.UserForgotPasswordOtp + strconv.Itoa(userId)
	otp, err := us.redisRepository.Get(otpKey)
	if err != nil || otp != data.Otp {
		log.Error(err)
		return false, errutil.ErrInvalidOtp
	}

	_ = us.redisRepository.Del(nonceKey, otpKey)

	return true, nil
}
