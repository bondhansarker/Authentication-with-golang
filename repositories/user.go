package repositories

import (
	"fmt"

	"auth/log"
	"auth/models"
	"auth/types"
	"auth/utils/errutil"
	"auth/utils/methodutil"
	"auth/utils/paginationutil"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type UserRepository struct {
	dbClient        *gorm.DB
	redisRepository *RedisRepository
}

func NewUserRepository(dbClient *gorm.DB, redisRepository *RedisRepository) *UserRepository {
	return &UserRepository{
		dbClient:        dbClient,
		redisRepository: redisRepository,
	}
}

func (ur *UserRepository) Create(user *models.User) error {
	if err := ur.dbClient.Create(&user).Error; err != nil {
		return errutil.ErrUserCreate
	}
	return nil
}

func (ur *UserRepository) Update(user *models.User) error {
	res := ur.dbClient.Model(&models.User{}).
		Where("id = ?", user.ID).
		Omit("email", "password", "login_provider").
		Updates(&user)
	if res.Error != nil {
		log.Error(res.Error.Error())
		return errutil.ErrUserUpdate
	}
	if res.RowsAffected == 0 {
		log.Error(gorm.ErrRecordNotFound.Error())
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (ur *UserRepository) FindBy(field string, value interface{}) (*models.User, error) {
	user := &models.User{}
	query := fmt.Sprintf("%s = ?", field)
	if err := ur.dbClient.Where(query, value).First(&user).Error; err != nil {
		log.Error(err.Error())
		return nil, err
	}
	return user, nil
}

func (ur *UserRepository) All(pagination *types.Pagination) ([]*models.User, error) {
	users := make([]*models.User, 0)
	tableName := "users"
	paginationQuery := paginationutil.GenerateFilteringCondition(ur.dbClient, tableName, pagination, false)
	res := paginationQuery.Find(&users)

	if res.Error == gorm.ErrRecordNotFound {
		log.Error(res.Error)
		return users, errutil.ErrRecordsNotFound
	}
	if res.Error != nil {
		log.Error(res.Error)
		return users, errutil.ErrFetchRecords
	}
	CountQuery := paginationutil.GenerateFilteringCondition(ur.dbClient, tableName, pagination, true)
	totalRows, err := ur.Count(CountQuery)
	if err != nil {
		log.Error(err)
		return users, errutil.ErrCountRecords
	}
	pagination.TotalRows = totalRows
	totalPages := paginationutil.CalculateTotalPageAndRows(pagination, totalRows)
	pagination.TotalPages = totalPages
	return users, nil
}

func (ur *UserRepository) Count(paginationQuery *gorm.DB) (int64, error) {
	var count int64 = 0
	if err := paginationQuery.Model(&models.User{}).Count(&count).Error; err != nil {
		log.Error(err.Error())
		return 0, errutil.ErrCountRecords
	}
	return count, nil
}

func (ur *UserRepository) SetMetaData(userId int, data map[string]interface{}) error {
	if err := ur.dbClient.Model(&models.User{}).Where("id = ?", userId).Updates(data).Error; err != nil {
		log.Error(err.Error())
		return err
	}
	return nil
}

func (ur *UserRepository) Delete(id int) error {
	res := ur.dbClient.Where("id = ?", id).Delete(&models.User{})
	if res.RowsAffected == 0 {
		log.Error(gorm.ErrRecordNotFound.Error())
		return gorm.ErrRecordNotFound
	}
	if res.Error != nil {
		log.Error(res.Error.Error())
		return res.Error
	}

	return nil
}

func (ur *UserRepository) ResetPassword(req *types.ResetPasswordReq) error {
	hashedPass, _ := bcrypt.GenerateFromPassword([]byte(req.Password), 8)
	err := ur.dbClient.Model(&models.User{}).
		Where("id = ?", req.ID).
		Update("password", hashedPass).
		Error

	if err != nil {
		log.Error(err.Error())
		return err
	}

	return nil
}

func (ur *UserRepository) CreateUserForSocialLogin(userData *types.SocialLoginData) (*models.User, error) {
	user := &models.User{}
	respErr := methodutil.CopyStruct(userData, &user)
	if respErr != nil {
		return nil, respErr
	}
	*user.Verified = true

	if err := ur.dbClient.Create(&user).Error; err != nil {
		log.Error(err.Error())
		return nil, err
	}
	return user, nil
}
