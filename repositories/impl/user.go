package impl

import (
	"fmt"
	"strings"

	"auth/consts"
	"auth/models"
	"auth/repositories"
	"auth/rest_errors"
	"auth/types"
	"auth/utils/methods"
	"auth/utils/paginations"
	"gorm.io/gorm"
)

type userRepository struct {
	dbClient *gorm.DB
}

func NewUserRepository(dbClient *gorm.DB) repositories.IUserRepository {
	return &userRepository{
		dbClient: dbClient,
	}
}

func (ur *userRepository) New(userData interface{}) (*models.User, error) {
	user := &models.User{}
	err := methods.CopyStruct(userData, &user)
	if err != nil {
		return nil, err
	}
	user.UserName = strings.ToLower(user.UserName)
	return user, nil

}

func (ur *userRepository) Create(user *models.User) error {
	if err := ur.dbClient.Create(&user).Error; err != nil {
		return rest_errors.ErrCreatingUser
	}
	return nil
}

func (ur *userRepository) Update(user *models.User) error {
	res := ur.dbClient.Model(&models.User{}).
		Where("id = ?", user.ID).
		Omit("email", "password", "login_provider").
		Updates(&user)
	if res.Error != nil {
		return rest_errors.ErrUpdatingUser
	}
	if res.RowsAffected == 0 {
		return rest_errors.UserNotFound
	}
	return nil
}

func (ur *userRepository) FindBy(field string, value interface{}) (*models.User, error) {
	user := models.User{}
	query := fmt.Sprintf("%s = ?", field)
	if err := ur.dbClient.Where(query, value).First(&user).Error; err != nil {
		return nil, rest_errors.UserNotFound
	}
	return &user, nil
}

func (ur *userRepository) All(pagination *types.Pagination) ([]*models.User, error) {
	users := make([]*models.User, 0)
	tableName := consts.Users
	paginationQuery := paginations.GenerateFilteringCondition(ur.dbClient, tableName, pagination, false)
	res := paginationQuery.Find(&users)

	if res.Error != nil {
		return users, rest_errors.ErrFetchingUsers
	}

	CountQuery := paginations.GenerateFilteringCondition(ur.dbClient, tableName, pagination, true)
	totalRows, err := ur.Count(CountQuery)
	if err != nil {
		return users, err
	}
	pagination.TotalRows = totalRows
	totalPages := paginations.CalculateTotalPageAndRows(pagination, totalRows)
	pagination.TotalPages = totalPages
	return users, nil
}

func (ur *userRepository) Count(paginationQuery *gorm.DB) (int64, error) {
	var count int64 = 0
	if err := paginationQuery.Model(&models.User{}).Count(&count).Error; err != nil {
		return 0, rest_errors.ErrCountingUsers
	}
	return count, nil
}

func (ur *userRepository) UpdateByInterface(id int, data map[string]interface{}) error {
	if err := ur.dbClient.Model(&models.User{}).Where("id = ?", id).Updates(data).Error; err != nil {
		return err
	}
	return nil
}

func (ur *userRepository) Delete(id int) error {
	res := ur.dbClient.Where("id = ?", id).Delete(&models.User{})
	if res.Error != nil {
		return rest_errors.ErrDeletingUser
	}
	if res.RowsAffected == 0 {
		return rest_errors.UserNotFound
	}
	return nil
}
