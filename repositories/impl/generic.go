package impl

import (
	"fmt"

	"auth/consts"
	"auth/models"
	"auth/rest_errors"
	"auth/types"
	"auth/utils/log"
	"auth/utils/paginations"

	"gorm.io/gorm"
)

var dbClient *gorm.DB

type repository struct{}

var GenericRepository *repository

func InitGenericRepository(client *gorm.DB) {
	dbClient = client
}

func (r *repository) Create(user *models.User) error {
	if err := dbClient.Create(&user).Error; err != nil {
		log.Error(err)
		return rest_errors.ErrCreatingUser
	}
	return nil
}

func (r *repository) Update(user *models.User) error {
	res := dbClient.Model(&models.User{}).
		Where("id = ?", user.ID).
		Omit("email", "password", "login_provider").
		Updates(&user)
	if res.Error != nil {
		log.Error(res.Error)
		return rest_errors.ErrUpdatingUser
	}

	return nil
}

func (r *repository) FindBy(field string, value interface{}) (*models.User, error) {
	user := models.User{}
	query := fmt.Sprintf("%s = ?", field)
	if err := dbClient.Where(query, value).First(&user).Error; err != nil {
		log.Error(err)
		return nil, rest_errors.UserNotFound
	}
	return &user, nil
}

func (r *repository) All(pagination *types.Pagination) ([]*models.User, error) {
	users := make([]*models.User, 0)
	tableName := consts.Users
	paginationQuery := paginations.GenerateFilteringCondition(dbClient, tableName, pagination, false)
	res := paginationQuery.Find(&users)

	if res.Error != nil {
		log.Error(res.Error)
		return users, rest_errors.ErrFetchingUsers
	}

	CountQuery := paginations.GenerateFilteringCondition(dbClient, tableName, pagination, true)
	totalRows, err := r.Count(CountQuery)
	if err != nil {
		log.Error(err)
		return users, err
	}
	pagination.TotalRows = totalRows
	totalPages := paginations.CalculateTotalPageAndRows(pagination, totalRows)
	pagination.TotalPages = totalPages
	return users, nil
}

func (r *repository) Count(paginationQuery *gorm.DB) (int64, error) {
	var count int64 = 0
	if err := paginationQuery.Model(&models.User{}).Count(&count).Error; err != nil {
		log.Error(err)
		return 0, rest_errors.ErrCountingUsers
	}
	return count, nil
}

func (r *repository) UpdateByInterface(id int, data map[string]interface{}) error {
	if err := dbClient.Model(&models.User{}).Where("id = ?", id).Updates(data).Error; err != nil {
		log.Error(err)
		return err
	}
	return nil
}

func (r *repository) Delete(id int) error {
	res := dbClient.Where("id = ?", id).Delete(&models.User{})
	if res.RowsAffected == 0 {
		return rest_errors.UserNotFound
	}
	if res.Error != nil {
		log.Error(res.Error)
		return rest_errors.ErrDeletingUser
	}
	return nil
}
