package repositories

import (
	"auth/consts"
	errors2 "auth/errors"
	"fmt"

	"auth/models"
	"auth/types"
	"auth/utils/log"
	"auth/utils/paginations"

	"gorm.io/gorm"
)

type UserRepository struct {
	dbClient *gorm.DB
}

func NewUserRepository(dbClient *gorm.DB) *UserRepository {
	return &UserRepository{
		dbClient: dbClient,
	}
}

func (ur *UserRepository) Create(user *models.User) error {
	if err := ur.dbClient.Create(&user).Error; err != nil {
		log.Error(err)
		return errors2.Create(consts.User)
	}
	return nil
}

func (ur *UserRepository) Update(user *models.User) error {
	res := ur.dbClient.Model(&models.User{}).
		Where("id = ?", user.ID).
		Omit("email", "password", "login_provider").
		Updates(&user)
	if res.Error != nil {
		log.Error(res.Error)
		return errors2.Update(consts.User)
	}
	if res.RowsAffected == 0 {
		return errors2.NotFound(consts.User)
	}
	return nil
}

func (ur *UserRepository) FindBy(field string, value interface{}) (*models.User, error) {
	user := models.User{}
	query := fmt.Sprintf("%s = ?", field)
	if err := ur.dbClient.Where(query, value).First(&user).Error; err != nil {
		log.Error(err)
		return nil, errors2.NotFound(consts.User)
	}
	return &user, nil
}

func (ur *UserRepository) All(pagination *types.Pagination) ([]*models.User, error) {
	users := make([]*models.User, 0)
	tableName := consts.Users
	paginationQuery := paginations.GenerateFilteringCondition(ur.dbClient, tableName, pagination, false)
	res := paginationQuery.Find(&users)

	if res.Error != nil {
		log.Error(res.Error)
		return users, errors2.Fetch(tableName)
	}

	CountQuery := paginations.GenerateFilteringCondition(ur.dbClient, tableName, pagination, true)
	totalRows, err := ur.Count(CountQuery)
	if err != nil {
		log.Error(err)
		return users, err
	}
	pagination.TotalRows = totalRows
	totalPages := paginations.CalculateTotalPageAndRows(pagination, totalRows)
	pagination.TotalPages = totalPages
	return users, nil
}

func (ur *UserRepository) Count(paginationQuery *gorm.DB) (int64, error) {
	var count int64 = 0
	if err := paginationQuery.Model(&models.User{}).Count(&count).Error; err != nil {
		log.Error(err)
		return 0, errors2.Count(consts.Users)
	}
	return count, nil
}

func (ur *UserRepository) UpdateByInterface(id int, data map[string]interface{}) error {
	if err := ur.dbClient.Model(&models.User{}).Where("id = ?", id).Updates(data).Error; err != nil {
		log.Error(err)
		return err
	}
	return nil
}

func (ur *UserRepository) Delete(id int) error {
	res := ur.dbClient.Where("id = ?", id).Delete(&models.User{})
	if res.RowsAffected == 0 {
		return errors2.NotFound(consts.User)
	}
	if res.Error != nil {
		log.Error(res.Error)
		return errors2.Delete(consts.User)
	}
	return nil
}
