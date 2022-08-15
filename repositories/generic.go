package repositories

import (
	"auth/models"
	"auth/types"
	"gorm.io/gorm"
)

type IRepository interface {
	New(userData interface{}) (*models.User, error)
	Create(user *models.User) error
	Update(user *models.User) error
	FindBy(field string, value interface{}) (*models.User, error)
	All(pagination *types.Pagination) ([]*models.User, error)
	Count(paginationQuery *gorm.DB) (int64, error)
	UpdateByInterface(id int, data map[string]interface{}) error
	Delete(id int) error
}
