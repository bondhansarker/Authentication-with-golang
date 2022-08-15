package impl

import (
	"auth/repositories"
	"auth/utils/methods"
	"strings"

	"auth/models"
	"auth/types"
	"auth/utils/log"
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
		log.Error(err)
		return nil, err
	}
	user.UserName = strings.ToLower(user.UserName)
	return user, nil

}

func (ur *userRepository) Create(user *models.User) error {
	return GenericRepository.Create(user)
}

func (ur *userRepository) Update(user *models.User) error {
	return GenericRepository.Update(user)
}

func (ur *userRepository) FindBy(field string, value interface{}) (*models.User, error) {
	return GenericRepository.FindBy(field, value)
}

func (ur *userRepository) All(pagination *types.Pagination) ([]*models.User, error) {
	return GenericRepository.All(pagination)
}

func (ur *userRepository) Count(paginationQuery *gorm.DB) (int64, error) {
	return GenericRepository.Count(paginationQuery)
}

func (ur *userRepository) UpdateByInterface(id int, data map[string]interface{}) error {
	return GenericRepository.UpdateByInterface(id, data)
}

func (ur *userRepository) Delete(id int) error {
	return GenericRepository.Delete(id)
}
