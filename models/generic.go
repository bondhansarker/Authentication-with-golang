package models

import (
	"auth/errors"
	"auth/utils/log"
	"gorm.io/gorm"
)

var dbClient *gorm.DB

type GenericModel[GenericType any] struct {
	id        interface{}
	dataType  interface{}
	modelName string
	data      GenericType
}

func InitGenericModel(client *gorm.DB) {
	dbClient = client
}

func (obj *GenericModel[GenericType]) Update() error {
	res := dbClient.Model(obj.dataType).
		Where("id = ?", obj.id).
		Omit("email", "password", "login_provider").
		Updates(&obj.data)
	if res.Error != nil {
		log.Error(res.Error)
		return errors.Update(obj.modelName)
	}
	if res.RowsAffected == 0 {
		return errors.NotFound(obj.modelName)
	}
	return nil
}

func (obj *GenericModel[GenericType]) Create() error {
	if err := dbClient.Create(&obj.data).Error; err != nil {
		log.Error(err)
		return errors.Create(obj.modelName)
	}
	return nil
}

func (obj *GenericModel[GenericType]) Delete() error {
	res := dbClient.Where("id = ?", obj.id).Delete(obj.dataType)
	if res.RowsAffected == 0 {
		return errors.NotFound(obj.modelName)
	}
	if res.Error != nil {
		log.Error(res.Error)
		return errors.Delete(obj.modelName)
	}
	return nil
}
