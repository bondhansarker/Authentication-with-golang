package models

import (
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

// func (obj *GenericModel[GenericType]) Update() error {
// 	res := dbClient.Model(obj.dataType).
// 		Where("id = ?", obj.id).
// 		Omit("email", "password", "login_provider").
// 		Updates(&obj.data)
// 	if res.Error != nil {
// 		log.Error(res.Error)
// 		return rest_errors.Update(obj.modelName)
// 	}
// 	if res.RowsAffected == 0 {
// 		return rest_errors.NotFound(obj.modelName)
// 	}
// 	return nil
// }
//
// func (obj *GenericModel[GenericType]) Create() error {
// 	if err := dbClient.Create(&obj.data).Error; err != nil {
// 		log.Error(err)
// 		return rest_errors.Create(obj.modelName)
// 	}
// 	return nil
// }
//
// func (obj *GenericModel[GenericType]) Delete() error {
// 	res := dbClient.Where("id = ?", obj.id).Delete(obj.dataType)
// 	if res.RowsAffected == 0 {
// 		return rest_errors.NotFound(obj.modelName)
// 	}
// 	if res.Error != nil {
// 		log.Error(res.Error)
// 		return rest_errors.NotFound(obj.modelName)
// 	}
// 	return nil
// }
