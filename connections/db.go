package connections

import (
	"fmt"
	"time"

	"auth/config"
	"auth/log"
	"auth/models"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var (
	dB  *gorm.DB
	err error
)

func NewDbClient() *gorm.DB {
	conf := config.Db()
	logMode := logger.Silent
	if conf.Debug {
		logMode = logger.Info
	}

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true", conf.User, conf.Pass, conf.Host, conf.Port, conf.Schema)

	dB, err = gorm.Open(mysql.Open(dsn), &gorm.Config{
		PrepareStmt: true,
		Logger:      logger.Default.LogMode(logMode),
	})
	if err != nil {
		panic(err)
	}

	sqlDb, err := dB.DB()
	if err != nil {
		panic(err)
	}

	if conf.MaxIdleConn != 0 {
		sqlDb.SetMaxIdleConns(conf.MaxIdleConn)
	}
	if conf.MaxOpenConn != 0 {
		sqlDb.SetMaxOpenConns(conf.MaxOpenConn)
	}
	if conf.MaxConnLifetime != 0 {
		sqlDb.SetConnMaxLifetime(conf.MaxConnLifetime * time.Second)
	}

	dB.AutoMigrate(
		&models.User{},
	)

	log.Info("mysql connection successful...")
	return dB
}

func Db() *gorm.DB {
	return dB
}
