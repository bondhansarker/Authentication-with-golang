package connections

import (
	"auth/config"
	"auth/log"
	"github.com/go-redis/redis"
)

var redisClient *redis.Client

func NewRedisClient() *redis.Client {
	conf := config.Redis()
	log.Info("connecting to redis at ", conf.Host, ":", conf.Port, "...")

	redisClient := redis.NewClient(&redis.Options{
		Addr:     conf.Host + ":" + conf.Port,
		Password: conf.Pass,
		DB:       conf.Db,
	})

	if _, err := redisClient.Ping().Result(); err != nil {
		log.Error("failed to connect redis: ", err)
		panic(err)
	}

	log.Info("redis connection successful...")
	return redisClient
}

func Redis() *redis.Client {
	return redisClient
}
