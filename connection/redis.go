package connection

import (
	"auth/config"
	"auth/utils/log"
	"github.com/go-redis/redis"
)

var redisClient *redis.Client

func Redis(redisConfig *config.RedisConfig) {
	log.Info("connecting to redis at ", redisConfig.Host, ":", redisConfig.Port, "...")

	redisClient = redis.NewClient(&redis.Options{
		Addr:     redisConfig.Host + ":" + redisConfig.Port,
		Password: redisConfig.Pass,
		DB:       redisConfig.Db,
	})

	if _, err := redisClient.Ping().Result(); err != nil {
		log.Error("failed to connect redis: ", err)
		panic(err.Error())
	}

	log.Info("redis connection successful...")
}

func RedisClient() *redis.Client {
	return redisClient
}
