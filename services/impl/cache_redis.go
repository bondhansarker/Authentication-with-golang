package serviceImpl

import (
	"auth/services"
	"encoding/json"
	"strconv"
	"time"

	"github.com/go-redis/redis"
)

type redisService struct {
	client *redis.Client
}

func NewRedisService(client *redis.Client) services.ICache {
	return &redisService{client: client}
}

func (rs *redisService) Set(key string, value interface{}, ttl time.Duration) error {
	return rs.client.Set(key, value, ttl*time.Second).Err()
}

func (rs *redisService) SetStruct(key string, value interface{}, ttl time.Duration) error {
	serializedValue, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return rs.client.Set(key, string(serializedValue), ttl*time.Second).Err()
}

func (rs *redisService) Get(key string) (string, error) {
	return rs.client.Get(key).Result()
}

func (rs *redisService) GetInt(key string) (int, error) {
	str, err := rs.client.Get(key).Result()
	if err != nil {
		return 0, err
	}

	return strconv.Atoi(str)
}

func (rs *redisService) GetStruct(key string, outputStruct interface{}) error {
	serializedValue, err := rs.client.Get(key).Result()
	if err != nil {
		return err
	}

	if err := json.Unmarshal([]byte(serializedValue), &outputStruct); err != nil {
		return err
	}

	return nil
}

func (rs *redisService) Del(keys ...string) error {
	return rs.client.Del(keys...).Err()
}

func (rs *redisService) DelPattern(pattern string) error {
	iter := rs.client.Scan(0, pattern, 0).Iterator()

	for iter.Next() {
		err := rs.client.Del(iter.Val()).Err()
		if err != nil {
			return err
		}
	}

	if err := iter.Err(); err != nil {
		return err
	}

	return nil
}
