package impl

import (
	"encoding/json"
	"strconv"
	"time"

	"auth/repositories"
	"github.com/go-redis/redis"
)

type redisRepository struct {
	client *redis.Client
}

func NewRedisRepository(client *redis.Client) repositories.ICache {
	return &redisRepository{client: client}
}

func (rs *redisRepository) Set(key string, value interface{}, ttl time.Duration) error {
	return rs.client.Set(key, value, ttl*time.Second).Err()
}

func (rs *redisRepository) SetStruct(key string, value interface{}, ttl time.Duration) error {
	serializedValue, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return rs.client.Set(key, string(serializedValue), ttl*time.Second).Err()
}

func (rs *redisRepository) Get(key string) (string, error) {
	return rs.client.Get(key).Result()
}

func (rs *redisRepository) GetInt(key string) (int, error) {
	str, err := rs.client.Get(key).Result()
	if err != nil {
		return 0, err
	}

	return strconv.Atoi(str)
}

func (rs *redisRepository) GetStruct(key string, outputStruct interface{}) error {
	serializedValue, err := rs.client.Get(key).Result()
	if err != nil {
		return err
	}

	if err := json.Unmarshal([]byte(serializedValue), &outputStruct); err != nil {
		return err
	}

	return nil
}

func (rs *redisRepository) Del(keys ...string) error {
	return rs.client.Del(keys...).Err()
}

func (rs *redisRepository) DelPattern(pattern string) error {
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
