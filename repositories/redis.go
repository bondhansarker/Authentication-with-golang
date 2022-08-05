package repositories

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/go-redis/redis"
)

type RedisRepository struct {
	client *redis.Client
}

func NewRedisRepository(client *redis.Client) *RedisRepository {
	return &RedisRepository{client: client}
}

func (rr *RedisRepository) Set(key string, value interface{}, ttl time.Duration) error {
	return rr.client.Set(key, value, ttl*time.Second).Err()
}

func (rr *RedisRepository) SetStruct(key string, value interface{}, ttl time.Duration) error {
	serializedValue, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return rr.client.Set(key, string(serializedValue), ttl*time.Second).Err()
}

func (rr *RedisRepository) Get(key string) (string, error) {
	return rr.client.Get(key).Result()
}

func (rr *RedisRepository) GetInt(key string) (int, error) {
	str, err := rr.client.Get(key).Result()
	if err != nil {
		return 0, err
	}

	return strconv.Atoi(str)
}

func (rr *RedisRepository) GetStruct(key string, outputStruct interface{}) error {
	serializedValue, err := rr.client.Get(key).Result()
	if err != nil {
		return err
	}

	if err := json.Unmarshal([]byte(serializedValue), &outputStruct); err != nil {
		return err
	}

	return nil
}

func (rr *RedisRepository) Del(keys ...string) error {
	return rr.client.Del(keys...).Err()
}

func (rr *RedisRepository) DelPattern(pattern string) error {
	iter := rr.client.Scan(0, pattern, 0).Iterator()

	for iter.Next() {
		err := rr.client.Del(iter.Val()).Err()
		if err != nil {
			return err
		}
	}

	if err := iter.Err(); err != nil {
		return err
	}

	return nil
}
