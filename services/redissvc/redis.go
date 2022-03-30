package redissvc

import (
	"auth/conn"
	"encoding/json"
	"strconv"
	"time"
)

func Set(key string, value interface{}, ttl time.Duration) error {
	return conn.Redis().Set(key, value, ttl*time.Second).Err()
}

func SetStruct(key string, value interface{}, ttl time.Duration) error {
	serializedValue, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return conn.Redis().Set(key, string(serializedValue), ttl*time.Second).Err()
}

func Get(key string) (string, error) {
	return conn.Redis().Get(key).Result()
}

func GetInt(key string) (int, error) {
	str, err := conn.Redis().Get(key).Result()
	if err != nil {
		return 0, err
	}

	return strconv.Atoi(str)
}

func GetStruct(key string, outputStruct interface{}) error {
	serializedValue, err := conn.Redis().Get(key).Result()
	if err != nil {
		return err
	}

	if err := json.Unmarshal([]byte(serializedValue), &outputStruct); err != nil {
		return err
	}

	return nil
}

func Del(keys ...string) error {
	return conn.Redis().Del(keys...).Err()
}

func DelPattern(pattern string) error {
	iter := conn.Redis().Scan(0, pattern, 0).Iterator()

	for iter.Next() {
		err := conn.Redis().Del(iter.Val()).Err()
		if err != nil {
			return err
		}
	}

	if err := iter.Err(); err != nil {
		return err
	}

	return nil
}
