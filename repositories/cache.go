package repositories

import "time"

type ICache interface {
	Set(key string, value interface{}, ttl time.Duration) error
	SetStruct(key string, value interface{}, ttl time.Duration) error
	Get(key string) (string, error)
	GetInt(key string) (int, error)
	GetStruct(key string, outputStruct interface{}) error
	Del(keys ...string) error
	DelPattern(pattern string) error
}
