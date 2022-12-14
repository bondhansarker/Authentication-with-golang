package config

import (
	"encoding/json"
	"fmt"
	"time"

	"auth/utils/log"

	"github.com/spf13/viper"
	_ "github.com/spf13/viper/remote"
)

type AppConfig struct {
	Name           string
	Port           string
	Page           int64
	Limit          int64
	Sort           string
	MockOtpEnabled bool
	MockOtp        string
	GoogleApiKey   string
	AppKey         string
}

type DbConfig struct {
	Host            string
	Port            string
	User            string
	Pass            string
	Schema          string
	MaxIdleConn     int
	MaxOpenConn     int
	MaxConnLifetime time.Duration
	Debug           bool
}

type JwtConfig struct {
	AccessTokenSecret  string
	RefreshTokenSecret string
	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration
	ContextKey         string
}

type RedisConfig struct {
	Host              string
	Port              string
	Pass              string
	Db                int
	AccessUuidPrefix  string
	RefreshUuidPrefix string
	UserPrefix        string
	OtpPrefix         string
	OtpNoncePrefix    string
	UserTtl           time.Duration
	OtpTtl            time.Duration
	OtpNonceTtl       time.Duration
}

type MailgunConfig struct {
	ApiKey string
	Domain string
}

type MailConfig struct {
	ServiceURL string
	Timeout    time.Duration
}

type AppleLoginConfig struct {
	AppBundleID           string
	ApplePublicKeyUrl     string
	ApplePublicKeyTimeout time.Duration
	AppleIdUrl            string
}

type Config struct {
	App        *AppConfig
	Db         *DbConfig
	Jwt        *JwtConfig
	Redis      *RedisConfig
	Mail       *MailConfig
	AppleLogin *AppleLoginConfig
}

var config *Config

func AllConfig() *Config {
	return config
}

func App() *AppConfig {
	return config.App
}

func Db() *DbConfig {
	return config.Db
}

func Jwt() *JwtConfig {
	return config.Jwt
}

func Redis() *RedisConfig {
	return config.Redis
}

func Mail() *MailConfig {
	return config.Mail
}

func AppleLogin() *AppleLoginConfig {
	return config.AppleLogin
}

func Load() {
	config = loadDefault()
	_ = viper.BindEnv("CONSUL_URL")
	_ = viper.BindEnv("CONSUL_PATH")

	consulURL := viper.GetString("CONSUL_URL")
	consulPath := viper.GetString("CONSUL_PATH")

	if consulURL != "" && consulPath != "" {
		_ = viper.AddRemoteProvider("consul", consulURL, consulPath)

		viper.SetConfigType("json")
		err := viper.ReadRemoteConfig()

		if err != nil {
			log.Info(fmt.Sprintf("%s named \"%s\"", err.Error(), consulPath))
		}
		if err := viper.Unmarshal(&config); err != nil {
			log.Error(err)
		}

		if r, err := json.MarshalIndent(&config, "", "  "); err == nil {
			log.Info(string(r))
		}
	} else {
		log.Error("CONSUL_URL or CONSUL_PATH missing! Serving with default config...")
	}
}

func loadDefault() *Config {
	return &Config{
		App: &AppConfig{
			Name:           "auth",
			Port:           "8080",
			Page:           1,
			Limit:          10,
			Sort:           "created_at",
			MockOtpEnabled: true,
			MockOtp:        "",
			GoogleApiKey:   "419662912672-uh565e54cgnmbve60bubsi0dqbdtpnia.apps.googleusercontent.com",
			AppKey:         "395d76cd709d4a52b12ea654b5220ca34bd6c041d352bf65",
		},
		Db: &DbConfig{
			Host:            "localhost",
			Port:            "3307",
			User:            "root",
			Pass:            "r00t",
			Schema:          "auth",
			MaxIdleConn:     1,
			MaxOpenConn:     2,
			MaxConnLifetime: 30,
			Debug:           true,
		},
		Jwt: &JwtConfig{
			AccessTokenSecret:  "accesstokensecret",
			RefreshTokenSecret: "refreshtokensecret",
			AccessTokenExpiry:  3600,   // in seconds, 1 hour
			RefreshTokenExpiry: 604800, // in seconds, 7 days
			ContextKey:         "user",
		},

		Redis: &RedisConfig{
			Host:              "localhost",
			Port:              "6379",
			Pass:              "",
			Db:                1,
			AccessUuidPrefix:  "consumer_access-uuid_",
			RefreshUuidPrefix: "consumer_refresh-uuid_",
			UserPrefix:        "consumer_user_",
			OtpPrefix:         "consumer_otp_",
			OtpNoncePrefix:    "consumer_otp-nonce_",
			UserTtl:           604800, // in seconds, 1 week
			OtpTtl:            300,    // in seconds, 5 minutes
			OtpNonceTtl:       1800,   // in seconds, 30 minutes
		},
		Mail: &MailConfig{
			ServiceURL: "",
			Timeout:    3,
		},
		AppleLogin: &AppleLoginConfig{
			AppBundleID:           "com.vivasoft.hink",
			ApplePublicKeyUrl:     "https://appleid.apple.com/auth/keys",
			AppleIdUrl:            "https://appleid.apple.com",
			ApplePublicKeyTimeout: 5,
		},
	}

}
