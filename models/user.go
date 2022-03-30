package models

import (
	"time"
)

type User struct {
	ID            int        `json:"id"`
	FirstName     *string    `json:"first_name" gorm:"default:Hink"`
	LastName      *string    `json:"last_name" gorm:"default:User"`
	Email         string     `json:"email"`
	Password      *string    `json:"password,omitempty"`
	Phone         string     `json:"phone"`
	ProfilePic    *string    `json:"profile_pic"`
	LoginProvider string     `json:"login_provider"`
	Verified      bool       `json:"verified"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	DeletedAt     *time.Time `json:"deleted_at"`
	LastLoginAt   *time.Time `json:"last_login_at"`
}
