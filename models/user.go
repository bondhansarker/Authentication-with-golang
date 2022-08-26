package models

import (
	"time"
)

type User struct {
	ID                  int        `json:"id"`
	Email               string     `json:"email"`
	Password            *string    `json:"password,omitempty"`
	Name                string     `json:"name"`
	UserName            string     `json:"user_name"`
	Phone               string     `json:"phone"`
	Website             string     `json:"website"`
	Bio                 string     `json:"bio"`
	Gender              string     `json:"gender"`
	ProfilePic          *string    `json:"profile_pic"`
	ProfilePicExtension *string    `json:"profile_pic_extension"`
	Verified            *bool      `json:"verified"`
	IsAdmin             *bool      `json:"is_admin"`
	LoginProvider       string     `json:"login_provider"`
	DownloadCount       int64      `json:"download_count" `
	UploadCount         int64      `json:"upload_count"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	DeletedAt           *time.Time `json:"deleted_at"`
	LastLoginAt         *time.Time `json:"last_login_at"`
}
