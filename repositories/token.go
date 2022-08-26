package repositories

import "auth/types"

type IToken interface {
	DeleteTokenUuid(uuid ...string) error
	StoreTokenUuid(userId int, token *types.JwtToken) error
	CreateToken(userId int) (*types.JwtToken, error)
}
