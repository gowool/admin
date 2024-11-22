package admin

import "github.com/gomig/avatar"

func GenerateAvatar(isMale bool) string {
	a := avatar.NewPersonAvatar(isMale)
	a.RandomizeShape(avatar.Circle)
	return a.Base64()
}
