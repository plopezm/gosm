package security

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/plopezm/gosm/gingonic/rsastore"

	jwtlib "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

//JwtRsaBearerAuthMiddleware to add JWT security to gin-gonic resources
func JwtRsaBearerAuthMiddleware(ptr gin.HandlerFunc, rsaKeystore *rsastore.RsaKeystore) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := strings.SplitN(c.GetHeader("Authorization"), " ", 2)
		if len(tokenString) != 2 || tokenString[0] != "Bearer" {
			c.String(http.StatusUnauthorized, "Bearer header required")
			return
		}

		token, err := jwtlib.Parse(tokenString[1], func(token *jwtlib.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwtlib.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return rsaKeystore.PublicKey, nil
		})

		if claims, ok := token.Claims.(jwtlib.MapClaims); ok && token.Valid {
			expires, ok := claims["exp"]
			if !ok {
				sendUnauthorized(c, errors.New("Token not valid"))
				return
			}

			if getTokenRemainingValidity(expires) == -1 {
				sendUnauthorized(c, errors.New("Token validity expired"))
				return
			}

			c.Set("claims", claims)
		} else {
			sendUnauthorized(c, err)
			return
		}
		ptr(c)
	}
}

func sendUnauthorized(c *gin.Context, err error) {
	fmt.Println(err.Error())
	c.String(http.StatusUnauthorized, "Token not valid: ", err.Error())
	return
}

func getTokenRemainingValidity(timestamp interface{}) int {
	if validity, ok := timestamp.(int64); ok {
		tm := time.Unix(validity, 0)
		remainer := tm.Sub(time.Now())
		if remainer > 0 {
			return int(remainer.Seconds())
		}
	}
	return -1
}
