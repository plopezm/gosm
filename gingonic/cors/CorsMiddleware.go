package cors

import "github.com/gin-gonic/gin"
import "fmt"

// Middleware enables CORS for every request using gin-gonic
func Middleware(url string, headers string, methods string, allowCredentials bool, maxAge uint64) gin.HandlerFunc {
	return func(c *gin.Context) {
		//"http://localhost:3000"
		c.Writer.Header().Set("Access-Control-Allow-Origin", url)
		//"Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With"
		c.Writer.Header().Set("Access-Control-Allow-Headers", headers)
		//"OPTIONS, GET, POST, PUT, DELETE"
		c.Writer.Header().Set("Access-Control-Allow-Methods", methods)
		if allowCredentials {
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		//"86400"
		maxAgeStr := fmt.Sprintf("%v", maxAge)
		c.Writer.Header().Set("Access-Control-Max-Age", maxAgeStr)

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}
