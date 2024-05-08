package main

import (
	"go-backend/controllers"
	"go-backend/initializers"
	"go-backend/middleware"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVariables()
}

func main() {

	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "hx-include-credentials", "hx-target", "hx-swap", "hx-current-url", "hx-request"},
		AllowCredentials: true,
		ExposeHeaders:    []string{"Content-Length"},
	}))

	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})

	r.POST("/login", controllers.Login)
	r.POST("/logout", controllers.Logout)
	r.GET("/validate", middleware.RequireAuth, controllers.Validate)
	r.POST("/passkey/start-registration", middleware.RequireAuth, controllers.StartRegistration)
	r.POST("/passkey/finalize-registration", middleware.RequireAuth, controllers.FinalizeRegistration)
	r.POST("/passkey/start-login", controllers.StartLogin)
	r.POST("/passkey/finalize-login", controllers.FinalizeLogin)

	r.Run()
}
