package main

import (
	"go-backend/controllers"
	"go-backend/initializers"
	"go-backend/middleware"

	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVariables()
}

func main() {

	r := gin.Default()
	r.LoadHTMLGlob("templates/*")

	// r.Use(cors.New(cors.Config{
	// 	AllowOrigins:     []string{"http://localhost:5173"},
	// 	AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
	// 	AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
	// 	AllowCredentials: true,
	// 	ExposeHeaders:    []string{"Content-Length"},
	// }))

	r.GET("/ping", func(c *gin.Context) {
		c.String(200, "pong")
	})

	// r.POST("/login", controllers.Login)
	r.POST("/login-user", controllers.Login)
	r.POST("/logout", controllers.Logout)
	r.GET("/validate", middleware.RequireAuth, controllers.Validate)
	r.POST("/passkey/start-registration", middleware.RequireAuth, controllers.StartRegistration)
	r.POST("/passkey/finalize-registration", middleware.RequireAuth, controllers.FinalizeRegistration)
	r.POST("/passkey/start-login", controllers.StartLogin)
	r.POST("/passkey/finalize-login", controllers.FinalizeLogin)

	r.GET("/home", controllers.HomePage)
	r.GET("/login", controllers.LoginPage)
	r.GET("/dashboard", controllers.DashboardPage)

	r.Run()
}
