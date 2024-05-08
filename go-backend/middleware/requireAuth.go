package middleware

import (
	"encoding/json"
	"fmt"
	"go-backend/models"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// type User struct {
// 	ID       string `json:"id"`
// 	Email    string `json:"email"`
// 	Password string `json:"password"` // Note: Passwords should be securely handled
// }

// func RequireAuth(c *gin.Context) {
// 	tokenString, err := c.Cookie("token")

// 	if err != nil {
// 		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "You must be logged in to perform this action"})
// 		return
// 	}

// 	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
// 		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
// 			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
// 		}

// 		return []byte(os.Getenv("SECRET")), nil
// 	})
// 	if err != nil {
// 		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
// 		return
// 	}

// 	if claims, ok := token.Claims.(jwt.MapClaims); ok {
// 		if float64(time.Now().Unix()) > claims["exp"].(float64) {
// 			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
// 			return
// 		}
// 		c.Next()
// 	} else {
// 		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
// 		return
// 	}
// }

func RequireAuth(c *gin.Context) {
	tokenString, err := c.Cookie("token")
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "You must be logged in to perform this action"})
		return
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("SECRET")), nil
	})
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
			return
		}

		// Load users from JSON file
		var users []models.User
		data, err := os.ReadFile("users.json")
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to read users data"})
			return
		}
		if err := json.Unmarshal(data, &users); err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse users data"})
			return
		}

		// Find user by ID from token
		userID := claims["sub"].(string)
		var foundUser *models.User
		for _, user := range users {
			if user.ID == userID {
				foundUser = &user
				break
			}
		}

		if foundUser == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			return
		}

		// Store user in context if needed
		c.Set("user", foundUser)
		c.Next()
	} else {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}
}
