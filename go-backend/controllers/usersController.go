package controllers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go-backend/models"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func Login(c *gin.Context) {
	var body struct {
		Email    string
		Password string
	}

	if err := c.Bind(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read body"})
		return
	}

	users := []models.User{}
	data, err := os.ReadFile("users.json")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read users file"})
		return
	}
	if err := json.Unmarshal(data, &users); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse users data"})
		return
	}

	var foundUser *models.User
	for _, user := range users {
		if user.Email == body.Email {
			foundUser = &user
			break
		}
	}

	if foundUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	if foundUser.Password != body.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": foundUser.ID,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	fmt.Println("Secret:", os.Getenv("SECRET"))

	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("token", tokenString, 3600*24*30, "/", "localhost", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
}

func Logout(c *gin.Context) {
	c.SetCookie("token", "", -1, "/", "localhost", false, true)

	c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
}

func Validate(c *gin.Context) {
	user, _ := c.Get("user")
	c.JSON(http.StatusOK, gin.H{"message": "I'm logged in", "user": user})
}

// passkeys
var (
	// tenantID = os.Getenv("PASSKEY_TENANT_ID")
	tenantID = "03915657-8161-4f7a-8170-70df0e370114"
	// apiKey = os.Getenv("PASSKEY_API_KEY")
	apiKey  = "xYyhiHZ8s9WbTH9ZZBSPgwgyr2TF-apKNoOdbZERspivln0tZTCDeMJTJ_Yfw9yx1WTUS7qUQfviizwpHFV2Kw=="
	baseURL = fmt.Sprintf("https://passkeys.hanko.io/%s", tenantID)
	headers = map[string]string{
		"apikey":       apiKey,
		"Content-Type": "application/json",
	}
)

func StartRegistration(c *gin.Context) {
	fmt.Println("registering passkey")
	userInterface, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User must be logged in to register a passkey"})
		return
	}

	fmt.Printf("Type of userInterface: %T\n", userInterface)

	user, ok := userInterface.(*models.User)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user data"})
		return
	}
	userID := user.ID
	userEmail := user.Email

	payload := map[string]string{
		"user_id":  userID,
		"username": userEmail,
	}

	payloadBytes, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", baseURL+"/registration/initialize", bytes.NewBuffer(payloadBytes))
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send request"})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var creationOptions map[string]interface{}
	json.Unmarshal(body, &creationOptions)

	c.JSON(http.StatusOK, creationOptions)
}

func FinalizeRegistration(c *gin.Context) {
	var data map[string]interface{}
	if err := c.BindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
		return
	}

	dataBytes, _ := json.Marshal(data)
	req, _ := http.NewRequest("POST", baseURL+"/registration/finalize", bytes.NewBuffer(dataBytes))
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send request"})
		return
	}
	defer resp.Body.Close()

	responseData, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(responseData, &result)

	c.JSON(http.StatusOK, gin.H{"message": "Passkey registered successfully"})
}

func StartLogin(c *gin.Context) {
	req, _ := http.NewRequest("POST", baseURL+"/login/initialize", nil)
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send request"})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var loginOptions map[string]interface{}
	json.Unmarshal(body, &loginOptions)

	c.JSON(http.StatusOK, loginOptions)
}

func FinalizeLogin(c *gin.Context) {
	var clientData map[string]interface{}
	if err := c.BindJSON(&clientData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
		return
	}

	dataBytes, _ := json.Marshal(clientData)
	req, _ := http.NewRequest("POST", baseURL+"/login/finalize", bytes.NewBuffer(dataBytes))
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send request"})
		return
	}
	defer resp.Body.Close()

	responseData, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(responseData, &result)

	token, _ := result["token"].(string)
	decodedPayload, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse token"})
		return
	}
	claims := decodedPayload.Claims.(jwt.MapClaims)
	userID := claims["sub"].(string)

	// Load users data
	var users []models.User
	data, err := os.ReadFile("users.json")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read users file"})
		return
	}
	if err := json.Unmarshal(data, &users); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse users data"})
		return
	}

	var foundUser *models.User
	for _, user := range users {
		if user.ID == userID {
			foundUser = &user
			break
		}
	}

	if foundUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": foundUser.ID,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	tokenString, err := newToken.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("token", tokenString, 3600*24*30, "/", "localhost", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
}
