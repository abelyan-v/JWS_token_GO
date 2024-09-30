package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type User struct {
	ID       uint `gorm:"primaryKey"`
	Name     string
	Password string
}

var jwtSecret = []byte("jqRBRwHNnO9NlKN4HXzjT52ZX17lQoa0")

type Claims struct {
	Username string `json:"username"`
	UserID   string `json:"user_id"`
	jwt.RegisteredClaims
}

func main() {
	dsn := "host=localhost user=postgres password=postgres dbname=users port=5432 sslmode=disable TimeZone=Europe/Moscow"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Ошибка подключения к базе данных:", err)
	}
	err = db.AutoMigrate(&User{})
	if err != nil {
		log.Fatal("Ошибка миграции базы данных:", err)
	}

	router := gin.Default()

	store := cookie.NewStore([]byte("secret"))
	router.Use(sessions.Sessions("mysession", store))

	router.GET("/", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set("key", "value")
		session.Save()
	})

	router.GET("/authorisation", func(c *gin.Context) {
		var user User
		result := db.Where("name = ? AND password = ?", "camelmilksagittarius", "t7AJjnbNp4XEG3xSHKDLhw").First(&user)
		if result.RowsAffected == 1 {
			accessToken, _ := CreateJWT(fmt.Sprint(user.ID), user.Name)
			refreshToken, _ := CreateRefreshToken(fmt.Sprint(user.ID), user.Name)

			c.JSON(http.StatusOK, gin.H{
				"message":       "Успешная авторизация",
				"access_token":  accessToken,
				"refresh_token": refreshToken,
			})
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "Пользователь не существует",
			})
		}
	})

	router.GET("/refresh_token", func(c *gin.Context) {
		accessToken := c.Query("access_token")

		if !VerifyJWT(accessToken) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "Невалидный access токен",
			})
			return
		}

		token, _ := jwt.ParseWithClaims(accessToken, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		claims, ok := token.Claims.(*Claims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "Невозможно получить claims",
			})
			return
		}

		refreshToken, err := CreateRefreshToken(claims.UserID, claims.Username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": "Ошибка при создании refresh токена",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"refresh_token": refreshToken,
		})
	})

	router.Run(":8080")
}

func CreateJWT(userID string, username string) (string, error) {
	expirationTime := time.Now().UTC().Add(1 * time.Minute)

	claims := &Claims{
		Username: username,
		UserID:   userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			Issuer:    "myApp",
			Subject:   userID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func CreateRefreshToken(userID string, username string) (string, error) {
	expirationTime := time.Now().UTC().Add(7 * 24 * time.Hour)

	claims := &Claims{
		Username: username,
		UserID:   userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			Issuer:    "myApp",
			Subject:   userID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func VerifyJWT(tokenString string) bool {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("неправильный метод подписи: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil {
		return false
	}

	if _, ok := token.Claims.(*Claims); ok && token.Valid {
		return true
	} else {
		return false
	}
}
