// main.go
package main

import (
	"errors"
	"log"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var jwtSecret = []byte("supersecretkey")
var db *gorm.DB

// ================== MODELS ==================

type User struct {
	ID          string `gorm:"primaryKey"`
	FirstName   string
	LastName    string
	PhoneNumber string `gorm:"unique"`
	Address     string
	Pin         string
	Balance     int64
	CreatedAt   time.Time
}

type Transfer struct {
	ID         string `gorm:"primaryKey"`
	FromUserID string
	ToUserID   string
	Amount     int64
	Remarks    string
	Status     string
	CreatedAt  time.Time
}

type Transaction struct {
	ID            string `gorm:"primaryKey"`
	UserID        string
	Type          string
	Amount        int64
	Remarks       string
	BalanceBefore int64
	BalanceAfter  int64
	CreatedAt     time.Time
}

// ================== MAIN ==================

func main() {
	database, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	db = database
	db.AutoMigrate(&User{}, &Transfer{}, &Transaction{})

	r := gin.Default()

	r.POST("/register", Register)
	r.POST("/login", Login)

	auth := r.Group("/")
	auth.Use(AuthMiddleware())
	{
		auth.POST("/topup", TopUp)
		auth.POST("/pay", Payment)
		auth.POST("/transfer", TransferHandler)
		auth.GET("/transactions", GetTransactions)
	}

	log.Println("Server running on :8080")
	r.Run(":8080")
}

// ================== JWT ==================

func GenerateToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func ParseToken(tokenStr string) (string, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		return "", errors.New("invalid token")
	}

	claims := token.Claims.(jwt.MapClaims)
	return claims["user_id"].(string), nil
}

// ================== MIDDLEWARE ==================

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if auth == "" {
			c.JSON(401, gin.H{"message": "Unauthenticated"})
			c.Abort()
			return
		}

		tokenStr := strings.TrimPrefix(auth, "Bearer ")
		userID, err := ParseToken(tokenStr)
		if err != nil {
			c.JSON(401, gin.H{"message": "Invalid token"})
			c.Abort()
			return
		}

		c.Set("user_id", userID)
		c.Next()
	}
}

// ================== HANDLERS ==================

func Register(c *gin.Context) {
	var req struct {
		FirstName   string `json:"first_name"`
		LastName    string `json:"last_name"`
		PhoneNumber string `json:"phone_number"`
		Address     string `json:"address"`
		Pin         string `json:"pin"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"message": "invalid request"})
		return
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(req.Pin), bcrypt.DefaultCost)

	user := User{
		ID:          uuid.New().String(),
		FirstName:   req.FirstName,
		LastName:    req.LastName,
		PhoneNumber: req.PhoneNumber,
		Address:     req.Address,
		Pin:         string(hash),
		Balance:     0,
	}

	if err := db.Create(&user).Error; err != nil {
		c.JSON(400, gin.H{"message": "Phone Number already registered"})
		return
	}

	c.JSON(200, user)
}

func Login(c *gin.Context) {
	var req struct {
		PhoneNumber string `json:"phone_number"`
		Pin         string `json:"pin"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"message": "invalid request"})
		return
	}

	var user User
	if err := db.Where("phone_number = ?", req.PhoneNumber).First(&user).Error; err != nil {
		c.JSON(400, gin.H{"message": "User not found"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Pin), []byte(req.Pin)); err != nil {
		c.JSON(400, gin.H{"message": "Invalid PIN"})
		return
	}

	token, _ := GenerateToken(user.ID)
	c.JSON(200, gin.H{"access_token": token})
}

func TopUp(c *gin.Context) {
	userID := c.MustGet("user_id").(string)

	var req struct {
		Amount int64 `json:"amount"`
	}

	c.BindJSON(&req)

	db.Transaction(func(tx *gorm.DB) error {
		var user User
		tx.First(&user, "id = ?", userID)

		before := user.Balance
		user.Balance += req.Amount
		tx.Save(&user)

		tx.Create(&Transaction{
			ID:            uuid.New().String(),
			UserID:        userID,
			Type:          "CREDIT",
			Amount:        req.Amount,
			BalanceBefore: before,
			BalanceAfter:  user.Balance,
		})

		c.JSON(200, user)
		return nil
	})
}

func Payment(c *gin.Context) {
	userID := c.MustGet("user_id").(string)

	var req struct {
		Amount  int64  `json:"amount"`
		Remarks string `json:"remarks"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"message": "invalid request"})
		return
	}

	err := db.Transaction(func(tx *gorm.DB) error {
		var user User
		tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&user, "id = ?", userID)

		if user.Balance < req.Amount {
			return errors.New("Balance is not enough")
		}

		before := user.Balance
		user.Balance -= req.Amount
		tx.Save(&user)

		paymentID := uuid.New().String()

		tx.Create(&Transaction{
			ID:            paymentID,
			UserID:        userID,
			Type:          "DEBIT",
			Amount:        req.Amount,
			Remarks:       req.Remarks,
			BalanceBefore: before,
			BalanceAfter:  user.Balance,
		})

		c.JSON(200, gin.H{
			"status": "SUCCESS",
			"result": gin.H{
				"payment_id":     paymentID,
				"amount":         req.Amount,
				"remarks":        req.Remarks,
				"balance_before": before,
				"balance_after":  user.Balance,
				"created_date":   time.Now().Format("2006-01-02 15:04:05"),
			},
		})

		return nil
	})

	if err != nil {
		c.JSON(400, gin.H{"message": err.Error()})
	}
}

func TransferHandler(c *gin.Context) {
	userID := c.MustGet("user_id").(string)

	var req struct {
		ToUser  string `json:"target_user"`
		Amount  int64  `json:"amount"`
		Remarks string `json:"remarks"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"message": "invalid request"})
		return
	}

	transfer := Transfer{
		ID:         uuid.New().String(),
		FromUserID: userID,
		ToUserID:   req.ToUser,
		Amount:     req.Amount,
		Remarks:    req.Remarks,
		Status:     "PENDING",
	}

	db.Create(&transfer)
	go processTransfer(transfer.ID)

	c.JSON(200, gin.H{"status": "PENDING"})
}

func processTransfer(id string) {
	db.Transaction(func(tx *gorm.DB) error {
		var t Transfer
		tx.First(&t, "id = ?", id)

		var from, to User
		tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&from, "id = ?", t.FromUserID)
		tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&to, "id = ?", t.ToUserID)

		if from.Balance < t.Amount {
			t.Status = "FAILED"
			tx.Save(&t)
			return nil
		}

		beforeFrom := from.Balance
		beforeTo := to.Balance

		from.Balance -= t.Amount
		to.Balance += t.Amount

		tx.Save(&from)
		tx.Save(&to)

		tx.Create(&Transaction{
			ID:            uuid.New().String(),
			UserID:        from.ID,
			Type:          "DEBIT",
			Amount:        t.Amount,
			Remarks:       t.Remarks,
			BalanceBefore: beforeFrom,
			BalanceAfter:  from.Balance,
		})

		tx.Create(&Transaction{
			ID:            uuid.New().String(),
			UserID:        to.ID,
			Type:          "CREDIT",
			Amount:        t.Amount,
			Remarks:       t.Remarks,
			BalanceBefore: beforeTo,
			BalanceAfter:  to.Balance,
		})

		t.Status = "SUCCESS"
		tx.Save(&t)

		return nil
	})
}

func GetTransactions(c *gin.Context) {
	userID := c.MustGet("user_id").(string)

	var txs []Transaction
	db.Where("user_id = ?", userID).Order("created_at desc").Find(&txs)

	c.JSON(200, gin.H{
		"status": "SUCCESS",
		"result": txs,
	})
}

/*
RUN:
go mod init wallet
go mod tidy
go run main.go
*/
