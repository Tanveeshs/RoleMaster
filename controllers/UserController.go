package controllers

import (
	"Auth-Server/models"
	"Auth-Server/utils"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"log"
	"time"
)

var SecretKey = []byte("SecretKey")

type UserController struct {
	collection  *mongo.Collection
	ctx         context.Context
	redisClient *redis.Client
}

func NewUserController(collection *mongo.Collection, ctx context.Context, redisClient *redis.Client) *UserController {
	return &UserController{
		collection:  collection,
		ctx:         ctx,
		redisClient: redisClient,
	}
}

type Signup struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type AddPermission struct {
	Username   string             `json:"username"`
	Permission models.Permissions `json:"permission"`
}
type LoginResp struct {
	hash string
}

func (uc *UserController) CreateUser(c *fiber.Ctx) error {
	signupReq := new(Signup)
	if err := c.BodyParser(signupReq); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Bad Request")
	}
	hashedPassword, err := utils.HashPassword(signupReq.Password)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Server Error")
	}
	user := new(models.User)
	user.ID = primitive.NewObjectID()
	user.CreatedAt = time.Now()
	user.Username = signupReq.Username
	user.Password = hashedPassword
	user.Permissions = make([]models.Permissions, 0)
	savedUser, err := uc.collection.InsertOne(uc.ctx, user)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Unable to save user")
	}
	log.Println("User Created", savedUser)
	return c.JSON(fiber.Map{"message": "Success"})
}
func (uc *UserController) AddPermission(c *fiber.Ctx) error {
	addPermissionReq := new(AddPermission)
	if err := c.BodyParser(addPermissionReq); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Bad Request")
	}
	user := new(models.User)
	err := uc.collection.FindOne(uc.ctx, bson.D{{"username", addPermissionReq.Username}}).Decode(&user)
	if err != nil {
		return err
	}
	log.Println("User Received", user)
	for _, v := range user.Permissions {
		if v.Entry == addPermissionReq.Permission.Entry {
			return fiber.NewError(fiber.StatusBadRequest, "Permission already exists")
		}
	}
	uc.collection.FindOneAndUpdate(uc.ctx, bson.D{{"username", addPermissionReq.Username}}, bson.M{"$push": bson.M{"permissions": addPermissionReq.Permission}})
	return c.JSON(fiber.Map{"message": "Success"})
}

func (uc *UserController) Login(c *fiber.Ctx) error {
	signupReq := new(Signup)
	if err := c.BodyParser(signupReq); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Bad Request")
	}
	user := new(models.User)
	err := uc.collection.FindOne(uc.ctx, bson.D{{"username", signupReq.Username}}).Decode(&user)
	if err != nil {
		return err
	}
	err = utils.VerifyPassword(signupReq.Password, user.Password)
	if err != nil {
		return fiber.NewError(fiber.StatusUnauthorized, "Unauthorized")
	}
	objStr := fmt.Sprintf("%+v", user.Permissions)
	data := []byte(objStr)
	hasher := sha256.New()
	_, err = hasher.Write(data)
	if err != nil {
		log.Fatal("Error:", err)
		return err
	}
	hash := hasher.Sum(nil)
	hashString := hex.EncodeToString(hash)
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["hash"] = hashString
	claims["exp"] = time.Now().Add(time.Hour * 1).Unix()

	permissionsJSON, err := json.Marshal(user.Permissions)
	result, err := uc.redisClient.SetNX(uc.ctx, hashString, permissionsJSON, 0).Result()
	log.Println("ERR", err)
	log.Println("Result from redis", result)
	tokenString, err := token.SignedString(SecretKey)
	if err != nil {
		log.Fatal("Error signing token:", err)
		return err
	}
	log.Println("JWT Token:", tokenString)
	return c.JSON(fiber.Map{"token": tokenString})
}
func (uc *UserController) TestRoute(c *fiber.Ctx) error {
	return c.SendString("Admin Test Route")
}
