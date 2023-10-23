package main

import (
	"Auth-Server/controllers"
	"Auth-Server/middleware"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"golang.org/x/net/context"
	"log"
)

var ctx context.Context
var err error
var client *mongo.Client
var MongoUri string = "mongodb://tanveeshs:pass123@localhost:27017/auth-server?authSource=admin"
var userController *controllers.UserController
var middleware1 *middleware.Middleware

func init() {
	log.Println()
	ctx = context.Background()
	client, err = mongo.Connect(ctx,
		options.Client().ApplyURI(MongoUri))
	if err = client.Ping(context.TODO(),
		readpref.Primary()); err != nil {
		log.Fatal(err)
	}
	log.Println("Connected to MongoDB")
	collection := client.Database("auth-server").Collection("users")
	redisClient := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0})
	status := redisClient.Ping(ctx)
	fmt.Println(status)
	userController = controllers.NewUserController(collection,
		ctx, redisClient)
	middleware1 = middleware.NewMiddleware(ctx, redisClient)
}

func main() {
	app := fiber.New()
	app.Use(logger.New())
	app.Post("/signup", userController.CreateUser)
	app.Post("/login", userController.Login)
	app.Post("/addPermission", userController.AddPermission)
	app.Post("/adminTestRoute", middleware1.AdminMiddlewareHandler, userController.TestRoute)
	err := app.Listen(":3000")
	if err != nil {
		log.Fatal("Error in running the server")
		return
	}
	log.Println("Server is running")
}
