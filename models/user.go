package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

type User struct {
	ID          primitive.ObjectID `json:"id" bson:"_id"`
	Username    string             `json:"username" bson:"username"`
	Password    string             `json:"password" bson:"password"`
	Permissions []Permissions      `json:"permissions" bson:"permissions"`
	CreatedAt   time.Time          `json:"created_at" bson:"created_at"`
}
type Permissions struct {
	Entry     int  `json:"entry" bson:"entry"`
	AddFlag   bool `json:"add_flag" bson:"add_flag"`
	AdminFlag bool `json:"admin_flag" bson:"admin_flag"`
}
