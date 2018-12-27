package go-mo-admin-dash-models

import (
	"time"

	"gopkg.in/mgo.v2/bson"
)

type(
	Admin struct {
		Id            bson.ObjectId `bson:"_id,omitempty"`
		FirstName     string
		LastName      string
		UserName      string
		Password      string `json:"password,omitempty"`
		HashPassword  []byte `json:"hashpassword,omitempty"`
		UserEmail     string
		Mobile        string
		AccountStatus bool
		CreatedBy     string
		CreatedOn     time.Time
		ModifedBy     string
		ModifiedOn    time.Time
	}
	AdminSession struct {
		Id           bson.ObjectId `bson:"_id,omitempty"`
		AdminId      string
		AccessHeader string
		AccessIP     string
		CreatedOn    time.Time
		ExpiredOn    time.Time
		Expired      bool
	}
)
