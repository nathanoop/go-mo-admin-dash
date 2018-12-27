package go-mo-admin-dash-common

import (
	"html/template"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)


func GetSession() *mgo.Session {
	if session == nil {
		var err error
		session, err = mgo.DialWithInfo(&mgo.DialInfo{
			Addrs:    []string{AppConfig.MongoDBHost},
			Username: AppConfig.DBUser,
			Password: AppConfig.DBPwd,
			Timeout:  60 * time.Second,
		})
		if err != nil {
			log.Fatalf("[GetSession]: %s\n", err)
		}
	}
	return session
}
func createDbSession() {
	var err error
	session, err = mgo.DialWithInfo(&mgo.DialInfo{
		Addrs:    []string{AppConfig.MongoDBHost},
		Username: AppConfig.DBUser,
		Password: AppConfig.DBPwd,
		Timeout:  60 * time.Second,
	})
	if err != nil {
		log.Fatalf("[createDbSession]: %s\n", err)
	}
}
// Add indexes into MongoDB
func addIndexes() {
	var err error
adminIndex := mgo.Index{
		Key:        []string{"username"},
		Unique:     false,
		Background: true,
		Sparse:     true,
	}
	// Add indexes into MongoDB
	session := GetSession().Copy()
	defer session.Close()
  adminCol := session.DB(AppConfig.Database).C("Admin")

	err = adminCol.EnsureIndex(adminIndex)
	if err != nil {
		log.Fatalf("[addIndexes]: %s\n", err)
	}
}