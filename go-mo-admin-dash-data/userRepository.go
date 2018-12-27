package go-mo-admin-dash-data

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
/* Admin Session collection functions START*/
func createAdminSession(adminId string, uaStr string) string {
	ds := NewDataStore()
	defer ds.Close()
	n := ds.C("AdminSession")
	obj_id := bson.NewObjectId()
	var admSess AdminSession
	admSess.Id = obj_id
	admSess.CreatedOn = time.Now()
	admSess.Expired = false
	browserStr := uaStr
	admSess.AccessHeader = browserStr
	//TODO- INVESTIGATION
	admSess.AccessIP = ""
	admSess.AdminId = adminId
	err := n.Insert(&admSess)
	if err != nil {
		return ""
	} else {
		log.Println("returning access token", obj_id.Hex())
		return obj_id.Hex()
	}
}

func getAdminSessionByToken(token string) (isValidToken bool, adminId string) {
	ds := NewDataStore()
	defer ds.Close()
	n := ds.C("AdminSession")
	var adminSessObj AdminSession
	var id = bson.ObjectIdHex(token)
	var tokenObj = bson.M{"_id": id, "expired": false}
	e := n.Find(tokenObj).One(&adminSessObj)
	if e != nil {
		isValidToken = false
		adminId = ""
		return
	} else {
		isValidToken = true
		adminId = adminSessObj.AdminId
		return
	}
}

func removeAdminSession(token string) bool {
	ds := NewDataStore()
	defer ds.Close()
	n := ds.C("AdminSession")
	var adminSessObj AdminSession
	var id = bson.ObjectIdHex(token)
	var tokenObj = bson.M{"_id": id}
	e := n.Find(tokenObj).One(&adminSessObj)
	if e != nil {
		return false
	} else {
		log.Println("validated session token")
		e = n.Update(tokenObj, bson.M{"$set": bson.M{"expired": true, "expiredon": time.Now()}})
		if e != nil {
			log.Println("error updating session token", e)
			return false
		} else {
			log.Println("updated session token")
			return true
		}
	}
}