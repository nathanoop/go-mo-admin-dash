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


/* Admin collection functions START*/
func getUserByUserName(userName string) (r Admin, e error) {
	ds := NewDataStore()
	defer ds.Close()
	n := ds.C("Admin")
	var userNameObj = bson.M{"username": userName}
	e = n.Find(userNameObj).One(&r)
	return
}

func getAdminUserFromId(adminId string) (r Admin, e error) {
	ds := NewDataStore()
	defer ds.Close()
	n := ds.C("Admin")
	var userNameObj = bson.M{"_id": bson.ObjectIdHex(adminId)}
	e = n.Find(userNameObj).One(&r)
	return
}

func insertAdminUser(firstname string, lastname string, username string, password string, hashpassword []byte, useremail string, mobile string, createdby string) string {
	ds := NewDataStore()
	defer ds.Close()
	n := ds.C("Admin")
	var adm Admin
	adm.FirstName = firstname
	adm.LastName = lastname
	adm.UserName = username
	adm.Password = password
	adm.HashPassword = hashpassword
	adm.UserEmail = useremail
	adm.Mobile = mobile
	adm.AccountStatus = true
	adm.CreatedBy = createdby
	adm.CreatedOn = time.Now()
	adm.ModifedBy = createdby
	adm.ModifiedOn = time.Now()
	err := n.Insert(&adm)
	if err != nil {
		return ERR_ADM_CREATE_INS_ERR
	} else {
		return ""
	}
}

func updateAdmin(firstname string, lastname string, useremail string, mobile string, modifiedby string, adminId string) string {
	adm, err := getAdminUserFromId(adminId)
	if err != nil {
		return ERR_DASHBRD_INV_ADMINID
	} else {
		ds := NewDataStore()
		defer ds.Close()
		n := ds.C("Admin")
		var adminIdObj = bson.M{"_id": bson.ObjectIdHex(adminId)}
		log.Println("updating admin user", adm.Id.Hex(), adminId)
		err = n.Update(adminIdObj, bson.M{"$set": bson.M{"firstname": firstname, "lastname": lastname, "useremail": useremail, "mobile": mobile, "modifedby": modifiedby, "modifiedon": time.Now()}})
		if err != nil {
			log.Println("error updating admin user", err)
			return ERR_ADM_UPDATE_UP_ERR
		} else {
			return ""
		}
	}
}

func updateAdminUserName(username string, modifiedby string, adminId string) string {
	adm, err := getAdminUserFromId(adminId)
	if err != nil {
		return ERR_DASHBRD_INV_ADMINID
	} else {
		result, err := getUserByUserName(username)
		if err != nil {
			ds := NewDataStore()
			defer ds.Close()
			n := ds.C("Admin")
			var adminIdObj = bson.M{"_id": bson.ObjectIdHex(adminId)}
			log.Println("updating admin userName", adm.Id.Hex(), adminId)
			err = n.Update(adminIdObj, bson.M{"$set": bson.M{"username": username, "modifedby": modifiedby, "modifiedon": time.Now()}})
			if err != nil {
				log.Println("error updating admin username", err)
				return ERR_ADM_UPDATE_UP_ERR
			} else {
				return ""
			}
		} else {
			log.Println("Duplicate user error", result.Id.Hex())
			return ERR_ADM_CREATE_DUP_USER_ERR
		}
	}
}

func updateAdminUserPassword(password string, hashpassword []byte, modifiedby string, adminId string) string {
	adm, err := getAdminUserFromId(adminId)
	if err != nil {
		return ERR_DASHBRD_INV_ADMINID
	} else {
		ds := NewDataStore()
		defer ds.Close()
		n := ds.C("Admin")
		var adminIdObj = bson.M{"_id": bson.ObjectIdHex(adminId)}
		log.Println("updating admin user  password", adm.Id.Hex(), adminId)
		err = n.Update(adminIdObj, bson.M{"$set": bson.M{"password": password, "hashpassword": hashpassword, "modifedby": modifiedby, "modifiedon": time.Now()}})
		if err != nil {
			log.Println("error updating admin user  password", err)
			return ERR_ADM_UPDATE_UP_ERR
		} else {
			return ""
		}
	}
}

func listAdminUsers(limit int, skip int) (adms []Admin, err error) {
	ds := NewDataStore()
	defer ds.Close()
	n := ds.C("Admin")
	accountstatusObj := bson.M{"accountstatus": true}
	if skip > 0 {
		err := n.Find(accountstatusObj).Sort("-modifiedon").Skip(skip).Limit(limit).All(&adms)
		log.Println("skip listing err", err)
	} else {
		err := n.Find(accountstatusObj).Sort("-modifiedon").Limit(limit).All(&adms)
		log.Println("lmit listing err", err)
	}
	return
}

func deleteAdmin(adminId string, modifiedby string) string {
	adm, err := getAdminUserFromId(adminId)
	if err != nil {
		return ERR_DASHBRD_INV_ADMINID
	} else {
		ds := NewDataStore()
		defer ds.Close()
		n := ds.C("Admin")
		var adminIdObj = bson.M{"_id": bson.ObjectIdHex(adminId)}
		log.Println("deleting admin user ", adm.Id.Hex(), adminId)
		err = n.Update(adminIdObj, bson.M{"$set": bson.M{"accountstatus": false, "modifedby": modifiedby, "modifiedon": time.Now()}})
		if err != nil {
			log.Println("error deleting admin user ", err)
			return ERR_ADM_DELETE_ERR
		} else {
			return ""
		}
	}
}

/* Admin collection functions END*/