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

func createAdminUserUtils(firstname string, lastname string, username string, password string, useremail string, mobile string, createdby string) string {
	msg := ""
	result, err := getUserByUserName(username)
	if err != nil {
		hashpassword, err := bcrypt.GenerateFromPassword([]byte(password), 14)
		if err != nil {
			msg = ERR_ADM_CREATE_PWD_HSH_ERR
		} else {
			msg = insertAdminUser(firstname, lastname, username, password, hashpassword, useremail, mobile, createdby)
		}
	} else {
		log.Println("duplicate user ...", result)
		msg = ERR_ADM_CREATE_DUP_USER_ERR
	}
	return msg
}

func getAdminUserById(adminId string) (adm Admin, err error) {
	adm, err = getAdminUserFromId(adminId)
	return
}

func updateAdminUserUtils(firstname string, lastname string, useremail string, mobile string, modifiedby string, adminId string) string {
	msg := updateAdmin(firstname, lastname, useremail, mobile, modifiedby, adminId)
	return msg
}

func updateAdminUserNameUtils(username string, modifiedby string, adminId string) string {
	msg := updateAdminUserName(username, modifiedby, adminId)
	return msg
}

func updateAdminUserPasswordUtils(password string, modifiedby string, adminId string) string {
	msg := ""
	hashpassword, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		msg = ERR_ADM_CREATE_PWD_HSH_ERR
	} else {
		msg = updateAdminUserPassword(password, hashpassword, modifiedby, adminId)
	}
	return msg
}

func listAdminUsersUtils(page int) (adms []Admin, err error) {
	limit := def_page_count
	skip := 0
	if page > 0 {
		skip = limit * page
	}
	adms, err = listAdminUsers(limit, skip)
	return
}

func deleteAdminUserUtils(adminId string, modifiedby string) string {
	msg := deleteAdmin(adminId, modifiedby)
	return msg
}