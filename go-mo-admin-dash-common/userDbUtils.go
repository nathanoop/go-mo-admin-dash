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

func authenticateAdminUser(userName string, password string) (msgCode string, adminId string) {
	msgCode, adminId = "", ""
	if userName != "" && password != "" {
		result, err := getUserByUserName(userName)
		if err != nil {
			return ERR_LOGIN_INV_USR, adminId
		} else {
			if result.AccountStatus == false {
				return ERR_LOGIN_DELETED_ACCNT, adminId
			} else {
				// Validate password
				err = bcrypt.CompareHashAndPassword(result.HashPassword, []byte(password))
				if err != nil {
					return ERR_LOGIN_INC_PSSWD, adminId
				} else {
					adminId = result.Id.Hex()
					return msgCode, adminId
				}
			}
		}
	} else {
		return ERR_LOGIN_INV_USR_PSS, adminId
	}
}

func getAdminAccessToken(adminId string, uaStr string) string {
	if adminId != "" {
		accessToken := createAdminSession(adminId, uaStr)
		return accessToken
	} else {
		return ""
	}
}

func validateAdminToken(token string) (isValidToken bool, adminObj Admin) {
	adminId := ""
	if token != "" {
		isValidToken, adminId = getAdminSessionByToken(token)
		if adminId != "" {
			adminObj, err := getAdminUserFromId(adminId)
			if err != nil {
				log.Println("unable to validate token ", token)
			} else {
				log.Println("validate token in admin", adminObj.UserName)
				return isValidToken, adminObj
			}
		}
	}
	return
}
func logoutAdminToken(token string) bool {
	if token != "" {
		isValidToken := removeAdminSession(token)
		return isValidToken
	} else {
		return false
	}
}