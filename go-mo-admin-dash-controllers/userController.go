package go-mo-admin-dash-controllers

import (
	"html/template"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"time"
	common "go-mo-admin-dash-common"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

func showLogin(w http.ResponseWriter, r *http.Request) {
	msg, msgStr := "", ""
	msg = r.URL.Query().Get("msg")
	if msg != "" {
		msgStr = getErrorMessageResponse(msg)
	}
	viewModal := ErrorMsg{msg, msgStr}
	renderTemplate(w, "login", "base", viewModal)
}

func authenticateAdmin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")
	responseStr, adminId := authenticateAdminUser(username, password)
	if responseStr == "" {
		ua := r.Header.Get("User-Agent")
		accessToken := getAdminAccessToken(adminId, ua)
		if accessToken != "" {
			http.Redirect(w, r, "/dashboard/"+accessToken, 302)
		} else {
			http.Redirect(w, r, "/?msg="+ERR_LOGIN_INV_TOKEN, 302)
		}
	} else {
		http.Redirect(w, r, "/?msg="+responseStr, 302)
	}
}

func logoutUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	token := vars["token"]
	isValidToken := logoutAdminToken(token)
	if isValidToken == true {
		http.Redirect(w, r, "/?msg="+ERR_LOGGED_OUT, 302)
	} else {
		http.Redirect(w, r, "/?msg="+ERR_LOGIN_INV_TOKEN, 302)
	}
}

func showDashboard(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	token := vars["token"]
	isValidToken, adminObj := validateAdminToken(token)
	if isValidToken == true {
		msg, msgStr := "", ""
		msg = r.URL.Query().Get("msg")
		if msg != "" {
			msgStr = getErrorMessageResponse(msg)
		}
		var admObj Admin
		viewModal := AdminTokenObj{token, adminObj, msg, msgStr, "", admObj}
		renderTemplate(w, "dashboard", "base", viewModal)
	} else {
		http.Redirect(w, r, "/?msg="+ERR_LOGIN_INV_TOKEN, 302)
	}
}