package go-mo-admin-dash-controllers

import (
	"html/template"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"time"
	common 	"go-mo-admin-dash-common"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)



func createAdminUser(w http.ResponseWriter, r *http.Request) {
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
		viewModal := AdminTokenObj{token, adminObj, msg, msgStr, "Admin", admObj}
		renderTemplate(w, "adminform", "base", viewModal)
	} else {
		http.Redirect(w, r, "/?msg="+ERR_LOGIN_INV_TOKEN, 302)
	}
}

func saveAdminUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	token := vars["token"]
	isValidToken, adminObj := validateAdminToken(token)
	if isValidToken == true {
		r.ParseForm()
		firstname := r.PostFormValue("firstname")
		lastname := r.PostFormValue("lastname")
		username := r.PostFormValue("username")
		password := r.PostFormValue("password")
		confirmpassword := r.PostFormValue("confirmpassword")
		useremail := r.PostFormValue("useremail")
		createdby := adminObj.Id.Hex()
		mobile := r.PostFormValue("mobile")
		if firstname != "" && lastname != "" && username != "" && password != "" && confirmpassword != "" && useremail != "" && mobile != "" {
			if password == confirmpassword {
				msg := createAdminUserUtils(firstname, lastname, username, password, useremail, mobile, createdby)
				if msg != "" {
					http.Redirect(w, r, "/admin/create/"+token+"?msg="+msg, 302)
				} else {
					http.Redirect(w, r, "/admin/list/"+token, 302)
				}
			} else {
				http.Redirect(w, r, "/admin/create/"+token+"?msg="+ERR_ADM_CREATE_PWD_ERR, 302)
			}
		} else {
			http.Redirect(w, r, "/admin/create/"+token+"?msg="+ERR_ADM_CREATE_REQ_FIELDS, 302)
		}
	} else {
		http.Redirect(w, r, "/?msg="+ERR_LOGIN_INV_TOKEN, 302)
	}
}

func editAdminUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	token := vars["token"]
	isValidToken, adminObj := validateAdminToken(token)
	if isValidToken == true {
		adminId := vars["adminId"]
		if adminId != "" {
			msg, msgStr := "", ""
			msg = r.URL.Query().Get("msg")
			if msg != "" {
				msgStr = getErrorMessageResponse(msg)
			}
			var admObj Admin
			if adminId != adminObj.Id.Hex() {
				admObj, err := getAdminUserById(adminId)
				if err != nil {
					http.Redirect(w, r, "/dashboard/token?msg="+ERR_DASHBRD_INV_ADMINID, 302)
				} else {
					log.Println("editing admin obj", admObj.Id.Hex())
				}
				viewModal := AdminTokenObj{token, adminObj, msg, msgStr, "Admin", admObj}
				renderTemplate(w, "admineditform", "base", viewModal)
			} else {
				admObj = adminObj
				viewModal := AdminTokenObj{token, adminObj, msg, msgStr, "Admin", admObj}
				renderTemplate(w, "admineditform", "base", viewModal)
			}
		} else {
			http.Redirect(w, r, "/dashboard/token?msg="+ERR_DASHBRD_INV_ADMINID, 302)
		}
	} else {
		http.Redirect(w, r, "/?msg="+ERR_LOGIN_INV_TOKEN, 302)
	}
}

func updateAdminUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	token := vars["token"]
	isValidToken, adminObj := validateAdminToken(token)
	if isValidToken == true {
		r.ParseForm()
		firstname := r.PostFormValue("firstname")
		lastname := r.PostFormValue("lastname")
		useremail := r.PostFormValue("useremail")
		modifiedby := adminObj.Id.Hex()
		mobile := r.PostFormValue("mobile")
		adminId := vars["adminId"]
		if firstname != "" && lastname != "" && useremail != "" && mobile != "" {
			msg := updateAdminUserUtils(firstname, lastname, useremail, mobile, modifiedby, adminId)
			if msg != "" {
				http.Redirect(w, r, "/dashboard/"+token+"?msg="+msg, 302)
			} else {
				http.Redirect(w, r, "/admin/edit/"+token+"/"+adminId, 302)
			}
		} else {
			http.Redirect(w, r, "/admin/edit/"+token+"/"+adminId+"?msg="+ERR_ADM_CREATE_REQ_FIELDS, 302)
		}
	} else {
		http.Redirect(w, r, "/?msg="+ERR_LOGIN_INV_TOKEN, 302)
	}
}

func editSettingsAdminUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	token := vars["token"]
	isValidToken, adminObj := validateAdminToken(token)
	if isValidToken == true {
		msg, msgStr := "", ""
		msg = r.URL.Query().Get("msg")
		if msg != "" {
			msgStr = getErrorMessageResponse(msg)
		}
		adminId := vars["adminId"]
		var admObj Admin
		if adminId != adminObj.Id.Hex() {
			admObj, err := getAdminUserById(adminId)
			if err != nil {
				http.Redirect(w, r, "/dashboard/token?msg="+ERR_DASHBRD_INV_ADMINID, 302)
			} else {
				log.Println("editing admin obj", admObj.Id.Hex())
			}
			viewModal := AdminTokenObj{token, adminObj, msg, msgStr, "Admin", admObj}
			renderTemplate(w, "adminsettingsform", "base", viewModal)
		} else {
			admObj = adminObj
			viewModal := AdminTokenObj{token, adminObj, msg, msgStr, "Admin", admObj}
			renderTemplate(w, "adminsettingsform", "base", viewModal)
		}
	} else {
		http.Redirect(w, r, "/?msg="+ERR_LOGIN_INV_TOKEN, 302)
	}
}

func changeAdminUsername(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	token := vars["token"]
	isValidToken, adminObj := validateAdminToken(token)
	if isValidToken == true {
		r.ParseForm()
		username := r.PostFormValue("username")
		adminId := vars["adminId"]
		if username != "" {
			modifiedby := adminObj.Id.Hex()
			msg := updateAdminUserNameUtils(username, modifiedby, adminId)
			if msg != "" {
				http.Redirect(w, r, "/dashboard/"+token+"?msg="+msg, 302)
			} else {
				http.Redirect(w, r, "/settings/"+token+"/"+adminId, 302)
			}
		} else {
			http.Redirect(w, r, "/settings/"+token+"/"+adminId+"?msg="+ERR_ADM_CREATE_REQ_FIELDS, 302)
		}
	} else {
		http.Redirect(w, r, "/?msg="+ERR_LOGIN_INV_TOKEN, 302)
	}
}

func changeAdminPassword(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	token := vars["token"]
	isValidToken, adminObj := validateAdminToken(token)
	if isValidToken == true {
		r.ParseForm()
		password := r.PostFormValue("password")
		confirmpassword := r.PostFormValue("confirmpassword")
		modifiedby := adminObj.Id.Hex()
		adminId := vars["adminId"]
		if password != "" && confirmpassword != "" {
			if password == confirmpassword {
				msg := updateAdminUserPasswordUtils(password, modifiedby, adminId)
				if msg != "" {
					http.Redirect(w, r, "/dashboard/"+token+"?msg="+msg, 302)
				} else {
					http.Redirect(w, r, "/settings/"+token+"/"+adminId, 302)
				}
			} else {
				http.Redirect(w, r, "/settings/"+token+"/"+adminId+"?msg="+ERR_ADM_CREATE_PWD_ERR, 302)
			}
		} else {
			http.Redirect(w, r, "/settings/"+token+"/"+adminId+"?msg="+ERR_ADM_CREATE_REQ_FIELDS, 302)
		}
	} else {
		http.Redirect(w, r, "/?msg="+ERR_LOGIN_INV_TOKEN, 302)
	}
}

func deleteAdminUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	token := vars["token"]
	isValidToken, adminObj := validateAdminToken(token)
	if isValidToken == true {
		log.Println("Delete admin by", adminObj.Id.Hex())
		modifiedby := adminObj.Id.Hex()
		adminId := vars["adminId"]
		if modifiedby != adminId {
			msg := deleteAdminUserUtils(adminId, modifiedby)
			if msg == "" {
				http.Redirect(w, r, "/admin/list/"+token, 302)
			} else {
				http.Redirect(w, r, "/admin/list/"+token+"?msg="+msg, 302)
			}
		} else {
			http.Redirect(w, r, "/admin/list/"+token+"?msg="+ERR_ADM_DEL_SELF, 302)
		}
	} else {
		http.Redirect(w, r, "/?msg="+ERR_LOGIN_INV_TOKEN, 302)
	}
}

func listAdminUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	token := vars["token"]
	isValidToken, adminObj := validateAdminToken(token)
	if isValidToken == true {
		msg, msgStr := "", ""
		msg = r.URL.Query().Get("msg")
		if msg != "" {
			msgStr = getErrorMessageResponse(msg)
		}
		p := r.URL.Query().Get("p")
		page, err := strconv.Atoi(p)
		if err != nil {
			page = 0
		}
		if p == "" {
			page = 0
		}
		adms, err := listAdminUsersUtils(page)
		if err != nil {
			msg = ERR_ADMIN_LISTING
			msgStr = getErrorMessageResponse(msg)
		}
		viewModal := AdminTokenListingObj{token, adminObj, msg, msgStr, "Admin", adms}
		renderTemplate(w, "adminlist", "base", viewModal)
	} else {
		http.Redirect(w, r, "/?msg="+ERR_LOGIN_INV_TOKEN, 302)
	}
}