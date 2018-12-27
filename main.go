package main

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

/* ERROR MESSAGE CODE START */
const (
	ERR_LOGIN_INV_USR_PSS       = "ERRLGN001"
	ERR_LOGIN_INV_USR           = "ERRLGN002"
	ERR_LOGIN_INC_PSSWD         = "ERRLGN003"
	ERR_LOGIN_INV_TOKEN         = "ERRLGN004"
	ERR_LOGGED_OUT              = "ERRLGN005"
	ERR_LOGIN_DELETED_ACCNT     = "ERRLGN06"
	ERR_ADM_CREATE_REQ_FIELDS   = "ERRADM001"
	ERR_ADM_CREATE_PWD_ERR      = "ERRADM002"
	ERR_ADM_CREATE_PWD_HSH_ERR  = "ERRADM003"
	ERR_ADM_CREATE_INS_ERR      = "ERRADM004"
	ERR_ADM_CREATE_DUP_USER_ERR = "ERRADM005"
	ERR_DASHBRD_INV_ADMINID     = "ERRDASH005"
	ERR_ADM_UPDATE_UP_ERR       = "ERRADM006"
	ERR_ADMIN_LISTING           = "ERRADM007"
	ERR_ADM_DEL_SELF            = "ERRADM008"
	ERR_ADM_DELETE_ERR          = "ERRADM009"
)

/* ERROR MESSAGE CODE END */
/* ERROR MESSAGE String START */

func getErrorMessageResponse(errCode string) string {
	var ErrorMessage = make(map[string]string)
	ErrorMessage["ERRLGN001"] = "Username not found."
	ErrorMessage["ERRLGN002"] = "Incorrect password."
	ErrorMessage["ERRLGN003"] = "Username, password not present."
	ErrorMessage["ERRLGN004"] = "Invalid Session token."
	ErrorMessage["ERRLGN005"] = "User logged out"
	ErrorMessage["ERRLGN06"] = "Deleted user account, cannot login"
	ErrorMessage["ERRADM001"] = "Required fields missing."
	ErrorMessage["ERRADM002"] = "Password, Confirm password not the same."
	ErrorMessage["ERRADM003"] = "Password hashing error."
	ErrorMessage["ERRADM004"] = "Admin user  Insert Failed"
	ErrorMessage["ERRADM005"] = "Duplicate user with same username"
	ErrorMessage["ERRDASH005"] = "Select a valid admin user to edit"
	ErrorMessage["ERRADM006"] = "Admin user  update Failed"
	ErrorMessage["ERRADM007"] = "Admin user listing Failed"
	ErrorMessage["ERRADM008"] = "Admin cannot delete self"
	ErrorMessage["ERRADM009"] = "Admin user delete failed"
	return ErrorMessage[errCode]
}

/* ERROR MESSAGE String END */

var session *mgo.Session

/*  Database START*/

type (
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
	DataStore struct {
		session *mgo.Session
	}
	ErrorMsg struct {
		Code    string
		Message string
	}

	AdminTokenObj struct {
		Token        string
		AdmObj       Admin
		Code         string
		Message      string
		Module       string
		EditAdminObj Admin
	}

	AdminTokenListingObj struct {
		Token        string
		AdmObj       Admin
		Code         string
		Message      string
		Module       string
		ListAdminObj []Admin
	}
)

/*  Database END*/

/*  APP Variables START*/
var def_page_count = 10

/*   APP Variables  END*/

func (d *DataStore) Close() {
	d.session.Close()
}

func (d *DataStore) C(name string) *mgo.Collection {
	return d.session.DB("AdminDash").C(name)
}

func NewDataStore() *DataStore {
	ds := &DataStore{
		session: session.Copy(),
	}
	return ds
}

/*  Database Structure */

var templates map[string]*template.Template

//Compile view templates
func init() {
	if templates == nil {
		templates = make(map[string]*template.Template)
	}
	templates["login"] = template.Must(template.ParseFiles("templates/login.html", "templates/base.html"))
	templates["dashboard"] = template.Must(template.ParseFiles("templates/admin/dashboard.html", "templates/base.html", "templates/admin/nav.html"))
	templates["adminform"] = template.Must(template.ParseFiles("templates/admin/adminform.html", "templates/base.html", "templates/admin/nav.html"))
	templates["admineditform"] = template.Must(template.ParseFiles("templates/admin/admineditform.html", "templates/base.html", "templates/admin/nav.html"))
	templates["adminlist"] = template.Must(template.ParseFiles("templates/admin/adminlist.html", "templates/base.html", "templates/admin/nav.html"))
	templates["adminsettingsform"] = template.Must(template.ParseFiles("templates/admin/adminsettingsform.html", "templates/base.html", "templates/admin/nav.html"))
}

//Render templates for the given name, template definition and data object
func renderTemplate(w http.ResponseWriter, name string, template string, viewModel interface{}) {
	// Ensure the template exists in the map.
	tmpl, ok := templates[name]
	if !ok {
		http.Error(w, "The template does not exist.", http.StatusInternalServerError)
	}
	err := tmpl.ExecuteTemplate(w, template, viewModel)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

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

/* Admin Session collection functions END*/

/*  Auth Utils functions START */
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

/*  Auth Utils functions END */

/* Admin Utils function START */
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

/* Admin Utils function END */

/* General Utils function START */

func getBrowser(uastr string) string {
	regexpStr := `(?i)(firefox|msie|chrome|safari)[/\s]([/\d.]+)`
	r, _ := regexp.Compile(regexpStr)
	match := r.FindString(uastr)
	return match
}

/* General Utils function END */

/* Routing functions*/
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

/* Routing functions*/

//Entry point of the program
func main() {

	var err error
	session, err = mgo.Dial("localhost")
	if err != nil {
		panic(err)
	}
	r := mux.NewRouter().StrictSlash(false)

	r.PathPrefix("/css/").Handler(http.StripPrefix("/css/", http.FileServer(http.Dir("public/css/"))))
	r.PathPrefix("/js/").Handler(http.StripPrefix("/js/", http.FileServer(http.Dir("public/js/"))))
	r.PathPrefix("/images/").Handler(http.StripPrefix("/images/", http.FileServer(http.Dir("public/images/"))))
	r.PathPrefix("/fonts/").Handler(http.StripPrefix("/fonts/", http.FileServer(http.Dir("public/fonts/"))))

	r.HandleFunc("/", showLogin).Methods("GET")
	r.HandleFunc("/authenticateUser", authenticateAdmin).Methods("POST")
	r.HandleFunc("/logout/{token}", logoutUser).Methods("GET")
	r.HandleFunc("/dashboard/{token}", showDashboard).Methods("GET")

	r.HandleFunc("/admin/create/{token}", createAdminUser).Methods("GET")
	r.HandleFunc("/admin/save/{token}", saveAdminUser).Methods("POST")
	r.HandleFunc("/admin/list/{token}", listAdminUser).Methods("GET")
	r.HandleFunc("/admin/edit/{token}/{adminId}", editAdminUser).Methods("GET")
	r.HandleFunc("/profile/{token}/{adminId}", editAdminUser).Methods("GET")
	r.HandleFunc("/settings/{token}/{adminId}", editSettingsAdminUser).Methods("GET")
	r.HandleFunc("/admin/update/{token}/{adminId}", updateAdminUser).Methods("POST")
	r.HandleFunc("/admin/changeusername/{token}/{adminId}", changeAdminUsername).Methods("POST")
	r.HandleFunc("/admin/changepassword/{token}/{adminId}", changeAdminPassword).Methods("POST")
	r.HandleFunc("/admin/delete/{token}/{adminId}", deleteAdminUser).Methods("GET")

	server := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}
	log.Println("Listening...")
	server.ListenAndServe()
}
