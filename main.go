package main

import (
	"encoding/base64"
	"html/template"
	"log"
	"net/http"
	"regexp"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

/* ERROR MESSAGE CODE START */
const (
	ERR_LOGIN_INV_USR_PSS = "ERRLGN001"
	ERR_LOGIN_INV_USR     = "ERRLGN002"
	ERR_LOGIN_INC_PSSWD   = "ERRLGN003"
	ERR_LOGIN_INV_TOKEN   = "ERRLGN004"
)

/* ERROR MESSAGE CODE END */
/* ERROR MESSAGE String START */

func getErrorMessageResponse(errCode string) string {
	var ErrorMessage = make(map[string]string)
	ErrorMessage["ERRLGN001"] = "Username not found."
	ErrorMessage["ERRLGN002"] = "Incorrect password."
	ErrorMessage["ERRLGN003"] = "Username, password not present."
	ErrorMessage["ERRLGN004"] = "Invalid Session token."
	return ErrorMessage[errCode]
}

/* ERROR MESSAGE String END */

var session *mgo.Session

/*  Database START*/

type (
	Admin struct {
		Id           bson.ObjectId `bson:"_id,omitempty"`
		FirstName    string
		LastName     string
		UserName     string
		Password     string `json:"password,omitempty"`
		HashPassword []byte `json:"hashpassword,omitempty"`
		UserEmail    string
		Mobile       string
		CreatedOn    time.Time
		ModifiedOn   time.Time
	}
	AdminSession struct {
		Id          bson.ObjectId `bson:"_id,omitempty"`
		AdminId     string
		AccessToken string
		CreatedOn   time.Time
		ExpiredOn   time.Time
		Expired     bool
	}
	DataStore struct {
		session *mgo.Session
	}
	ErrorMsg struct {
		Code    string
		Message string
	}

	AdminTokenObj struct {
		Token  string
		AdmObj Admin
	}
)

/*  Database END*/

func (d *DataStore) Close() {
	d.session.Close()
}

func (d *DataStore) C(name string) *mgo.Collection {
	return d.session.DB("Notes").C(name)
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
	templates["dashboard"] = template.Must(template.ParseFiles("templates/dashboard.html", "templates/base.html", "templates/nav.html"))
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

/* Admin collection functions END*/
/* Admin Session collection functions START*/
func createAdminSession(adminId string, uaStr string) string {
	ds := NewDataStore()
	defer ds.Close()
	n := ds.C("AdminSession")
	var admSess AdminSession
	admSess.CreatedOn = time.Now()
	admSess.ExpiredOn = time.Now()
	admSess.Expired = true
	browserStr := ""
	if uaStr != "" {
		browserStr = getBrowser(uaStr)
	}
	var tokenStr = adminId + browserStr
	var token = string(base64.StdEncoding.EncodeToString([]byte(tokenStr)))
	admSess.AccessToken = token
	admSess.AdminId = adminId
	err := n.Insert(&admSess)
	if err != nil {
		return ""
	} else {
		return token
	}
}

func deleteAdminSessionEntry(adminSessId string) {
	var id = bson.ObjectIdHex(adminSessId)
	ds := NewDataStore()
	defer ds.Close()
	n := ds.C("AdminSession")
	err := n.Remove(bson.M{"_id": id})
	if err != nil {
		log.Println("unable to delete ", adminSessId)
	}
}

func getAdminSessionByToken(token string) (isValidToken bool, adminId string) {
	ds := NewDataStore()
	defer ds.Close()
	n := ds.C("AdminSession")
	var adminSessObj AdminSession
	var tokenObj = bson.M{"accesstoken": token}
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

/* Admin Session collection functions END*/

/*  Auth Utils functions START */
func authenticateAdminUser(userName string, password string) (msgCode string, adminId string) {
	msgCode, adminId = "", ""
	if userName != "" && password != "" {
		result, err := getUserByUserName(userName)
		if err != nil {
			return ERR_LOGIN_INV_USR, adminId
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
			}
		}
	}
	return
}

/*  Auth Utils functions END */

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

func showDashboard(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	token := vars["token"]
	isValidToken, adminObj := validateAdminToken(token)
	if isValidToken == true {
		viewModal := AdminTokenObj{token, adminObj}
		renderTemplate(w, "dashboard", "base", viewModal)
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
	r.HandleFunc("/dashboard/{token}", showDashboard).Methods("GET")

	server := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}
	log.Println("Listening...")
	server.ListenAndServe()
}
