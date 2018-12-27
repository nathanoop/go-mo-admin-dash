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