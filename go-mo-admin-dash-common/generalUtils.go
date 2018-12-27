package go-mo-admin-dash-common

import (
	"encoding/json"
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


// AppConfig holds the configuration values from config.json file
var AppConfig configuration

// Initialize AppConfig
func initConfig() {
	loadAppConfig()
}

// Reads config.json and decode into AppConfig
func loadAppConfig() {
	file, err := os.Open("go-mo-admin-dash-common/config.json")
	defer file.Close()
	if err != nil {
		log.Fatalf("[loadConfig]: %s\n", err)
	}
	decoder := json.NewDecoder(file)
	AppConfig = configuration{}
	err = decoder.Decode(&AppConfig)
	if err != nil {
		log.Fatalf("[loadAppConfig]: %s\n", err)
	}
}

func getBrowser(uastr string) string {
	regexpStr := `(?i)(firefox|msie|chrome|safari)[/\s]([/\d.]+)`
	r, _ := regexp.Compile(regexpStr)
	match := r.FindString(uastr)
	return match
}