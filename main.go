package main

import (
	common "go-mo-admin-dash-common"
	routers "go-mo-admin-dash-routers"
	"log"
	"net/http"

	mgo "gopkg.in/mgo.v2"
)

//Entry point of the program
func main() {

	router := routers.InitRoutes()

	var err error
	session, err = mgo.Dial("localhost")
	if err != nil {
		panic(err)
	}

	server := &http.Server{
		Addr:    common.AppConfig.Server,
		Handler: router,
	}
	log.Println("Listening...")
	server.ListenAndServe()
}
