package go-mo-admin-dash-routers

import (
	"github.com/gorilla/mux"
	controllers "go-mo-admin-dash-controllers"
)

func SetUserRoutes(router *mux.Router) *mux.Router {
	router.HandleFunc("/", controllers.showLogin).Methods("GET")
	router.HandleFunc("/authenticateUser", controllers.authenticateAdmin).Methods("POST")
	router.HandleFunc("/logout/{token}", controllers.logoutUser).Methods("GET")
	router.HandleFunc("/dashboard/{token}", controllers.showDashboard).Methods("GET")
	return router
}
