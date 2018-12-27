package go-mo-admin-dash-routers

import (
	"github.com/gorilla/mux"
	controllers "go-mo-admin-dash-controllers"
)

func SetAdminRoutes(router *mux.Router) *mux.Router {

	router.HandleFunc("/admin/create/{token}", controllers.createAdminUser).Methods("GET")
	router.HandleFunc("/admin/save/{token}", controllers.saveAdminUser).Methods("POST")
	router.HandleFunc("/admin/list/{token}", controllers.listAdminUser).Methods("GET")
	router.HandleFunc("/admin/edit/{token}/{adminId}", controllers.editAdminUser).Methods("GET")
	router.HandleFunc("/profile/{token}/{adminId}",controllers.editAdminUser).Methods("GET")
	router.HandleFunc("/settings/{token}/{adminId}", controllers.editSettingsAdminUser).Methods("GET")
	router.HandleFunc("/admin/update/{token}/{adminId}", controllers.updateAdminUser).Methods("POST")
	router.HandleFunc("/admin/changeusername/{token}/{adminId}",controllers.changeAdminUsername).Methods("POST")
	router.HandleFunc("/admin/changepassword/{token}/{adminId}", controllers.changeAdminPassword).Methods("POST")
	router.HandleFunc("/admin/delete/{token}/{adminId}", controllers.deleteAdminUser).Methods("GET")


	return router
}