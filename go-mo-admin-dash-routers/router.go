package go-mo-admin-dash-routers


import (
	"github.com/gorilla/mux"
)

func InitRoutes() *mux.Router {
	router := mux.NewRouter().StrictSlash(false)

	router.PathPrefix("/css/").Handler(http.StripPrefix("/css/", http.FileServer(http.Dir("public/css/"))))
	router.PathPrefix("/js/").Handler(http.StripPrefix("/js/", http.FileServer(http.Dir("public/js/"))))
	router.PathPrefix("/images/").Handler(http.StripPrefix("/images/", http.FileServer(http.Dir("public/images/"))))
	router.PathPrefix("/fonts/").Handler(http.StripPrefix("/fonts/", http.FileServer(http.Dir("public/fonts/"))))

	// Routes for the User entity
	router = SetUserRoutes(router)
	// Routes for the Admin entity
	router = SetAdminRoutes(router)
	return router
}