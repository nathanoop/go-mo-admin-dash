package go-mo-admin-dash-controllers
import (
	models "go-mo-admin-dash-models"
)

//Models for JSON resources
type (

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