package go-mo-admin-dash-common


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


/*  APP Variables START*/
var def_page_count = 10

/*   APP Variables  END*/