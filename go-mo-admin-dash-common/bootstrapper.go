package go-mo-admin-dash-common

// init bootstrapps the application
func init() {
	// Initialize AppConfig variable
	initConfig()
	// Start a MongoDB session
	createDbSession()
	// Add indexes into MongoDB
	addIndexes()
}
