package config

import (
	"os"
	"fmt"
	"io/ioutil"
	"encoding/json"
)

type Config struct {
	PublicKeyPath  string
	PrivateKeyPath string
	JWTExpirationHours  int
}

var config *Config = nil
var env = "development"

func Initialize() {
	env = os.Getenv("GO_ENV")
	if env == "" {
		fmt.Println("Warning: GO_ENV not found, setting \"development\" for env")
		env = "development"
	}
	LoadSettings(env)
}

func LoadSettings(env string) {
	fmt.Println(fmt.Sprintf("config/%s.json", env));
	content, err := ioutil.ReadFile(fmt.Sprintf("config/%s.json", env))
	if err != nil {
		fmt.Println("Error while reading config file", err)
	}
	config = &Config{}
	jsonErr := json.Unmarshal(content, &config)
	fmt.Println(config)
	if jsonErr != nil {
		fmt.Println("Error while parsing config file", jsonErr)
	}
}

func GetEnv() string {
	return env
}

func Get() *Config {
	if config == nil {
		Initialize()
	}
	return config
}

func IsEnv(check string) bool {
	return check == env
}