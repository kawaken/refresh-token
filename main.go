package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/BurntSushi/toml"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"time"
)

type Config struct {
	Tokens []*AuthToken
}

type AuthToken struct {
	Name             string
	ClientID         string
	ClientSecret     string
	AuthURL          string
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresAt        time.Time
	Error            string
	ErrorDescription string `json:"error_description"`
}

func loadConf() (conf *Config, err error) {
	_, err = toml.DecodeFile("conf.toml", &conf)
	return
}

func writeConf(conf *Config) (err error) {

	var buffer bytes.Buffer
	encoder := toml.NewEncoder(&buffer)
	err = encoder.Encode(conf)
	if err != nil {
		return
	}
	err = ioutil.WriteFile("conf.toml", buffer.Bytes(), os.ModePerm)
	return
}

func refreshAccessToken(token *AuthToken) {

	values := url.Values{}
	values.Add("client_id", token.ClientID)
	values.Add("client_secret", token.ClientSecret)
	values.Add("refresh_token", token.RefreshToken)
	values.Add("grant_type", "refresh_token")

	resp, err := http.PostForm(token.AuthURL, values)

	if err != nil {
		fmt.Println(err)
		return
	}

	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%v\n", string(b))

	var at AuthToken
	err = json.Unmarshal(b, &at)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%v\n", at)

	if at.Error == "" && at.AccessToken != "" {
		fmt.Println("\nVerified")
		token.AccessToken = at.AccessToken
		if at.RefreshToken != "" {
			token.RefreshToken = at.RefreshToken
		}
		token.ExpiresAt = time.Now().Add(time.Duration(at.ExpiresIn) * time.Second)

		return
	}
}

func main() {

	conf, err := loadConf()
	if err != nil {
		fmt.Println(err)
		return
	}

	var updated bool
	for _, token := range conf.Tokens {
		if token.ExpiresAt.Before(time.Now()) {
			fmt.Println("token expired:", token.Name)
			refreshAccessToken(token)
			updated = true
		}
	}
	if updated {
		writeConf(conf)
	}

}
