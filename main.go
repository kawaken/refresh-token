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
	"strings"
	"time"
)

// Config は更新対象の設定。複数の設定を保持している。
type Config struct {
	// Tokens はAuthTokenのスライス
	Tokens []*AuthToken
}

// AuthToken は認証用のTokenと関連の情報
type AuthToken struct {
	Name             string
	ClientID         string
	ClientSecret     string
	AuthURL          string
	TokenURL         string
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresAt        time.Time
	Error            string
	ErrorDescription string `json:"error_description"`
	Scopes           []string
}

func loadConf() (*Config, error) {
	conf := new(Config)
	_, err := toml.DecodeFile("conf.toml", &conf)

	return conf, err
}

func writeConf(conf *Config) error {

	var buffer bytes.Buffer
	encoder := toml.NewEncoder(&buffer)
	err := encoder.Encode(conf)
	if err != nil {
		return err
	}
	return ioutil.WriteFile("conf.toml", buffer.Bytes(), os.ModePerm)
}

func refreshAccessToken(token *AuthToken) error {

	values := url.Values{}
	values.Add("client_id", token.ClientID)
	values.Add("client_secret", token.ClientSecret)
	values.Add("refresh_token", token.RefreshToken)
	values.Add("grant_type", "refresh_token")

	resp, err := http.PostForm(token.TokenURL, values)

	if err != nil {
		return err
	}

	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var at AuthToken
	err = json.Unmarshal(b, &at)
	if err != nil {
		return err
	}

	if at.Error != "" {
		return fmt.Errorf("response token error: %s, %s", at.Error, at.ErrorDescription)
	}

	if at.AccessToken == "" {
		return fmt.Errorf("response token error: empty access token")
	}

	token.AccessToken = at.AccessToken
	if at.RefreshToken != "" {
		token.RefreshToken = at.RefreshToken
	}
	token.ExpiresAt = time.Now().Add(time.Duration(at.ExpiresIn) * time.Second)

	return nil
}

func getAccessToken(token *AuthToken) error {

	values := url.Values{}
	values.Add("response_code", "code")
	values.Add("client_id", token.ClientID)
	values.Add("client_secret", token.ClientSecret)
	values.Add("redirect_url", "urn:ietf:wg:oauth:2.0:oob")
	values.Add("scope", strings.Join(token.Scopes, " "))

	authorizeURL := fmt.Sprintf("%s?%s", token.AuthURL, values.Encode())

	fmt.Printf("Open url: %s\n", authorizeURL)
	fmt.Printf("Enter authorization code: ")

	var authCode string
	_, err := fmt.Scanln(&authCode)
	if err != nil {
		return err
	}

	return nil

}

func main() {

	conf, err := loadConf()
	if err != nil {
		fmt.Println(err)
		return
	}

	var updated bool
	for _, token := range conf.Tokens {
		if token.ExpiresAt.Before(time.Now().Add(-1 * time.Duration(10) * time.Minute)) {
			err := refreshAccessToken(token)
			if err != nil {
				break
			}
			updated = true
		}
	}
	if updated {
		writeConf(conf)
	}

}
