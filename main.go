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

var checkDuration = time.Duration(10) * time.Minute

// Config は更新対象の設定。複数の設定を保持している。
type Config struct {
	Authentications []*Authentication
}

// AuthResponse は認証のレスポンス解釈用の構造体です
type AuthResponse struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`

	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// Authentication は認証の内容を保持する構造体です
type Authentication struct {
	Name string

	ClientID     string
	ClientSecret string

	RefreshToken string
	AccessToken  string
	ExpiresIn    int
	ExpiresAt    time.Time

	// Authorization用
	AuthURL string
	Scopes  []string

	// Token取得用
	TokenURL string
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

func refreshAccessToken(auth *Authentication) error {

	values := url.Values{}
	values.Add("client_id", auth.ClientID)
	values.Add("client_secret", auth.ClientSecret)
	values.Add("refresh_token", auth.RefreshToken)
	values.Add("grant_type", "refresh_token")

	resp, err := http.PostForm(auth.TokenURL, values)

	if err != nil {
		return err
	}

	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var ar AuthResponse
	err = json.Unmarshal(b, &ar)
	if err != nil {
		return err
	}

	if ar.Error != "" {
		return fmt.Errorf("response token error: %s, %s", ar.Error, ar.ErrorDescription)
	}

	if ar.AccessToken == "" {
		return fmt.Errorf("response token error: empty access token")
	}

	auth.AccessToken = ar.AccessToken
	if ar.RefreshToken != "" {
		auth.RefreshToken = ar.RefreshToken
	}
	auth.ExpiresAt = time.Now().Add(time.Duration(ar.ExpiresIn) * time.Second)

	return nil
}

func getAccessToken(req *Authentication) error {

	values := url.Values{}
	values.Add("response_code", "code")
	values.Add("client_id", req.ClientID)
	values.Add("client_secret", req.ClientSecret)
	values.Add("redirect_url", "urn:ietf:wg:oauth:2.0:oob")
	values.Add("scope", strings.Join(req.Scopes, " "))

	authorizeURL := fmt.Sprintf("%s?%s", req.AuthURL, values.Encode())

	fmt.Printf("Open url: %s\n", authorizeURL)
	fmt.Printf("Enter authorization code: ")

	var authCode string
	_, err := fmt.Scanln(&authCode)
	if err != nil {
		return err
	}

	return nil

}

func doNew() {
}

func doRefresh() {
	conf, err := loadConf()
	if err != nil {
		fmt.Println(err)
		return
	}

	var updated bool
	for _, auth := range conf.Authentications {
		// チェック期限だったらチェックする
		if auth.ExpiresAt.Before(time.Now().Add(-1 * checkDuration)) {
			err := refreshAccessToken(auth)
			if err != nil {
				fmt.Println(err)
				break
			}
			updated = true
		}
	}

	if updated {
		err = writeConf(conf)
		if err != nil {
			fmt.Println(err)
		}
	}
}

func main() {

	if len(os.Args) == 1 {
		doRefresh()
		return
	}

	switch os.Args[1] {
	case "new":
		doNew()
	case "refresh":
		doRefresh()
	}

}
