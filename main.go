package main

import (
	"bytes"
	"encoding/json"
	"flag"
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

var (
	file = flag.String("file", "conf.toml", "config file path")
)

// Config は更新対象の設定。複数の設定を保持している。
type Config struct {
	Sites []*Site
}

// AuthResponse は認証のレスポンス解釈用の構造体です
type AuthResponse struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`

	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// Site は認証の内容を保持する構造体です
type Site struct {
	Name string

	ClientID     string
	ClientSecret string

	RefreshToken string
	AccessToken  string
	ExpiresIn    int `toml:"-"`
	ExpiresAt    time.Time

	// Authorization用
	AuthURL string
	Scopes  []string

	// Token取得用
	TokenURL string
}

func loadConf(path string) (*Config, error) {
	conf := new(Config)
	_, err := toml.DecodeFile(path, &conf)

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

func getAuthorizationCode(site *Site) (string, error) {

	values := url.Values{}
	values.Add("response_type", "code")
	values.Add("client_id", site.ClientID)
	//values.Add("client_secret", site.ClientSecret)
	values.Add("redirect_uri", "urn:ietf:wg:oauth:2.0:oob")
	values.Add("scope", strings.Join(site.Scopes, " "))

	authorizeURL := fmt.Sprintf("%s?%s", site.AuthURL, values.Encode())

	fmt.Printf("Open url: \n%s\n\n", authorizeURL)
	fmt.Printf("Enter authorization code: ")

	var authCode string
	_, err := fmt.Scanln(&authCode)
	if err != nil {
		return "", err
	}

	if authCode == "" {
		return "", fmt.Errorf("cant read Authorization Code")
	}

	return authCode, nil
}

func requestAccessToken(site *Site, values url.Values) error {

	resp, err := http.PostForm(site.TokenURL, values)

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

	site.AccessToken = ar.AccessToken
	if ar.RefreshToken != "" {
		site.RefreshToken = ar.RefreshToken
	}
	site.ExpiresAt = time.Now().Add(time.Duration(ar.ExpiresIn) * time.Second)

	return nil
}

func getAccessToken(site *Site) error {

	authCode, err := getAuthorizationCode(site)
	if err != nil {
		return err
	}

	values := url.Values{}
	values.Add("client_id", site.ClientID)
	values.Add("client_secret", site.ClientSecret)
	values.Add("code", authCode)
	values.Add("redirect_uri", "urn:ietf:wg:oauth:2.0:oob")
	values.Add("grant_type", "authorization_code")

	return requestAccessToken(site, values)
}

func refreshAccessToken(site *Site) error {

	values := url.Values{}
	values.Add("client_id", site.ClientID)
	values.Add("client_secret", site.ClientSecret)
	values.Add("refresh_token", site.RefreshToken)
	values.Add("grant_type", "refresh_token")

	return requestAccessToken(site, values)
}

func doNew(site *Site) (bool, error) {
	// RefreshToken が空ではない場合は何もしない
	if site.RefreshToken != "" {
		return false, nil
	}

	err := getAccessToken(site)
	return err == nil, err
}

func doRefresh(site *Site) (bool, error) {
	// 有効期限に近くなければ何もしない
	if site.ExpiresAt.After(time.Now().Add(checkDuration)) {
		return false, nil
	}

	if site.RefreshToken == "" {
		return false, fmt.Errorf("no RefreshToken")
	}

	err := refreshAccessToken(site)
	return err == nil, err
}

func main() {
	flag.Parse()

	conf, err := loadConf(*file)
	if err != nil {
		fmt.Println(err)
		return
	}

	cmd := doRefresh

	if len(os.Args) > 1 && os.Args[1] == "new" {
		cmd = doNew
	}

	var updated bool
	for _, site := range conf.Sites {
		success, err := cmd(site)
		if err != nil {
			updated = false
			fmt.Printf("%s: %s\n", site.Name, err)
			break
		}

		updated = updated || success
	}

	if !updated {
		return
	}

	err = writeConf(conf)
	if err != nil {
		fmt.Println(err)
	}
}
