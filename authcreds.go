package authcreds

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-secretsmanager-caching-go/secretcache"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/joho/godotenv"
	"github.com/spf13/cast"
	"github.com/tidwall/gjson"
	"go.uber.org/atomic"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
)

type Secret struct {
	BearerToken   atomic.String
	APIToken      atomic.String
	token         []byte
	url           string
	SecretID      string
	SecretVersion string
	TokenType     string
	TokenField    string
}

var (
	BearerToken    atomic.String
	MailCreds      atomic.String
	Keyring        []Secret
	secretCache, _ = secretcache.New()
)

func AuthLoad() error {
	var secret0ID string
	var secret1ID string
	var projectID string

	if s := os.Getenv("SECRET_STORE"); s == "" {
		_, e := os.Stat("./conf.env")
		if os.IsNotExist(e) {
			err := generateVarsFile()
			if err != nil {
				return fmt.Errorf("authcreds package: error generating conf.env: %v", err)
			}
			return fmt.Errorf("authcreds package: missing conf.env file and required envvars not defined")
		}
		err := godotenv.Load("./conf.env")
		if err != nil {
			return fmt.Errorf("error loading .env file and required envvars not defined: %v", err)
		}
	}

	secretLocation := os.Getenv("SECRET_STORE")
	secretCount := cast.ToInt(os.Getenv("NUM_SECRETS"))

	if secretCount < 1 {
		return fmt.Errorf("authcreds package: missing or invalid env var: num_secrets")
	}

	url := os.Getenv("TOKEN_URL")
	if url == "" {
		return fmt.Errorf("authcreds package: missing env var: token_url")
	}
	tokenField := os.Getenv("TOKEN_FIELD")
	if tokenField == "" {
		return fmt.Errorf("authcreds package: missing env var: token_field")
	}

	switch secretLocation {
	case "GCP":
		projectID = os.Getenv("PROJECT_ID")
		for i := 0; i < int(secretCount); i++ {
			var err error
			s := new(Secret)
			s.SecretID = os.Getenv("SECRET_ID_" + cast.ToString(i))
			if s.SecretID == "" {
				return fmt.Errorf("authcreds: missing secret_id")
			}
			s.SecretVersion = os.Getenv("SECRET_VERSION_" + cast.ToString(i))
			if s.SecretVersion == "" {
				s.SecretVersion = "1"
			}
			s.url = os.Getenv("TOKEN_URL_" + cast.ToString(i))
			if url == "" {
				return fmt.Errorf("authcreds package: missing env var: token_url")
			}
			s.TokenField = os.Getenv("TOKEN_FIELD_" + cast.ToString(i))
			if s.TokenField == "" {
				s.TokenField = "access_token"
			}
			s.TokenType = os.Getenv("TOKEN_TYPE_" + cast.ToString(i))
			if s.TokenType == "" {
				s.TokenType = "Bearer"
			} else {
				s.TokenType = "APIKEY"
			}
			s.token, err = fetchGCPSecret(projectID, s.SecretID, s.SecretVersion)
			if err != nil {
				return fmt.Errorf("authcreds: error retrieving %v/version/%v: %v", s.SecretID, s.SecretVersion, err)
			}
			Keyring = append(Keyring, *s)
		}
		for i := 0; i < len(Keyring); i++ {
			if Keyring[i].TokenType == "Bearer" {
				go authBearer(Keyring, i, "")
				go authBearer(Keyring, i, "30s")
			} else {
				Keyring[i].APIToken.Store(string(Keyring[i].token))
			}
			if i+1 == 2 {
				MailCreds.Store(string(Keyring[i].token))
			}
		}
	case "AWS":
		switch secretCount {
		case 1:
			secret0ID = os.Getenv("SECRET_ID_1")
			secret0, err := fetchAWSSecret("AWS_SECRET_ID_1")
			if err != nil {
				return fmt.Errorf("error retrieving AWS secret %v: %v", secret0ID, err)
			}
			go auth(url, tokenField, []byte(secret0))
			go auth2(url, tokenField, []byte(secret0))
		case 2:
			secret0ID = os.Getenv("SECRET_ID_1")
			secret0, err := fetchAWSSecret("AWS_SECRET_ID_1")
			if err != nil {
				return fmt.Errorf("error retrieving AWS secret %v: %v", secret0ID, err)
			}
			secret1ID = os.Getenv("SECRET_ID_2")
			secret1, err := fetchAWSSecret("AWS_SECRET_ID_2")
			if err != nil {
				return fmt.Errorf("error retrieving AWS secret %v: %v", secret1ID, err)
			}
			go auth(url, tokenField, []byte(secret0))
			go auth2(url, tokenField, []byte(secret0))
			MailCreds.Store(string(secret1))
		}
		secret0ID = os.Getenv("SECRET_ID_1")
		secret1ID = os.Getenv("SECRET_ID_2")

	}
	return nil
}

func fetchAWSSecret(secretID string) (string, error) {
	result, err := secretCache.GetSecretString(secretID)
	if err != nil {
		return result, err
	}
	return result, err
}

func fetchGCPSecret(projectID, secretID, secretVersion string) ([]byte, error) {
	ctx := context.Background()
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to setup client: %v", err)
	}
	defer client.Close()

	accessRequest := &secretmanagerpb.AccessSecretVersionRequest{
		Name: "projects/" + projectID + "/secrets/" + secretID + "/versions/" + secretVersion,
	}
	result, err := client.AccessSecretVersion(ctx, accessRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to access secret version: %v", err)
	}

	return result.Payload.Data, nil
}

func auth(url, tokenField string, secret []byte) {
	payload := strings.NewReader(string(secret))
	req, err := retryablehttp.NewRequest("POST", url, payload)
	if err != nil {
		log.Println(err)
	}
	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 2
	retryClient.RetryWaitMin = 10000000
	retryClient.Logger = nil

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Cache-Control", "no-cache")
	var expiry int64
	for {
		res, err := retryClient.Do(req)
		if err != nil {
			log.Println(err)
		}

		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			log.Println(err)
		}
		res.Body.Close()
		jsonbody := string(body)
		BearerToken.Store("Bearer " + gjson.Get(jsonbody, tokenField).Str)
		expiry = gjson.Get(jsonbody, "expires_in").Int()
		d := time.Duration(expiry)
		time.Sleep(d * time.Second)
	}
}

func auth2(url, tokenField string, secret []byte) {
	payload := strings.NewReader(string(secret))
	req, err := retryablehttp.NewRequest("POST", url, payload)
	if err != nil {
		log.Println(err)
	}
	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 2
	retryClient.RetryWaitMin = 10000000
	retryClient.Logger = nil

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Cache-Control", "no-cache")
	time.Sleep(150 * time.Second)
	var expiry int64
	for {
		res, err := retryClient.Do(req)
		if err != nil {
			log.Println(err)
		}

		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			log.Println(err)
		}
		res.Body.Close()
		jsonbody := string(body)
		BearerToken.Store("Bearer " + gjson.Get(jsonbody, tokenField).Str)
		expiry = gjson.Get(jsonbody, "expires_in").Int()
		d := time.Duration(expiry)
		time.Sleep(d * time.Second)
	}
}

func authBearer(Keyring []Secret, index int, overlap string) {
	s := Keyring[index]
	payload := strings.NewReader(string(s.token))
	req, err := retryablehttp.NewRequest("POST", s.url, payload)
	if err != nil {
		log.Println(err)
	}
	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 2
	retryClient.RetryWaitMin = 10000000
	retryClient.Logger = nil

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Cache-Control", "no-cache")
	var expiry int64
	time.Sleep(cast.ToDuration(overlap))
	for {
		res, err := retryClient.Do(req)
		if err != nil {
			log.Println(err)
		}

		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			log.Println(err)
		}
		res.Body.Close()
		jsonbody := string(body)
		BearerToken.Store("Bearer " + gjson.Get(jsonbody, s.TokenField).Str)
		expiry = gjson.Get(jsonbody, "expires_in").Int()
		d := time.Duration(expiry)
		time.Sleep(d * time.Second)
	}
}

func generateVarsFile() error {
	f, err := os.Create("./conf.env")
	if err != nil {
		return fmt.Errorf("conf.env file creation: %v", err)
	}
	varsTemplate := "# SECRET STORE\nSECRET_STORE=\nNUM_SECRETS=1\n# SECRET MANAGER\nPROJECT_ID=\nSECRET_ID_1=\nSECRET_VERSION_1=\nSECRET_ID_2=\nSECRET_VERSION_2=\n# AUTH\nTOKEN_URL=\n"
	_, err = f.WriteString(varsTemplate)
	if err != nil {
		return fmt.Errorf("conf.env file write: %v", err)
	}
	f.Sync()
	return err
}
