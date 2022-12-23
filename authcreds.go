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

var (
	BearerToken    atomic.String
	MailCreds      atomic.String
	secretCache, _ = secretcache.New()
)

func AuthLoad() {
	var secret0ID string
	var secret0Version string
	var secret1ID string
	var secret1Version string
	var projectID string
	var url string
	_, e := os.Stat("./conf.env")
	if os.IsNotExist(e) {
		err := generateVarsFile()
		if err != nil {
			log.Fatal(err)
		}
		log.Println("authcreds package: missing conf.env file")
		os.Exit(1)
	}
	err := godotenv.Load("./conf.env")
	if err != nil {
		log.Fatal("error loading .env file")
	}
	secretLocation := os.Getenv("SECRET_STORE")
	secretCount := cast.ToInt(os.Getenv("NUM_SECRETS"))

	if secretCount < 1 {
		log.Fatal("missing or invalid env var: num_secrets")
	}
	url = os.Getenv("TOKEN_URL")
	if url == "" {
		log.Fatal("missing env var: token_url")
	}
	switch secretLocation {
	case "GCP":
		projectID = os.Getenv("PROJECT_ID")
		switch secretCount {
		case 1:
			secret0ID = os.Getenv("SECRET_ID_1")
			secret0Version = os.Getenv("SECRET_VERSION_1")
			secret0, err := fetchGCPSecret(projectID, secret0ID, secret0Version)
			if err != nil {
				log.Fatalf("error retrieving %v/version/%v: %v", secret0ID, secret0Version, err)
			}
			go auth(url, secret0)
			go auth2(url, secret0)
		case 2:
			secret0ID = os.Getenv("SECRET_ID_1")
			secret0Version = os.Getenv("SECRET_VERSION_1")
			secret1ID = os.Getenv("SECRET_ID_2")
			secret1Version = os.Getenv("SECRET_VERSION_2")
			secret0, err := fetchGCPSecret(projectID, secret0ID, secret0Version)
			if err != nil {
				log.Fatalf("error retrieving %v/version/%v: %v", secret0ID, secret0Version, err)
			}
			secret1, err := fetchGCPSecret(projectID, secret1ID, secret1Version)
			if err != nil {
				log.Fatalf("error retrieving %v/version/%v: %v", secret1ID, secret1Version, err)
			}
			go auth(url, secret0)
			go auth2(url, secret0)
			MailCreds.Store(string(secret1))
		}
	case "AWS":
		switch secretCount {
		case 1:
			secret0ID = os.Getenv("SECRET_ID_1")
			secret0, err := fetchAWSSecret("AWS_SECRET_ID_1")
			if err != nil {
				log.Fatal("error retrieving AWS secret %v: %v", secret0ID, err)
			}
			go auth(url, []byte(secret0))
			go auth2(url, []byte(secret0))
		case 2:
			secret0ID = os.Getenv("SECRET_ID_1")
			secret0, err := fetchAWSSecret("AWS_SECRET_ID_1")
			if err != nil {
				log.Fatal("error retrieving AWS secret %v: %v", secret0ID, err)
			}
			secret1ID = os.Getenv("SECRET_ID_2")
			secret1, err := fetchAWSSecret("AWS_SECRET_ID_2")
			if err != nil {
				log.Fatal("error retrieving AWS secret %v: %v", secret1ID, err)
			}
			go auth(url, []byte(secret0))
			go auth2(url, []byte(secret0))
			MailCreds.Store(string(secret1))
		}
		secret0ID = os.Getenv("SECRET_ID_1")
		secret1ID = os.Getenv("SECRET_ID_2")

	}
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

func auth(url string, secret []byte) {
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
		BearerToken.Store("Bearer " + gjson.Get(jsonbody, "access_token").Str)
		expiry = gjson.Get(jsonbody, "expires_in").Int()
		d := time.Duration(expiry)
		time.Sleep(d * time.Second)
	}
}

func auth2(url string, secret []byte) {
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
		BearerToken.Store("Bearer " + gjson.Get(jsonbody, "access_token").Str)
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
