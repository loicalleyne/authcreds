package authcreds

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/joho/godotenv"
	"github.com/tidwall/gjson"
	"go.uber.org/atomic"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
)

var (
	BearerToken atomic.String
	MailCreds   atomic.String
)

func AuthLoad() {
	var secret0ID string
	var secret0Version string
	var secret1ID string
	var secret1Version string
	var projectID string
	var url string
	err := godotenv.Load("./conf.env")
	if err != nil {
		log.Fatal("error loading .env file")
	}
	secretLocation := os.Getenv("SECRET_STORE")
	if secretLocation == "GCP" {
		projectID = os.Getenv("PROJECT_ID")
		secret0ID = os.Getenv("SECRET_ID_1")
		secret0Version = os.Getenv("SECRET_VERSION_1")
		secret1ID = os.Getenv("SECRET_ID_2")
		secret1Version = os.Getenv("SECRET_VERSION_2")
		url = os.Getenv("TOKEN_URL")
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
		log.Printf("Token: %v\nExpires in: %v", BearerToken, expiry)
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
		log.Printf("Token: %v\nExpires in: %v", BearerToken, expiry)
		d := time.Duration(expiry)
		time.Sleep(d * time.Second)
	}
}
