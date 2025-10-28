package main

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/pbkdf2"
	"gopkg.in/yaml.v3"
)

const PBIN_URL = "https://privatebin.net"
const CUSTOM_MESSAGE = "Here are the new AWS credentials:"

var b64Encoding = base64.StdEncoding

func generateStrongPassword(length int) (string, error) {
	if length < 12 {
		length = 12
	}
	lower := "abcdefghijklmnopqrstuvwxyz"
	upper := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits := "0123456789"
	symbols := "!@#$%^&*()-_=+[]{}:,.?/"
	all := lower + upper + digits + symbols

	pick := func(set string) (byte, error) {
		b := make([]byte, 1)
		if _, err := rand.Read(b); err != nil {
			return 0, err
		}
		return set[int(b[0])%len(set)], nil
	}
	var out []byte
	for _, set := range []string{lower, upper, digits, symbols} {
		ch, err := pick(set)
		if err != nil {
			return "", err
		}
		out = append(out, ch)
	}
	for len(out) < length {
		ch, err := pick(all)
		if err != nil {
			return "", err
		}
		out = append(out, ch)
	}
	for i := len(out) - 1; i > 0; i-- {
		b := make([]byte, 1)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		j := int(b[0]) % (i + 1)
		out[i], out[j] = out[j], out[i]
	}
	return string(out), nil
}

type Config struct {
	PrivateBinURL         string `yaml:"privatebin_url"`
	Expire                string `yaml:"expire"`
	Burn                  int    `yaml:"burn"`
	OpenDiscussion        int    `yaml:"opendiscussion"`
	Format                string `yaml:"format"`
	CustomMessage         string `yaml:"custom_message"`
	UsernamePrefix        string `yaml:"username_prefix"`
	UserPath              string `yaml:"user_path"`
	PasswordLength        int    `yaml:"password_length"`
	PasswordResetRequired bool   `yaml:"password_reset_required"`
	CreateConsoleLogin    bool   `yaml:"create_console_login"`
	CreateAccessKey       bool   `yaml:"create_access_key"`
	Region                string `yaml:"region"`
	Compression           string `yaml:"compression"`
}

func defaultConfig() Config {
	return Config{
		PrivateBinURL:         PBIN_URL,
		Expire:                "1day",
		Burn:                  1,
		OpenDiscussion:        0,
		Format:                "plaintext",
		CustomMessage:         CUSTOM_MESSAGE,
		UsernamePrefix:        "",
		UserPath:              "",
		PasswordLength:        20,
		PasswordResetRequired: false,
		CreateConsoleLogin:    true,
		CreateAccessKey:       true,
		Compression:           "none",
	}
}

func loadConfig() Config {
	path := os.Getenv("IAMGEN_CONFIG")
	if path == "" {
		path = "config.yaml"
	}
	cfg := defaultConfig()
	if b, err := os.ReadFile(path); err == nil {
		_ = yaml.Unmarshal(b, &cfg)
	}
	return cfg
}

func normalizePrivateBinExpire(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	if s == "" {
		return "1day"
	}
	allowed := map[string]bool{
		"5min": true, "10min": true, "1hour": true, "1day": true,
		"1week": true, "1month": true, "1year": true, "never": true,
	}
	if allowed[s] {
		return s
	}
	switch s {
	case "7days", "7d", "oneweek", "7 days":
		return "1week"
	case "24h", "24hours", "1d", "one day", "1 day":
		return "1day"
	case "1 w", "1 wk", "1 weeks":
		return "1week"
	case "hour", "1 hr", "1 h":
		return "1hour"
	default:
		return "1day"
	}
}

func expireToHumanReadable(expire string) string {
	switch expire {
	case "5min":
		return "5 minutes"
	case "10min":
		return "10 minutes"
	case "1hour":
		return "1 hour"
	case "1day":
		return "1 day"
	case "1week":
		return "1 week"
	case "1month":
		return "1 month"
	case "1year":
		return "1 year"
	case "never":
		return "never"
	default:
		return "1 day"
	}
}

func normalizePrivateBinFormat(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	switch s {
	case "plaintext", "text", "plain":
		return "plaintext"
	case "markdown", "md":
		return "markdown"
	case "syntaxhighlighting", "code", "syntax":
		return "syntaxhighlighting"
	default:
		return "plaintext"
	}
}

func normalizeCompression(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	switch s {
	case "zlib", "none":
		return s
	default:
		return "none"
	}
}

func rollbackResources(ctx context.Context, iamClient *iam.Client, userName string, createdUser bool, accessKeyIds []string) {
	for _, keyId := range accessKeyIds {
		_, _ = iamClient.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{UserName: &userName, AccessKeyId: &keyId})
	}
	if createdUser {
		_, _ = iamClient.DeleteUser(ctx, &iam.DeleteUserInput{UserName: &userName})
	}
}

func parseAWSCredsFromCSV(path string) (string, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	r := csv.NewReader(f)
	rows, err := r.ReadAll()
	if err != nil {
		return "", "", err
	}
	if len(rows) < 2 {
		return "", "", fmt.Errorf("csv must have header and at least one data row")
	}
	header := rows[0]
	var idxAK, idxSK = -1, -1
	for i, h := range header {
		key := strings.ToLower(strings.TrimSpace(h))
		switch key {
		case "access key id", "access key id:":
			idxAK = i
		case "secret access key", "secret access key:":
			idxSK = i
		}
	}
	if idxAK == -1 || idxSK == -1 {
		for i, h := range header {
			key := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(h), "  ", " "))
			if idxAK == -1 && strings.Contains(key, "access key id") {
				idxAK = i
			}
			if idxSK == -1 && strings.Contains(key, "secret access key") {
				idxSK = i
			}
		}
	}
	if idxAK == -1 || idxSK == -1 {
		return "", "", fmt.Errorf("could not find Access Key ID/Secret AccessKey columns in CSV header")
	}
	data := rows[1]
	if idxAK >= len(data) || idxSK >= len(data) {
		return "", "", fmt.Errorf("csv columns out of range")
	}
	return strings.TrimSpace(data[idxAK]), strings.TrimSpace(data[idxSK]), nil
}

type PrivateBinRequest struct {
	V     int   `json:"v"`
	AData []any `json:"adata"`
	Meta  struct {
		Expire string `json:"expire"`
	} `json:"meta"`
	CT string `json:"ct"`
}

type PrivateBinResponse struct {
	Status   int    `json:"status"`
	ID       string `json:"id"`
	URL      string `json:"url"`
	Delete   string `json:"deletetoken"`
	Password string `json:"bs58key"`
	Message  string `json:"message"`
}

type PBSpec struct {
	IV          string `json:"iv"`
	Salt        string `json:"salt"`
	Iterations  int    `json:"iterations"`
	KeySize     int    `json:"keysize"`
	TagSize     int    `json:"tagsize"`
	Algorithm   string `json:"algorithm"`
	Mode        string `json:"mode"`
	Compression string `json:"compression"`
}

type PBAData struct {
	Spec             PBSpec `json:"spec"`
	Formatter        string `json:"formatter"`
	OpenDiscussion   bool   `json:"opendiscussion"`
	BurnAfterReading bool   `json:"burnafterreading"`
}

func createPrivateBinPaste(ctx context.Context, pasteURL *url.URL, textData []byte, cfg Config) (string, error) {
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		return "", fmt.Errorf("failed to generate master key: %w", err)
	}

	// Wrap the paste content in JSON format as PrivateBin expects
	pasteContent := map[string]string{
		"paste": string(textData),
	}
	pasteJSON, err := json.Marshal(pasteContent)
	if err != nil {
		return "", fmt.Errorf("failed to marshal paste content: %w", err)
	}

	var dataToEncrypt []byte
	compressionType := normalizeCompression(cfg.Compression)
	if compressionType == "zlib" {
		var b bytes.Buffer
		w := zlib.NewWriter(&b)
		if _, err := w.Write(pasteJSON); err != nil {
			return "", fmt.Errorf("failed to compress data: %w", err)
		}
		w.Close()
		dataToEncrypt = b.Bytes()
	} else {
		dataToEncrypt = pasteJSON
	}

	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("failed to generate iv: %w", err)
	}

	iterations := 600000
	keySize := 32
	derivedKey := pbkdf2.Key(masterKey, salt, iterations, keySize, sha256.New)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	b64Salt := b64Encoding.EncodeToString(salt)
	b64IV := b64Encoding.EncodeToString(iv)

	// Spec must be an array, not an object
	specArray := [8]any{
		b64IV,
		b64Salt,
		iterations,
		keySize * 8,
		128,
		"aes",
		"gcm",
		compressionType,
	}

	// OpenDiscussion and Burn must be integers (0 or 1), not booleans
	openDiscussionInt := 0
	if cfg.OpenDiscussion != 0 {
		openDiscussionInt = 1
	}
	burnInt := 0
	if cfg.Burn != 0 {
		burnInt = 1
	}

	adataArray := [4]any{
		specArray,
		normalizePrivateBinFormat(cfg.Format),
		openDiscussionInt,
		burnInt,
	}

	adataJSON, err := json.Marshal(adataArray)
	if err != nil {
		return "", fmt.Errorf("failed to marshal adata: %w", err)
	}

	ciphertext := aesgcm.Seal(nil, iv, dataToEncrypt, adataJSON)

	b64CT := b64Encoding.EncodeToString(ciphertext)

	reqPayload := PrivateBinRequest{
		V:     2,
		AData: adataArray[:],
		Meta: struct {
			Expire string `json:"expire"`
		}{Expire: normalizePrivateBinExpire(cfg.Expire)},
		CT: b64CT,
	}

	jsonPayload, err := json.Marshal(reqPayload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", pasteURL.String(), bytes.NewBuffer(jsonPayload))
	if err != nil {
		return "", fmt.Errorf("failed to create API request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Requested-With", "JSONHttpRequest")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read API response: %w", err)
	}

	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var pbResp PrivateBinResponse
	if err := json.Unmarshal(body, &pbResp); err != nil {
		return "", fmt.Errorf("failed to parse API response JSON: %w. Body: %s", err, string(body))
	}

	if pbResp.Status != 0 {
		return "", fmt.Errorf("privatebin server error: %s", pbResp.Message)
	}

	b58Key := base58.Encode(masterKey)

	relativeURL, err := url.Parse(pbResp.URL)
	if err != nil {
		return "", fmt.Errorf("failed to parse relative URL from API (%s): %w", pbResp.URL, err)
	}

	finalURL := pasteURL.ResolveReference(relativeURL)
	finalURL.Fragment = b58Key

	return finalURL.String(), nil
}

func main() {
	log.SetFlags(0)
	ctx := context.Background()

	var cliUsername string
	var cliConsole bool
	var cliProgram bool
	var cliCSV string
	var cliPath string
	flag.StringVar(&cliUsername, "u", "", "username to create")
	flag.BoolVar(&cliConsole, "c", false, "create console login (password)")
	flag.BoolVar(&cliProgram, "p", false, "create programmatic access (access key)")
	flag.StringVar(&cliCSV, "csv", "", "path to AWS credentials CSV (overrides env/profile)")
	flag.StringVar(&cliPath, "path", "", "IAM user path (overrides YAML user_path)")
	flag.Parse()

	flagPassed := func(name string) bool {
		set := false
		flag.Visit(func(f *flag.Flag) {
			if f.Name == name {
				set = true
			}
		})
		return set
	}

	appCfg := loadConfig()
	appCfg.Expire = normalizePrivateBinExpire(appCfg.Expire)
	appCfg.Format = normalizePrivateBinFormat(appCfg.Format)
	appCfg.Compression = normalizeCompression(appCfg.Compression)
	userName := cliUsername
	if userName == "" {
		if appCfg.UsernamePrefix != "" {
			userName = fmt.Sprintf("%s%d", appCfg.UsernamePrefix, time.Now().Unix())
		} else {
			log.Fatalf("username is required. Provide -u or set username_prefix to generate one")
		}
	}
	if flagPassed("c") || flagPassed("p") {
		appCfg.CreateConsoleLogin = cliConsole
		appCfg.CreateAccessKey = cliProgram
	}
	if flagPassed("path") {
		appCfg.UserPath = cliPath
	}

	var cfgOpts []func(*config.LoadOptions) error
	if appCfg.Region != "" {
		cfgOpts = append(cfgOpts, config.WithRegion(appCfg.Region))
	}
	if cliCSV != "" {
		ak, sk, err := parseAWSCredsFromCSV(cliCSV)
		if err != nil {
			log.Fatalf("Failed to read CSV credentials: %v", err)
		}
		cfgOpts = append(cfgOpts, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(ak, sk, "")))
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, cfgOpts...)
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}
	iamClient := iam.NewFromConfig(awsCfg)

	log.Printf("Creating user: %s", userName)
	createdUser := false
	createUserInput := &iam.CreateUserInput{UserName: &userName}
	if appCfg.UserPath != "" {
		createUserInput.Path = &appCfg.UserPath
	}
	_, err = iamClient.CreateUser(ctx, createUserInput)
	if err != nil {
		var alreadyExists *types.EntityAlreadyExistsException
		if !errors.As(err, &alreadyExists) {
			log.Fatalf("Failed to create user: %v", err)
		}
		log.Println("User already exists. Continuing.")
	} else {
		createdUser = true
	}

	var credentialsLines []string
	var pendingConsolePassword string
	if appCfg.CreateConsoleLogin {
		pw, err := generateStrongPassword(appCfg.PasswordLength)
		if err != nil {
			log.Fatalf("Failed to generate password: %v", err)
		}
		pendingConsolePassword = pw
		credentialsLines = append(credentialsLines,
			fmt.Sprintf("Console Username: %s", userName),
			fmt.Sprintf("Console Password: %s", pw),
		)
	}

	var createdAccessKeyIds []string
	if appCfg.CreateAccessKey {
		log.Println("Creating access key...")
		keyOut, err := iamClient.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: &userName})
		if err != nil {
			log.Fatalf("Failed to create access key: %v", err)
		}
		credentialsLines = append(credentialsLines,
			fmt.Sprintf("AccessKeyId: %s", *keyOut.AccessKey.AccessKeyId),
			fmt.Sprintf("SecretAccessKey: %s", *keyOut.AccessKey.SecretAccessKey),
		)
		createdAccessKeyIds = append(createdAccessKeyIds, *keyOut.AccessKey.AccessKeyId)
	}

	if len(credentialsLines) == 0 {
		log.Fatalf("No credentials generated. Enable at least one of create_console_login or create_access_key in config.")
	}

	credentialsText := strings.Join(credentialsLines, "\n")

	log.Println("Sending to PrivateBin...")
	u, err := url.Parse(appCfg.PrivateBinURL)
	if err != nil {
		rollbackResources(ctx, iamClient, userName, createdUser, createdAccessKeyIds)
		log.Fatalf("Invalid PrivateBin URL: %v", err)
	}

	// Ensure URL ends with / for the API endpoint
	if !strings.HasSuffix(u.Path, "/") {
		if u.Path == "" {
			u.Path = "/"
		} else {
			u.Path = u.Path + "/"
		}
	}

	fullLink, err := createPrivateBinPaste(ctx, u, []byte(credentialsText), appCfg)
	if err != nil {
		rollbackResources(ctx, iamClient, userName, createdUser, createdAccessKeyIds)
		log.Fatalf("PrivateBin create failed: %v", err)
	}

	if appCfg.CreateConsoleLogin {
		log.Println("Creating login profile (console password)...")
		reset := appCfg.PasswordResetRequired
		_, err = iamClient.CreateLoginProfile(ctx, &iam.CreateLoginProfileInput{
			UserName:              &userName,
			Password:              &pendingConsolePassword,
			PasswordResetRequired: reset,
		})
		if err != nil {
			var alreadyExists *types.EntityAlreadyExistsException
			if errors.As(err, &alreadyExists) {
				log.Println("Login profile exists. Updating password...")
				_, err = iamClient.UpdateLoginProfile(ctx, &iam.UpdateLoginProfileInput{
					UserName:              &userName,
					Password:              &pendingConsolePassword,
					PasswordResetRequired: aws.Bool(reset),
				})
				if err != nil {
					log.Fatalf("Failed to update login profile: %v", err)
				}
			} else {
				log.Fatalf("Failed to create login profile: %v", err)
			}
		}
	}

	fmt.Println("---")
	fmt.Printf("Subject: New AWS Credentials for %s\n\n", userName)
	fmt.Println("Hello,")
	fmt.Println(appCfg.CustomMessage)

	expireText := expireToHumanReadable(appCfg.Expire)
	if expireText == "never" {
		fmt.Println("This link will never expire and can only be viewed once.")
	} else {
		fmt.Printf("This link will expire in %s and can only be viewed once.\n", expireText)
	}

	fmt.Println(fullLink)
	fmt.Println("\n---")
}
