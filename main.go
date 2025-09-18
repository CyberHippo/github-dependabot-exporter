package main

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/robfig/cron/v3"
)

var (
	alertsGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "github_dependabot_alerts",
			Help: "Number of open Dependabot alerts per repository, severity, and state",
		},
    []string{"repo", "severity", "state"},
	)
)

type Repo struct {
	Name string `json:"name"`
}

type DependabotAlert struct {
	State string `json:"state"`
	SecurityAdvisory  struct {
		Severity string `json:"severity"`
	} `json:"security_advisory"`
}

const (
	AuthPAT       = "pat"
	AuthGitHubApp = "app"
)

// --- GitHub App Auth ---
func getAppJWT(appID int64, privateKey *rsa.PrivateKey) (string, error) {
	now := time.Now()
	claims := jwt.StandardClaims{
		IssuedAt:  now.Unix() - 60,
		ExpiresAt: now.Add(time.Minute * 10).Unix(),
		Issuer:    strconv.FormatInt(appID, 10),
	}
	j := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return j.SignedString(privateKey)
}

func loadPrivateKeyFromFile(path string) (*rsa.PrivateKey, error) {
	keyBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.New("invalid PEM private key")
	}
	return jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
}

func getInstallationToken(appID, installationID int64, privateKeyPath string) (string, error) {
	privateKey, err := loadPrivateKeyFromFile(privateKeyPath)
	if err != nil {
		return "", err
	}
	jwtToken, err := getAppJWT(appID, privateKey)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("https://api.github.com/app/installations/%d/access_tokens", installationID)
	req, _ := http.NewRequest("POST", url, nil)
	req.Header.Add("Authorization", "Bearer "+jwtToken)
	req.Header.Add("Accept", "application/vnd.github+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get installation token: %s", string(body))
	}
	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.Token, nil
}

func fetchAllRepos(ctx context.Context, httpClient *http.Client, org, token string) ([]Repo, error) {
	var allRepos []Repo
	page := 1
	for {
		url := fmt.Sprintf("https://api.github.com/orgs/%s/repos?per_page=100&page=%d", org, page)
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		req.Header.Set("Accept", "application/vnd.github+json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("failed to fetch repos: %s", string(body))
		}
		var repos []Repo
		if err := json.NewDecoder(resp.Body).Decode(&repos); err != nil {
			return nil, err
		}
		if len(repos) == 0 {
			break
		}
		allRepos = append(allRepos, repos...)
		page++
	}
	return allRepos, nil
}

func fetchDependabotAlertsForRepo(ctx context.Context, httpClient *http.Client, org, repo, token string) ([]DependabotAlert, error) {
	log.Debugf("Fetching alerts for repo %s in org %s", repo, org)
	var allAlerts []DependabotAlert
	page := 1
	for {
		url := fmt.Sprintf("https://api.github.com/repos/%s/%s/dependabot/alerts?per_page=100&page=%d", org, repo, page)
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		req.Header.Set("Accept", "application/vnd.github+json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode == 404 {
			// Repo probably doesn't have dependabot enabled
			break
		}
		if resp.StatusCode != 200 {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("Failed to fetch dependabot alerts for %s: %s", repo, string(body))
		}
		var alerts []DependabotAlert
		if err := json.NewDecoder(resp.Body).Decode(&alerts); err != nil {
			return nil, err
		}
		if len(alerts) == 0 {
			break
		}
		allAlerts = append(allAlerts, alerts...)
		page++
	}
	return allAlerts, nil
}

func updateMetrics(org string, httpClient *http.Client, token string) {
	ctx := context.Background()
	repos, err := fetchAllRepos(ctx, httpClient, org, token)
	if err != nil {
		log.Errorf("Error fetching repos: %v", err)
		return
	}
	log.Infof("Found %d repos in org %s", len(repos), org)
	for _, repo := range repos {
		alerts, err := fetchDependabotAlertsForRepo(ctx, httpClient, org, repo.Name, token)
		if err != nil {
			log.Warnf("Error fetching dependabot alerts for %s: %v", repo.Name, err)
			continue
		}
    counts := map[string]map[string]int{}
    for _, alert := range alerts {
        sev := alert.SecurityAdvisory.Severity
        state := alert.State
        if counts[sev] == nil {
            counts[sev] = map[string]int{}
        }
        counts[sev][state]++
    }
    for severity, states := range counts {
        for state, count := range states {
            alertsGauge.WithLabelValues(repo.Name, severity, state).Set(float64(count))
        }
    }
	}
}

func getenv(key, fallback string) string {
	value := os.Getenv(key)
	if len(value) == 0 {
		return fallback
	}
	return value
}

func main() {
	// Configure logger
	log.SetFormatter(&log.JSONFormatter{})
	logLevelEnv := strings.ToLower(getenv("LOG_LEVEL", ""))
	level := log.InfoLevel
	parsedLogLevel, err := log.ParseLevel(logLevelEnv)
	if err == nil {
		level = parsedLogLevel
	} else {
		log.Warnf("Invalid LOG_LEVEL '%s', defaulting to Info level", logLevelEnv)
	}
	log.SetLevel(level)

  listenPort := getenv("LISTEN_PORT", "8080")
  org := getenv("GITHUB_ORG", "")
  authMode := getenv("GITHUB_AUTH_MODE", "")
	schedule := getenv("CRON_SCHEDULE", "0 0 * * *")
	log.Infof("Refreshing metrics scheduled at %s", schedule)
	if org == "" || authMode == "" {
		log.Error("GITHUB_ORG and GITHUB_AUTH_MODE must be set")
	}

	var token string

	switch authMode {
	case AuthPAT:
		token = os.Getenv("GITHUB_TOKEN")
		if token == "" {
			log.Fatal("GITHUB_TOKEN must be set for personal access token auth")
		}
	case AuthGitHubApp:
		appID, err := strconv.ParseInt(os.Getenv("GITHUB_APP_ID"), 10, 64)
		installationID, err2 := strconv.ParseInt(os.Getenv("GITHUB_APP_INSTALLATION_ID"), 10, 64)
		privateKeyPath := os.Getenv("GITHUB_APP_PRIVATE_KEY_PATH")
		if err != nil || err2 != nil || privateKeyPath == "" {
			log.Fatal("GITHUB_APP_ID, GITHUB_APP_INSTALLATION_ID, and GITHUB_APP_PRIVATE_KEY_PATH must be set for app auth")
		}
		token, err = getInstallationToken(appID, installationID, privateKeyPath)
		if err != nil {
			log.Errorf("GitHub App auth failed: %v", err)
		}
	default:
		log.Errorf("Unknown GITHUB_AUTH_MODE: %s", authMode)
	}

	// Register Prometheus metrics
	prometheus.MustRegister(alertsGauge)

	httpClient := &http.Client{Timeout: 10 * time.Second}

	// Initial fetch
	go updateMetrics(org, httpClient, token)

	c := cron.New()
	_, err = c.AddFunc(schedule, func() {
		log.Info("Refreshing metrics.")
		updateMetrics(org, httpClient, token)
	})
	if err != nil {
		log.Fatalf("Failed to schedule cron: %v", err)
	}
	c.Start()

  addr := fmt.Sprintf(":%s", listenPort)
	http.Handle("/metrics", promhttp.Handler())
  log.Infof("Exporter running on :%s/metrics", addr)
  log.Fatal(http.ListenAndServe(addr, nil))

}
