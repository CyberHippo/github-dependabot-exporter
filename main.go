package main

import (
	"context"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/go-github/v57/github"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/robfig/cron/v3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
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

const (
	AuthPAT       = "pat"
	AuthGitHubApp = "app"
)

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

	// Create a GitHub client with JWT token for app authentication
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: jwtToken})
	tc := oauth2.NewClient(context.Background(), ts)
	client := github.NewClient(tc)

	// Get installation access token
	token, _, err := client.Apps.CreateInstallationToken(context.Background(), installationID, &github.InstallationTokenOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get installation token: %v", err)
	}

	return token.GetToken(), nil
}

func fetchAllRepos(ctx context.Context, client *github.Client, org string) ([]*github.Repository, error) {
	var allRepos []*github.Repository

	opt := &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}

	for {
		repos, resp, err := client.Repositories.ListByOrg(ctx, org, opt)
		if err != nil {
			log.Errorf("failed to fetch repos: %v", err)
			return nil, err
		}

		allRepos = append(allRepos, repos...)

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return allRepos, nil
}

func fetchDependabotAlertsForRepo(ctx context.Context, client *github.Client, org, repo string) ([]*github.DependabotAlert, error) {
	log.Debugf("Fetching alerts for %s/%s", org, repo)
	var allAlerts []*github.DependabotAlert

	opt := &github.ListAlertsOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}

	for {
		alerts, resp, err := client.Dependabot.ListRepoAlerts(ctx, org, repo, opt)
		if err != nil {
			// Check if it's a 404 error (repo doesn't have dependabot enabled)
			if ghErr, ok := err.(*github.ErrorResponse); ok && ghErr.Response.StatusCode == 404 {
				log.Debugf("Repository %s/%s doesn't have Dependabot enabled or accessible", org, repo)
				break
			}
			log.Errorf("failed to fetch dependabot alerts for %s/%s: %v", repo, org, err)
			return nil, err
		}

		allAlerts = append(allAlerts, alerts...)

		if resp.NextPage == 0 {
			break
		}
		opt.ListOptions.Page = resp.NextPage
	}

	return allAlerts, nil
}

func updateMetrics(org string, client *github.Client) {
	ctx := context.Background()
	repos, err := fetchAllRepos(ctx, client, org)
	if err != nil {
		log.Errorf("Error fetching repos: %v", err)
		return
	}

	log.Infof("Found %d repos in org %s", len(repos), org)

	for _, repo := range repos {
		repoName := repo.GetName()
		alerts, err := fetchDependabotAlertsForRepo(ctx, client, org, repoName)
		if err != nil {
			log.Warnf("Error fetching dependabot alerts for %s: %v", repoName, err)
			continue
		}

		counts := map[string]map[string]int{}
		for _, alert := range alerts {
			sev := alert.SecurityAdvisory.GetSeverity()
			state := alert.GetState()
			if counts[sev] == nil {
				counts[sev] = map[string]int{}
			}
			counts[sev][state]++
		}

		for severity, states := range counts {
			for state, count := range states {
				alertsGauge.WithLabelValues(repoName, severity, state).Set(float64(count))
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

func createGitHubClient(token string) *github.Client {
	if token == "" {
		// Return client without authentication
		return github.NewClient(nil)
	}

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(context.Background(), ts)
	return github.NewClient(tc)
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
		log.Fatal("GITHUB_ORG and GITHUB_AUTH_MODE must be set")
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
			log.Fatalf("GitHub App auth failed: %v", err)
		}
	default:
		log.Fatalf("Unknown GITHUB_AUTH_MODE: %s", authMode)
	}

	// Create GitHub client
	client := createGitHubClient(token)

	// Register Prometheus metrics
	prometheus.MustRegister(alertsGauge)

	// Initial fetch
	go updateMetrics(org, client)

	c := cron.New()
	_, err = c.AddFunc(schedule, func() {
		log.Info("Refreshing metrics.")
		updateMetrics(org, client)
	})
	if err != nil {
		log.Fatalf("Failed to schedule cron: %v", err)
	}
	c.Start()

	addr := fmt.Sprintf(":%s", listenPort)
	http.Handle("/metrics", promhttp.Handler())
	log.Infof("Exporter running on %s/metrics", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
