# GitHub Dependabot Alerts Prometheus Exporter

This exporter fetches [Dependabot alerts](https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts) for all repositories in a GitHub organization and exposes metrics per repository, severity, and state for consumption by [Prometheus](https://prometheus.io/).

## Features

- Aggregates Dependabot alerts across all repositories in a GitHub organization.
- Exposes metrics by repository, severity, and alert state.
- Supports authentication via GitHub Personal Access Token **or** GitHub App.
- Metrics refreshed automatically every day at midnight (UTC).
- Lightweight, single binary.

## Metrics

The exporter exposes the following metric:

```
github_dependabot_alerts{repo="repo-name",severity="high",state="open"} 4
```

- **repo**: The repository name.
- **severity**: The alert severity (`critical`, `high`, `medium`, `low`).
- **state**: The alert state (`open`, `fixed`, `dismissed`, etc.).
- **value**: Number of alerts matching the labels.

## Getting Started

### 1. Build

```sh
go build -o dependabot-prometheus-exporter
```

### 2. Configure

Set the following environment variables:
#### General configuration

- `LOG_LEVEL`: (Opt.) The log level, defaults to `info`.
- `LISTEN_PORT`: (Opt.) The port on which the exporter will expose its metrics, defaults to `9090`.
- `GITHUB_ORG`: The name of your GitHub organization.

#### For Personal Access Token

- `GITHUB_AUTH_MODE`: `pat`
- `GITHUB_TOKEN`: A GitHub Personal Access Token with `repo` and `security_events` read access.

#### For GitHub App

- `GITHUB_AUTH_MODE`: `app`
- `GITHUB_APP_ID`: The ID of your GitHub App (numeric).
- `GITHUB_APP_INSTALLATION_ID`: The installation ID for your org.
- `GITHUB_APP_PRIVATE_KEY_PATH`: Path to your GitHub App private key (PEM file).

### 3. Run

```sh
./dependabot-prometheus-exporter
```

Metrics will be available at:  
[http://localhost:9090/metrics](http://localhost:9090/metrics)

### 4. Prometheus Scrape Config Example

```yaml
scrape_configs:
  - job_name: 'dependabot-prometheus-exporter'
    static_configs:
      - targets: ['localhost:9090']
```

---

## Example Metric Output

```
# HELP github_dependabot_alerts Number of Dependabot alerts per repository, severity, and state
# TYPE github_dependabot_alerts gauge
github_dependabot_alerts{repo="my-repo",severity="high",state="open"} 2
github_dependabot_alerts{repo="my-repo",severity="medium",state="fixed"} 1
github_dependabot_alerts{repo="another-repo",severity="low",state="open"} 1
```

---

## Development

- Requires Go 1.24+.
- Run tests with:

```sh
go test
```

## Security

- The exporter requires read access to Dependabot alerts in your organization.
- Store your tokens/keys securely and limit their permissions as much as possible.

---

## License

MIT

---

## Credits

- [Prometheus Go client](https://github.com/prometheus/client_golang)
- [robfig/cron](https://github.com/robfig/cron)
- [sirupsen/logrus](https://github.com/sirupsen/logrus)
