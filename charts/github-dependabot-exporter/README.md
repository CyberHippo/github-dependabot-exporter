# GitHub Dependabot Alerts Exporter Helm Chart

This Helm chart deploys the [GitHub Dependabot Alerts Prometheus Exporter](https://github.com/CyberHippo/github-dependabot-exporter) as a Kubernetes Deployment, exposing metrics for Prometheus.

## Configuration

| Parameter                       | Description                                                    | Default                |
|----------------------------------|----------------------------------------------------------------|------------------------|
| `image.repository`               | Container image repository                                     | `ghcr.io/cyberhippo/github-dependabot-exporter` |
| `image.tag`                      | Image tag                                                      | `latest`               |
| `image.pullPolicy`               | Image pull policy                                              | `IfNotPresent`         |
| `replicaCount`                   | Number of replicas                                             | 1                      |
| `service.port`                   | Service port                                                   | 8080                   |
| `env`                            | Extra environment variables (see below)                        | `{}`                   |
| `resources`                      | Resource requests/limits                                       | `{}`                   |
| `nodeSelector`                   | Node selector                                                  | `{}`                   |
| `tolerations`                    | Tolerations                                                    | `[]`                   |
| `affinity`                       | Affinity rules                                                 | `{}`                   |

### Authentication

You must provide the required [environment variables](../../README.md#configure) for either PAT or GitHub App authentication (see below).

#### Example for PAT:

```yaml
env:
  GITHUB_ORG: "my-org"
  GITHUB_AUTH_MODE: "pat"
  GITHUB_TOKEN: "<your-token>"
```

#### Example for GitHub App:

```yaml
env:
  GITHUB_ORG: "my-org"
  GITHUB_AUTH_MODE: "app"
  GITHUB_APP_ID: "1234"
  GITHUB_APP_INSTALLATION_ID: "5678"
  GITHUB_APP_PRIVATE_KEY_PATH: "/etc/github-app/private-key.pem"
extraVolumeMounts:
  - name: github-app-key
    mountPath: /etc/github-app
    readOnly: true
extraVolumes:
  - name: github-app-key
    secret:
      secretName: github-app-private-key
```

## ServiceMonitor

If you use [Prometheus Operator](https://github.com/prometheus-operator/prometheus-operator), enable the `serviceMonitor.enabled` value to automatically create a ServiceMonitor.

## Usage

```sh
helm repo add cyberhippo https://cyberhippo.github.io/github-dependabot-exporter/
helm install github-dependabot-exporter cyberhippo/github-dependabot-exporter
```

---
