# Web Log Security Analyzer

A stateless Flask dashboard that parses bounded Apache/Nginx access-log samples and produces explainable, rule-based security findings. It is designed for the B9IS121 CI/CD Automation and Cloud Deployment assessment.

## Features

- Parses Apache/Nginx common and combined access-log formats.
- Summarises methods, HTTP outcomes, source counts and popular paths.
- Detects repeated authentication failures, path enumeration, sensitive-resource probes, scanner user agents, unusual HTTP methods, traversal, SQL-injection and XSS patterns.
- Returns clear `200`, `400` and `413` API responses for Postman evidence.
- Stores no submitted logs and makes no external network calls.
- Exposes the built Git SHA through `/api/version` for deployment traceability.

## Run locally

```bash
python3 -m pip install --requirement requirements.txt
python3 -m unittest discover --start-directory tests --verbose
python3 app.py
```

Open `http://localhost:8080`.

## API

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Container health and version |
| `GET` | `/api/version` | Deployed commit SHA |
| `GET` | `/api/sample` | Synthetic demonstration logs |
| `POST` | `/api/analyse` | Analyse `{ "log_text": "..." }` |

Example:

```bash
curl --request POST http://localhost:8080/api/analyse \
  --header 'Content-Type: application/json' \
  --data '{"log_text":"198.51.100.10 - - [25/Nov/2026:10:00:01 +0000] \"GET / HTTP/1.1\" 200 4210 \"-\" \"Mozilla/5.0\""}'
```

## Docker

```bash
docker build --build-arg APP_VERSION=local-demo --tag web-log-security-analyzer:local .
docker run --rm --publish 8080:8080 web-log-security-analyzer:local
```

The image runs as a non-root user and reads Render's `PORT` environment variable.

## CI/CD configuration

The workflow in `.github/workflows/deploy.yml` tests, builds and smoke-tests every change. On a push to `main`, it publishes commit-SHA and `latest` tags to GHCR. It also publishes to Amazon ECR when the following repository settings exist:

| Type | Name | Purpose |
| --- | --- | --- |
| Secret | `AWS_ROLE_ARN` | Branch-scoped GitHub OIDC role |
| Variable | `AWS_REGION` | ECR region |
| Variable | `ECR_REPOSITORY` | ECR repository name |
| Secret | `RENDER_DEPLOY_HOOK_URL` | Starts the image-backed Render deployment |
| Variable | `PUBLIC_APP_URL` | Live URL polled for the commit SHA |

See [the architecture](docs/architecture.md) for the complete flow.

## Postman

Import `postman_collection.json`, change the collection variable `baseUrl` to the Render URL, and send all requests. The invalid request is expected to return `400`; this demonstrates input validation rather than a failed test.

## Deliberate limitations

- Fixed signatures can produce false positives and false negatives.
- Only pasted batches of Apache/Nginx common or combined logs are supported.
- The service does not collect live logs, block traffic, enrich IP addresses or correlate multiple systems.
- Input is limited to 250 non-empty lines and 100 KB to bound public resource use.
- The tool is educational and does not replace a SIEM or professional incident investigation.
