# Ziqx UAE e-Invoice Validator

A standalone, stateless HTTP API for technical validation of UAE PINT-AE Billing invoices and credit notes. It runs the pinned official UBL 2.1 schema closure and both compiled OpenPeppol PINT-AE 1.0.4 rule sets using Saxon HE 12.10.

This folder is ready for its own Git repository. Builds and runtime need no Tanseek checkout, database, PII keys, storage or backend image. The extraction does not initialize a repository or publish/deploy a service.

## Run locally

Docker and Python 3 are sufficient; Java is compiled inside the image:

```sh
cp .env.example .env
openssl rand -hex 32
```

Put the generated token in `EINVOICE_VALIDATOR_TOKEN`. For a local build, set `VALIDATOR_IMAGE=ziqx-ae-einvoice-validator:local` in `.env`, then run:

```sh
docker compose -f compose.yaml -f compose.build.yaml up -d --build --wait
curl --fail http://127.0.0.1:8091/v1/healthz
```

The independent Compose project uses a pinned HAProxy ingress on a loopback-only port. Only that ingress joins both the edge and private validation networks; the Java validator has no published port or outbound network. Both services use read-only filesystems, nonroot users, dropped capabilities and resource limits. Temporary validator storage is bounded. It shares no network or environment file with Tanseek. Change the host port with `VALIDATOR_BIND_PORT`.

## API

The full OpenAPI 3.1 contract is [openapi.yaml](openapi.yaml).

| Method | Path | Authentication | Result |
| --- | --- | --- | --- |
| GET | `/v1/healthz` | None | Pinned specification and manifest digest |
| POST | `/v1/validate` | Bearer service token | Document-bound validation report |

In a shell with the service token exported:

```sh
curl --fail-with-body http://127.0.0.1:8091/v1/validate \
  -H "Authorization: Bearer $EINVOICE_VALIDATOR_TOKEN" \
  -H 'Content-Type: application/xml' \
  -H 'X-Ziqx-Specification: pint-ae-1.0.4' \
  --data-binary @testdata/generated-invoice.xml
```

Completed validation returns HTTP 200 even for an invalid document. Check `valid`, `xsdValid`, `rulesExecuted` and `failedRules`. Validity requires XSD success, both rule executions and no failed assertions. Reports contain only specification/document/resource digests, schema status, rule count and safe rule IDs.

Requests require `application/xml`, no content encoding, at most 8 MiB, and the exact specification header. Authentication failure returns 401, unsupported content/encoding/specification 415, oversized bodies 413, and saturation or execution failure 503. DTDs, entities, external references and unsafe structural budgets produce an invalid report. Never treat unavailable validation as success. XML is not logged or retained after bounded worker execution.

Deprecated `/healthz` and `/validate` routes remain for existing clients. The latter uses `X-Wusooly-Specification`; new clients use `/v1/validate` with `X-Ziqx-Specification`.

## Independent releases and deployment

GitHub Actions checks source history, resource integrity, actual fixtures and isolation, then scans the exact tested validator and pinned ingress images for HIGH/CRITICAL vulnerabilities before registry login. Pull requests and main pushes verify without publishing. A `v*` Git tag or manual run with `publish=true` publishes `ghcr.io/<repository-owner>/ae-einvoice-validator` with `latest`, commit SHA and version tags where applicable.

Set `VALIDATOR_IMAGE` in the service's `.env` to the published image, preferably a reviewed digest, then run `docker compose pull` and `docker compose up -d --wait`. Provision a dedicated HTTPS origin with the host proxy in [Caddyfile.example](Caddyfile.example). Keep the container port on loopback. No domain, registry publication or production deployment is created automatically. Rotate tokens with authorized clients.

The pinned runtime installs `libexpat>=2.9.0-r0` and `brotli-libs>=1.2.1-r0`. The vulnerability gate remains mandatory; no suppression was added.

## Verification

```sh
python3 -B tests/test_package.py
python3 -B .github/scripts/test_security_scan.py
docker build -t ziqx-ae-einvoice-validator:validation .
python3 test.py
python3 test_compose.py
```

The runtime suite checks official examples and sixteen fixed generated invoice/credit fixtures inside a disposable network-disabled container. It exercises both API versions, rule/schema failures, entities, depth, body size, encoding, authentication, concurrency and denied header-only request availability. It uses public synthetic fixtures and removes its container afterward. `test_compose.py` separately starts a temporary Compose project, verifies real v1 and legacy requests through the loopback ingress, checks validator network isolation and removes the project.

Each request runs in a child JVM with a 384 MiB heap and 25-second deadline; two slots bound work. Original resources and notices remain in [resources/pint-ae-1.0.4](resources/pint-ae-1.0.4/README.md). Java verifies packaged manifest/archive hashes at startup. Specification updates require new versioned resources and deliberate API/client compatibility changes.

## Tanseek integration and future paid access

Tanseek retains an optional HTTP adapter. Set its `EINVOICE_VALIDATOR_URL` to the service HTTPS origin and `EINVOICE_VALIDATOR_TOKEN` to an authorized token when needed. Leave both blank while unused. Tanseek never builds or starts this service, and outages do not block startup or ordinary invoices. Its adapter checks document/specification/resource digests before accepting a validated package.

The current API has one server-to-server token. Paid public access under Ziqx will need per-customer keys, revocation, quotas, rate limits, metering, billing and support at a dedicated gateway; those features are not implemented here. This service performs technical Billing validation. It does not submit invoices, provide ASP registration, validate every UAE document type or certify regulatory compliance.
