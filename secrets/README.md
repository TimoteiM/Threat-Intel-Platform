# Host secrets / trust material for containers

Bind-mounted read-only into the backend containers. **Gitignored** — nothing in
here except this README is ever committed.

| File | Mounted at | Used by | Purpose |
|---|---|---|---|
| `cape-internal-ca.crt` | `/run/secrets/cape-internal-ca.crt` | `api`, `worker`, `beat` | Verifies the TLS certificate of the CAPE reverse proxy at `https://172.16.45.10:8443`. |

## cape-internal-ca.crt

The **public** certificate of the internal CA that signed the CAPE Nginx
certificate. It is not a private key and not a credential — it is the trust
anchor that lets `CAPE_VERIFY_TLS=true` succeed against an internally-issued
certificate, instead of the alternative of turning verification off.

Expected: PEM, beginning `-----BEGIN CERTIFICATE-----`.

```bash
install -m 0644 /path/to/cape-internal-ca.crt \
  /home/expert/apps/Threat-Intel-Platform/secrets/cape-internal-ca.crt
```

The CAPE API **token** does not belong here. It lives in `.env` as
`CAPE_API_TOKEN` and reaches the containers through `env_file`.

## Ordering matters

`docker-compose.yml` bind-mounts this file individually. Docker creates a
**directory** at the source path if the file is missing when a container is
created, and a directory called `cape-internal-ca.crt` then blocks the real
file from being copied in. So: copy the certificate first, recreate the
containers second.
