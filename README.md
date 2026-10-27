Linode DDNS Server
==================

A small dockerized Go server that updates Linode DNS records. It works with router DDNS clients such as [inadyn](https://github.com/troglobit/inadyn).

## Motivation

Most routers come with a DDNS client, usually inadyn. These clients do not support Linode. They send GET requests, but the Linode API needs a PUT request to update a DNS record.

This server takes the client's GET request and makes the Linode API call itself. The Linode API token stays on the server and is never sent by the client.

## Configuration

See [`config.example.yaml`](config.example.yaml).

```yaml
listen: ":8080"            # optional, default :8080
tls:                       # optional; set both or neither
  cert_file: /config/cert.pem
  key_file: /config/key.pem
trusted_proxies: [127.0.0.1]   # optional; IPs/CIDRs whose X-Forwarded-For is trusted for logging
users:
  - username: "router"
    password_hash: "$2a$10$..."      # from `linode-ddns hash-password`
    linode_api_token: "..."          # needs Domains read/write
    domains:                         # required; hostnames this user may update
      - home.example.com
      - example.com
```

- Passwords are stored as bcrypt hashes. To generate one, run `echo -n 'pw' | linode-ddns hash-password`. You can also run `linode-ddns hash-password` and type the password at the prompt.
- Records are found by hostname. The server picks the token's Linode domain that is the longest suffix of the hostname, then finds the A or AAAA record with the matching name. Records must already exist in Linode. The server never creates them.
- Each user must list the exact hostnames it may update in `domains`. Other hostnames get `nohost`, even if the token can reach them.
- The server exits with an error if the file is missing, the YAML is malformed, or validation fails. Unknown fields are also rejected.

## Running

```sh
./linode-ddns --config=/path/to/linode-ddns.yaml [--listen=:8080]
```

### Docker

```sh
docker build -t linode-ddns .
chmod 600 linode-ddns.yaml
docker run -d -p 8080:8080 --user "$(id -u):$(id -g)" \
  -v "$PWD/linode-ddns.yaml:/config/linode-ddns.yaml:ro" linode-ddns
```

Bind-mount the config file to `/config/linode-ddns.yaml`. The image passes that path to the server automatically.

- The host path must be absolute (start with `/`, or use `$PWD/`). Docker treats a bare name such as `linode-ddns.yaml` as a named volume. It then mounts an empty directory, and the server exits with `read /config/linode-ddns.yaml: is a directory`.
- Inside the container, keep `listen` at `":8080"`. A `127.0.0.1` address there is unreachable from outside the container. To limit access to the host, publish the port with `-p 127.0.0.1:8080:8080` instead.
- The config file holds Linode API tokens, so keep it at mode `600`. The server logs a warning at startup when group or others can access it. `--user "$(id -u):$(id -g)"` runs the container as the file's owner so it can still read the file. Without `--user`, the image runs as its built-in non-root user, which cannot read a `600` file owned by you.
- To hash a password with the image:

```sh
docker run --rm -i linode-ddns hash-password
```

### Behind nginx

Run the server on plain HTTP bound to localhost and let nginx handle TLS:

```yaml
listen: "127.0.0.1:8080"
```

With Docker, keep `listen: ":8080"` in the config and publish the port on localhost only: `-p 127.0.0.1:8080:8080`.

```nginx
server {
    listen 443 ssl;
    server_name ddns.example.net;

    ssl_certificate     /etc/letsencrypt/live/ddns.example.net/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ddns.example.net/privkey.pem;

    location /v1/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

Notes:

- nginx forwards the `Authorization` and `Accept` headers by default, so basic auth and response negotiation work without extra configuration.
- To log the real client address instead of `127.0.0.1`, set `trusted_proxies` and send `X-Forwarded-For` from nginx as shown above:

  ```yaml
  trusted_proxies: [127.0.0.1, "::1"]
  ```

  With Docker, requests arrive from the Docker bridge gateway instead of `127.0.0.1`. Trust that address instead, for example `172.17.0.1`.

  The server reads `X-Forwarded-For` only when the request comes directly from a trusted proxy. It walks the header from right to left, skips trusted entries, and logs the first untrusted address. Entries a client adds at the left end are never used. The header affects logging only; DNS updates always use the `ip`/`ipv6` parameters.
- Some router clients cannot use HTTPS. For them, add a `listen 80;` server block with the same `location`. Basic auth credentials then travel in cleartext, so use a dedicated user whose `domains` list is limited to the router's hostnames.
- nginx access logs record the query string, which includes the hostname and IP. They do not record the password, because it is sent in the `Authorization` header.

## API

Both endpoints require HTTP basic authentication and accept only `GET`.

The response format depends on the `Accept` header:

- **JSON:** returned when `application/json` is preferred over `text/plain`. The body looks like `{"results":[{"type":"A","status":"good","ip":"1.2.3.4"}]}`. Errors include a `message` field.
- **Plain text:** returned in every other case, including `*/*` or a missing header. The body uses dyndns2 codes, one line per record.

| Code | HTTP | Meaning |
|---|---|---|
| `good <ip>` | 200 | Record updated |
| `nochg <ip>` | 200 | Record already had this IP |
| `badauth` | 401 | Missing or wrong credentials |
| `abuse` | 429 | Too many failed logins from this client; see `Retry-After` |
| `notfqdn` | 400 | `domain` missing or not a valid hostname |
| `badip` | 400 | `ip`/`ipv6` missing, wrong address family, or not unicast (loopback, link-local, multicast, broadcast, unspecified) |
| `nohost` | 404 | Hostname not allowed for this user, or no matching record |
| `911` | 502 | Linode API error (details in server log) |

If a request covers several records, the HTTP status comes from the first record that failed.

Failed logins are limited per client address (per /64 for IPv6). After 10 failures in a row, the client gets `abuse` until it regains an attempt, one per minute. Behind a reverse proxy, set `trusted_proxies`; otherwise every client shares the proxy's address and one client's failures lock out the others.

### `GET /v1/update?domain=<host>&ip=<ipv4>&ipv6=<ipv6>`

Updates the A record from `ip`, the AAAA record from `ipv6`, or both. At least one of the two is required.

### `GET /v1/status?domain=<host>`

Returns the current A and AAAA targets. Records that don't exist are left out. In plain text, each record is a line such as `A 1.2.3.4`. In JSON, each record has `"status":"ok"`. If neither record exists, the response is `nohost`.

## inadyn

```
custom linode {
    ssl            = false        # true if TLS is enabled on the server or a proxy
    ddns-server    = ddns.example.net
    ddns-path      = "/v1/update?domain=%h&ip=%i"
    ddns-response  = { good, nochg }
    username       = router
    password       = secret
    hostname       = home.example.com
}
```

By default, inadyn does not treat `nochg` as a success, so `ddns-response` must list it. `ddns-server` takes a hostname only. Serve on port 80 or 443, either directly with `listen` or behind a reverse proxy (see [Behind nginx](#behind-nginx)).

For IPv6, enable `allow-ipv6 = true`. Then add a second `custom` section with `ddns-path = "/v1/update?domain=%h&ipv6=%i"` and a checkip source that returns an IPv6 address.

## Development

```sh
make test                                   # go vet + go test -race
make bin                                    # local binary ./linode-ddns
make image                                  # local docker image linode-ddns:latest
make build                                  # all platforms, into the buildx cache
make push IMAGE=myuser/linode-ddns          # push :1.0.0 and :latest (docker login first)
make push IMAGE=myuser/linode-ddns VERSION=1.1.0
```

`build` and `push` use a buildx builder called `multiarch`, created on first use. Multi-platform images can't be loaded into the local Docker image store. `build` therefore leaves the result in the builder cache, and `push` reuses it.
