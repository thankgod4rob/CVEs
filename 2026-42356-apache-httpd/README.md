# CVE-2026-42356 - Apache HTTPD Wrong Handler on Internal Redirect

PoC for CVE-2026-42356 affecting Apache HTTP Server **2.4.60 through 2.4.68**.

When a CGI script returns a local `Location` header (no scheme, just a path), Apache performs an internal redirect via subrequest. On vulnerable versions, the redirect target **inherits the CGI handler** even if mod_mime doesn't recognize its extension. So if you can drop an extensionless file into a `ScriptAlias`'d directory, a legit CGI script can redirect to it and Apache will happily execute it.

## Preconditions

This requires Apache 2.4.60-2.4.68 with `mod_cgi` or `mod_cgid` enabled, a `ScriptAlias` directory (like `/cgi-bin/`) that the attacker can place files into or already has a file in, and an existing CGI script that performs a local internal redirect or the ability to upload one.

## Usage

Install dependencies:

```
pip install -r requirements.txt
```

Run the check against a target:

```
python3 2026-42356.py --target http://localhost:8080
```

Interactive RCE shell:

```
python3 2026-42356.py --target http://localhost:8080 -i
```

## Docker lab

A Dockerfile and compose file are included to spin up a vulnerable Apache 2.4.68 instance.

```
docker compose up --build -d
python3 2026-42356.py --target http://localhost:8080
```

Tear it down:

```
docker compose down
```
