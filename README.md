# dockerfile-audit

Go CLI that lints **Dockerfiles for security and supply-chain hygiene**. It understands line continuations, `ONBUILD` and multi-stage builds (only the **final stage** decides the runtime user), and gives a concrete fix for every finding. Standard library only.

> Built with AI assistance (Claude) as a portfolio project. Review the code before relying on it.

## Usage

```bash
go install github.com/jvch0512/dockerfile-audit@latest
dockerfile-audit Dockerfile
dockerfile-audit -json -fail-on high services/*/Dockerfile
cat Dockerfile | dockerfile-audit -
```

```
Dockerfile:6 [high] D006 downloads a script and pipes it straight into a shell
    fix: Download, verify a pinned checksum or signature, then execute
```
(illustrative output)

Exit code `0` ok, `1` findings at or above `-fail-on` (default `medium`), `2` usage or I/O error.

## Rules

| ID | Severity | Check |
|----|----------|-------|
| D001 | high | final image runs as root (no `USER`, or last `USER` is root/0) |
| D002 | medium | base image untagged or `:latest` |
| D015 | low | base image pinned by tag but not by digest |
| D003 / D004 | medium / low | `ADD` of a remote URL / `ADD` where `COPY` would do |
| D005 | high | literal secret in `ENV` or `ARG` (both end up in image history) |
| D006 | high | `curl \| sh` style installs |
| D007 | high | TLS or signature checks disabled (`curl -k`, `--no-check-certificate`, `--trusted-host`, `--allow-untrusted`, `--force-yes`) |
| D008 | medium | `EXPOSE 22` |
| D009 | medium | `chmod 777` |
| D010 | low | `sudo` in a build |
| D011-D013 | low | apt without `--no-install-recommends`, package lists left in the layer, `apt upgrade` |
| D014 | low | `pip install` without `--no-cache-dir` |
| D016 | low | no `HEALTHCHECK` in the final stage |

## Details

* Registry ports are not mistaken for tags: `registry.local:5000/app` is untagged
* Stage names and `scratch` are not treated as pullable images
* Both `ENV KEY value` and `ENV A=1 B="x y"` forms are parsed
* Tests cover every rule with a clean counter-example, plus the CLI and the two sample files

Complements, not replaces, hadolint and image scanners such as Trivy or Grype.

## Development

```bash
go vet ./... && go test -race ./...
```

MIT licensed.
