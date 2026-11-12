package lint

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Finding is one rule violation.
type Finding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Line     int    `json:"line"`
	Message  string `json:"message"`
	Fix      string `json:"fix"`
}

var (
	pipeToShell  = regexp.MustCompile(`(?i)(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b`)
	insecureTLS  = regexp.MustCompile(`(?i)\bcurl\b[^|;&]*\s(-k|--insecure)\b|--no-check-certificate|--trusted-host|npm\s+config\s+set\s+strict-ssl\s+false|git\s+config[^;&]*sslVerify\s+false|apk\s+add[^;&]*--allow-untrusted|--allow-unauthenticated|--force-yes`)
	secretName   = regexp.MustCompile(`(?i)(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential|access[_-]?key)`)
	chmod777     = regexp.MustCompile(`chmod\s+(-R\s+)?(0?777|a\+rwx|ugo\+rwx)`)
	aptInstall   = regexp.MustCompile(`apt(-get)?\s+install`)
	sudoUse      = regexp.MustCompile(`(^|[;&|]\s*|\s)sudo\s`)
	pkgManagerUp = regexp.MustCompile(`apt(-get)?\s+upgrade|apt(-get)?\s+dist-upgrade`)
)

func add(out *[]Finding, rule, sev string, line int, msg, fix string) {
	*out = append(*out, Finding{rule, sev, line, msg, fix})
}

func imageRef(args string) (image string, stage string) {
	f := strings.Fields(args)
	var parts []string
	for _, p := range f {
		if strings.HasPrefix(p, "--") {
			continue
		}
		parts = append(parts, p)
	}
	if len(parts) == 0 {
		return "", ""
	}
	if len(parts) >= 3 && strings.EqualFold(parts[1], "AS") {
		return parts[0], strings.ToLower(parts[2])
	}
	return parts[0], ""
}

// Analyze applies every rule to the parsed instructions.
func Analyze(ins []Instruction) []Finding {
	var out []Finding
	stages := map[string]bool{}
	finalStart := 0
	hasFrom := false
	for i, in := range ins {
		if in.Cmd == "FROM" {
			hasFrom = true
			finalStart = i
		}
	}
	var finalUser string
	var finalUserLine int
	healthcheck := false

	for i, in := range ins {
		switch in.Cmd {
		case "FROM":
			img, stage := imageRef(in.Args)
			if stage != "" {
				stages[stage] = true
			}
			lower := strings.ToLower(img)
			if lower == "scratch" || stages[lower] || strings.HasPrefix(img, "$") {
				break
			}
			if strings.Contains(img, "@sha256:") {
				break
			}
			last := img[strings.LastIndex(img, "/")+1:]
			switch {
			case !strings.Contains(last, ":"):
				add(&out, "D002", "medium", in.Line, fmt.Sprintf("base image '%s' has no tag (defaults to :latest)", img), "Pin a version tag, ideally an immutable digest (@sha256:...)")
			case strings.HasSuffix(last, ":latest"):
				add(&out, "D002", "medium", in.Line, fmt.Sprintf("base image '%s' uses :latest", img), "Pin a version tag, ideally an immutable digest (@sha256:...)")
			default:
				add(&out, "D015", "low", in.Line, fmt.Sprintf("base image '%s' is pinned by tag only; tags are mutable", img), "Pin by digest for reproducible, tamper-evident builds")
			}
		case "USER":
			if i > finalStart {
				finalUser, finalUserLine = strings.Fields(in.Args + " x")[0], in.Line
			}
		case "HEALTHCHECK":
			if i > finalStart && !strings.EqualFold(strings.TrimSpace(in.Args), "NONE") {
				healthcheck = true
			}
		case "ADD":
			a := strings.Fields(in.Args)
			if len(a) > 0 && regexp.MustCompile(`(?i)^(--\S+\s+)*https?://`).MatchString(in.Args) {
				add(&out, "D003", "medium", in.Line, "ADD downloads a remote URL without integrity verification", "Use curl/wget in RUN with a checksum check, or COPY a verified artifact")
			} else {
				add(&out, "D004", "low", in.Line, "ADD has implicit extraction and URL behaviour", "Use COPY unless you need to auto-extract a local tar archive")
			}
		case "EXPOSE":
			for _, p := range strings.Fields(in.Args) {
				if strings.HasPrefix(p, "22") && (p == "22" || strings.HasPrefix(p, "22/")) {
					add(&out, "D008", "medium", in.Line, "EXPOSE 22 suggests an SSH daemon inside the container", "Use docker exec / kubectl exec; do not run sshd in containers")
				}
			}
		case "ENV", "ARG":
			for _, kv := range envPairs(in.Args) {
				if secretName.MatchString(kv[0]) && kv[1] != "" && !strings.HasPrefix(kv[1], "$") {
					sev := "high"
					fix := "Use BuildKit secrets (RUN --mount=type=secret) or inject at runtime; build args are stored in image history"
					if in.Cmd == "ENV" {
						fix = "Inject secrets at runtime (env file, orchestrator secret); ENV values are baked into the image"
					}
					add(&out, "D005", sev, in.Line, fmt.Sprintf("%s %s appears to hold a literal secret", in.Cmd, kv[0]), fix)
				}
			}
		case "RUN":
			a := in.Args
			if pipeToShell.MatchString(a) {
				add(&out, "D006", "high", in.Line, "downloads a script and pipes it straight into a shell", "Download, verify a pinned checksum or signature, then execute")
			}
			if insecureTLS.MatchString(a) {
				add(&out, "D007", "high", in.Line, "disables TLS or signature verification", "Remove the insecure flag and fix the certificate/trust problem instead")
			}
			if chmod777.MatchString(a) {
				add(&out, "D009", "medium", in.Line, "world-writable permissions (chmod 777)", "Grant the minimum: chmod 755 for directories/binaries, 644 for files, or chown to the runtime user")
			}
			if sudoUse.MatchString(a) {
				add(&out, "D010", "low", in.Line, "sudo is unnecessary in a Dockerfile (builds already run as root)", "Drop sudo; switch USER explicitly where needed")
			}
			if aptInstall.MatchString(a) {
				if !strings.Contains(a, "--no-install-recommends") {
					add(&out, "D011", "low", in.Line, "apt install without --no-install-recommends pulls extra packages (bigger attack surface)", "Add --no-install-recommends")
				}
				if !strings.Contains(a, "/var/lib/apt/lists") {
					add(&out, "D012", "low", in.Line, "apt package lists are left in the layer", "Finish the same RUN with: rm -rf /var/lib/apt/lists/*")
				}
			}
			if pkgManagerUp.MatchString(a) {
				add(&out, "D013", "low", in.Line, "apt upgrade makes builds non-reproducible", "Rebuild from an updated, pinned base image instead")
			}
			if regexp.MustCompile(`pip3?\s+install`).MatchString(a) && !strings.Contains(a, "--no-cache-dir") && !strings.Contains(a, "-r ") && strings.Contains(a, "install") && !strings.Contains(a, "PIP_NO_CACHE_DIR") {
				add(&out, "D014", "low", in.Line, "pip install without --no-cache-dir keeps the wheel cache in the layer", "Add --no-cache-dir")
			}
		}
	}
	if hasFrom {
		if finalUser == "" {
			add(&out, "D001", "high", ins[finalStart].Line, "final image runs as root (no USER instruction)", "Create an unprivileged user and add USER <name> before CMD/ENTRYPOINT")
		} else if u := strings.ToLower(finalUser); u == "root" || u == "0" || strings.HasPrefix(u, "0:") || strings.HasPrefix(u, "root:") {
			add(&out, "D001", "high", finalUserLine, "final USER is root", "Switch to an unprivileged user before CMD/ENTRYPOINT")
		}
		if !healthcheck {
			add(&out, "D016", "low", ins[finalStart].Line, "no HEALTHCHECK in the final stage", "Add a HEALTHCHECK, or rely on orchestrator probes and document it")
		}
	}
	rank := map[string]int{"high": 0, "medium": 1, "low": 2}
	sort.SliceStable(out, func(i, j int) bool {
		if rank[out[i].Severity] != rank[out[j].Severity] {
			return rank[out[i].Severity] < rank[out[j].Severity]
		}
		return out[i].Line < out[j].Line
	})
	return out
}

// envPairs understands both `ENV KEY value` and `ENV A=1 B="x y"` forms.
func envPairs(args string) [][2]string {
	args = strings.TrimSpace(args)
	if args == "" {
		return nil
	}
	first := strings.Fields(args)[0]
	if !strings.Contains(first, "=") {
		name, val, _ := strings.Cut(args, " ")
		return [][2]string{{name, strings.Trim(strings.TrimSpace(val), `"'`)}}
	}
	var out [][2]string
	re := regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|\S*)`)
	for _, m := range re.FindAllStringSubmatch(args, -1) {
		out = append(out, [2]string{m[1], strings.Trim(m[2], `"'`)})
	}
	return out
}
