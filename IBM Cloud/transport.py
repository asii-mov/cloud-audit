"""Small verified-TLS JSON client and append-only engagement evidence writer."""
import hashlib
import json
import re
import shlex
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AuditError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Evidence:
    def __init__(self, directory, mode):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, mode=0o700, exist_ok=False)
        self.mode = mode
        self.events = []
        self.secrets = set()
        self.lines = ["IBM CLOUD | IAM ENGAGEMENT TRANSCRIPT", f"Mode: {mode}",
                      f"Started: {now()}",
                      ("Prompts below simulate HTTP requests from fixtures; no network requests were executed."
                       if mode.startswith("SYNTHETIC") else
                       "Prompts below render HTTP requests executed by Python, not an interactive shell."),
                      "Secrets are redacted. Review notes are automated assessment, not human sign-off.",
                      "Configuration findings are hypotheses until business need and access are validated.", ""]

    def protect(self, value):
        if isinstance(value, str) and value:
            self.secrets.add(value)

    def clean(self, value):
        if isinstance(value, dict):
            return {str(k): "[REDACTED]" if re.sub(r"[^a-z]", "", str(k).lower()) in {
                "apikey", "accesstoken", "refreshtoken", "authorization", "password",
                "secret", "clientsecret", "userdata", "privatekey", "token", "idtoken"
            } else self.clean(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.clean(v) for v in value]
        if isinstance(value, str):
            for secret in sorted(self.secrets, key=len, reverse=True):
                value = value.replace(secret, "[REDACTED]")
            # Prevent terminal control sequences and embedded prompts in resource names.
            return "".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in value)
        return value

    def note(self, text):
        self.lines.append(f"[{now()}] REVIEW: {self.clean(text)}")

    def request(self, label, method, url, status, response, body=None, authenticated=False, headers=None, form=False):
        event = self.clean({"time": now(), "label": label, "method": method,
                            "url": url, "status": status, "response": response,
                            "request_body": body, "request_headers": headers or {}})
        self.events.append(event)
        command = f"curl -sS -X {method} {shlex.quote(self.clean(url))}"
        if authenticated:
            command += " -H 'Authorization: Bearer [REDACTED]'"
        for name, value in (headers or {}).items():
            if name.lower() != "authorization":
                command += " -H " + shlex.quote(self.clean(f"{name}: {value}"))
        if body is not None:
            rendered = urllib.parse.urlencode(self.clean(body)) if form else json.dumps(self.clean(body), sort_keys=True)
            command += " --data " + shlex.quote(rendered)
        self.lines.extend(["", f"[{event['time']}] {self.clean(label)}", f"tester@ibm-audit$ {command}",
                           f"HTTP {status}", json.dumps(event["response"], indent=2, sort_keys=True)])

    def finish(self, inventory, findings, gaps):
        self.note(f"Review completed: {len(findings)} review items; {len(gaps)} coverage gaps.")
        for f in findings:
            self.note(f"{f['id']} [{f['severity']}] {f['title']} | {f['resource']}")
            self.note(f["narrative"])
            self.note("Recommended follow-up: " + f["recommendation"])
        for gap in gaps:
            self.note("COVERAGE GAP: " + gap)
        if not findings:
            self.note("No implemented heuristic matched. This is not a least-privilege certification.")
        report = {"schema_version": 1, "mode": self.mode, "completed_at": now(),
                  "findings": findings, "coverage_gaps": gaps, "events": self.events,
                  "inventory": inventory}
        files = {"transcript.txt": "\n".join(self.lines) + "\n",
                 "report.json": json.dumps(self.clean(report), indent=2, sort_keys=True) + "\n"}
        for name, content in files.items():
            path = self.directory / name
            path.write_text(content, encoding="utf-8")
            path.chmod(0o600)
        manifest = {name: hashlib.sha256((self.directory / name).read_bytes()).hexdigest() for name in files}
        (self.directory / "SHA256SUMS.json").write_text(json.dumps(manifest, indent=2) + "\n")


class Client:
    def __init__(self, base, evidence, token=None, local=False):
        self.base = base.rstrip("/")
        self.evidence = evidence
        self.token = token
        self.evidence.protect(token)
        handlers = [NoRedirect()]
        if local:
            handlers.append(urllib.request.ProxyHandler({}))
        self.opener = urllib.request.build_opener(*handlers)

    def url(self, path, params=None):
        url = urllib.parse.urljoin(self.base + "/", path)
        target, origin = urllib.parse.urlsplit(url), urllib.parse.urlsplit(self.base)
        if (target.scheme, target.netloc) != (origin.scheme, origin.netloc) or target.username or target.fragment:
            raise AuditError("Refused a URL outside the configured API origin")
        if params:
            url += ("&" if target.query else "?") + urllib.parse.urlencode(params)
        return url

    def call(self, path, label, params=None, method="GET", body=None, form=False, headers=None):
        url = self.url(path, params)
        hdr = {"Accept": "application/json", **(headers or {})}
        if self.token:
            hdr["Authorization"] = "Bearer " + self.token
        data = None
        if body is not None:
            data = (urllib.parse.urlencode(body) if form else json.dumps(body)).encode()
            hdr["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
        req = urllib.request.Request(url, data=data, headers=hdr, method=method)
        try:
            with self.opener.open(req, timeout=20) as response:
                status = response.status
                raw = response.read(16 * 1024 * 1024 + 1)
                if len(raw) > 16 * 1024 * 1024:
                    raise AuditError("Response exceeded 16 MiB; narrow collection scope")
                result = json.loads(raw)
                if not isinstance(result, dict):
                    raise AuditError("Expected a JSON object")
        except urllib.error.HTTPError as exc:
            # Never persist arbitrary error bodies: services can echo credentials.
            self.evidence.request(label, method, url, exc.code, {"error": "HTTP request failed; body omitted"}, body, bool(self.token), hdr, form)
            raise AuditError(f"{label}: HTTP {exc.code}", exc.code) from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, AuditError) as exc:
            self.evidence.request(label, method, url, "ERROR", {"error_type": type(exc).__name__}, body, bool(self.token), hdr, form)
            raise AuditError(f"{label}: transport or JSON response failure ({type(exc).__name__})") from None
        for name in ("access_token", "refresh_token", "apikey", "id_token"):
            self.evidence.protect(result.get(name))
        self.evidence.request(label, method, url, status, result, body, bool(self.token), hdr, form)
        return result

    def pages(self, path, key, label, params=None):
        current = self.url(path, params)
        expected_path = urllib.parse.urlsplit(current).path
        seen = set()
        for _ in range(1000):
            current = self.url(current)
            if urllib.parse.urlsplit(current).path != expected_path or current in seen:
                raise AuditError(f"{label}: invalid or repeated pagination URL")
            seen.add(current)
            response = self.call(current, label)
            rows = response.get(key)
            if not isinstance(rows, list) or not all(isinstance(x, dict) for x in rows):
                raise AuditError(f"{label}: missing or malformed {key} array")
            yield from rows
            following = response.get("next")
            if not following:
                return
            if isinstance(following, dict):
                following = following.get("href")
            if not isinstance(following, str) or not following:
                raise AuditError(f"{label}: malformed pagination link")
            current = urllib.parse.urljoin(current, following)
        raise AuditError(f"{label}: pagination limit reached")
