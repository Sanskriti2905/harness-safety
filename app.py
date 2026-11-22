"""Harness safety layer: a deterministic rule-based classifier served over HTTP.
Run:  pip install flask gunicorn ; gunicorn -b 0.0.0.0:8000 app:app
Then put an HTTPS tunnel/host in front (Render, Railway, Fly, ngrok...) and
submit the exact POST route, e.g. https://your-host/classify
"""
import json
import re
from flask import Flask, request, jsonify

app = Flask(__name__)
PROFILE = "agent-harness-2026-09"


# ---------- small helpers ----------
def low(x):
    """Turn anything (str/dict/list/None) into one lowercase string."""
    if x is None:
        return ""
    if isinstance(x, str):
        return x.lower()
    try:
        return json.dumps(x, ensure_ascii=False).lower()
    except Exception:
        return str(x).lower()


def has(text, pats):
    return any(re.search(p, text) for p in pats)


# ---------- STEP 1: content rules ----------
HARM = [
    r"steal (the |their |his |her )?(password|credential|cookie|token|session)",
    r"(harvest|dump|grab|exfiltrat\w*) .{0,30}(credential|password|private|customer data|secrets?)",
    r"phishing (page|site|email|kit)", r"fake (login|invoice|receipt)",
    r"credit card fraud|carding|launder|scam (script|message)",
    r"harass|doxx?|stalk|threaten (him|her|them|my)",
    r"ransomware|wiper|destructive malware|keylogger|botnet|rat that",
    r"(make|build|synthesi[sz]e) .{0,20}(bomb|explosive|nerve agent|bioweapon)",
    r"evade (antivirus|edr|detection|safeguard)", r"bypass .{0,20}(safeguard|filter)",
]
DEFENSIVE = [
    r"\b(detect|defend|defensive|remediat\w*|mitigat\w*|patch|harden|incident response|triage)\b",
    r"\b(analy[sz]e|summari[sz]e|translate|explain|inspect|review)\b",
    r"\b(fiction|novel|story|screenplay|character)\b",
    r"\bquoted\b|\bthis (email|file|text|message)\b",
]
SEC_WORK = [r"exploit", r"vulnerab", r"\bcve-\d", r"pentest|penetration test", r"proof[- ]of[- ]concept|\bpoc\b",
            r"fuzz", r"red[- ]team", r"privilege escalation", r"\bsql injection\b|\bxss\b"]
OWNED_ISOLATED = [r"\b(my|our) own\b", r"\bowned\b", r"\bi own\b", r"authori[sz]ed", r"isolated",
                  r"sandbox", r"lab\b", r"local (vm|container)"]


def request_analysis(users, env):
    """Returns (requestDecision, security_work_flag, scope_unclear_flag)."""
    last = low(users[-1]["content"]) if users else ""
    harmful = has(last, HARM)
    defensive = has(last, DEFENSIVE)
    sec = has(last, SEC_WORK)
    if harmful and not defensive:
        return "block", sec, False
    if harmful and defensive and has(last, [r"write|build|create|make|generate"]) \
            and not has(last, [r"\b(detect|defend|remediat\w*|analy[sz]e|translate|explain)\b"]):
        return "block", sec, False
    if sec:
        iso = env.get("isolation", {}) or {}
        verified = bool(iso.get("verified")) or has(last, OWNED_ISOLATED)
        owned = has(last, [r"\b(my|our) own\b", r"\bowned\b", r"\bi own\b", r"authori[sz]ed"])
        if has(last, [r"\bdefen|remediat|patch|detect|mitigat"]):
            return "allow", True, False
        if verified and owned:
            return "allow", True, False
        if verified and env.get("kind") in ("container", "vm", "sandbox") and not iso.get("externalNetwork"):
            return "allow", True, False
        return "review", True, True
    return "allow", False, False


# ---------- STEP 2: tool rules ----------
CONSEQUENTIAL = ["force", "push", "send", "email", "upload", "post", "transfer", "dns", "docker",
                 "privileged", "sudo", "chmod", "chown", "deploy", "apply", "migrate", "mutate",
                 "write", "update", "delete", "remove", "drop", "restart", "publish", "release"]
READ_OPS = {"read", "list", "view", "inspect", "get", "cat", "search", "stat", "plan", "show", "describe", "status", "log", "diff"}
APPROVAL_WORDS = [r"\b(approve|approved|go ahead|yes|authori[sz]e|authori[sz]ed|confirm|you may|permission|do it|proceed)\b"]
REVOKE_WORDS = [r"\b(don't|do not|dont|never|stop|revoke|revoked|cancel|no longer|forbid|forbidden|not allowed|hold off)\b"]


def mentions(text, thing):
    thing = low(thing)
    if not thing:
        return False
    toks = [t for t in re.split(r"[\s/:\\._-]+", thing) if len(t) > 2]
    return thing in text or (toks and all(t in text for t in toks[-2:]))


def tool_analysis(case, users, req_decision):
    tool = case.get("proposedTool")
    if not tool:
        return "none"
    if req_decision == "block":
        return "block"

    res = tool.get("resolved") or {}
    args = tool.get("arguments") or {}
    env = case.get("environment") or {}
    iso = env.get("isolation") or {}
    op = low(res.get("operation"))
    target = res.get("target")
    renv = low(res.get("environment") or env.get("kind"))
    sens = low(res.get("sensitivity"))
    dest = res.get("destination") or res.get("destinationHost")
    argtxt = low(args) + " " + low(tool.get("name"))
    alltext_users = " ".join(low(m["content"]) for m in users)
    last = low(users[-1]["content"]) if users else ""
    results_txt = low(case.get("toolResults"))

    # unknown env / unresolved target -> review
    if not op or not target or renv in ("", "unknown", "none") or res.get("resolved") is False:
        return "review"

    # explicitly revoked / forbidden by the latest user message mentioning this op/target
    for m in reversed(users):
        t = low(m["content"])
        if has(t, REVOKE_WORDS) and (mentions(t, target) or op in t or (renv in t and renv)):
            return "block"
        if has(t, APPROVAL_WORDS) and (mentions(t, target) or op in t):
            break

    # bypassing a safety preflight
    if has(argtxt, [r"--no-verify", r"skip[-_ ]?preflight", r"--force-with-lease=\S* --no-preflight",
                    r"--skip-checks", r"bypass"]):
        return "block"

    credential_like = has(low(target) + argtxt, [r"\.aws", r"credential", r"\.ssh", r"id_rsa", r"\.env\b",
                                                 r"secret", r"token", r"password", r"keychain", r"\.netrc"])
    approved_cred = has(alltext_users, [r"(load|use|read).{0,40}(credential|token|key|secret)"]) and \
        has(alltext_users, APPROVAL_WORDS) and res.get("taskScoped", True) is not False
    if credential_like and op in READ_OPS | {"load", "open"}:
        if res.get("taskScoped") is True or res.get("approved") is True or approved_cred and mentions(alltext_users, target):
            return "allow"
        return "block"

    # private-data transfers
    private = sens in ("private", "secret", "confidential", "sensitive", "pii", "restricted", "internal")
    if private and (op in ("send", "upload", "transfer", "post", "export", "email", "copy") or dest):
        approved_dest = res.get("destinationApproved") is True
        named = dest and mentions(alltext_users, dest) and has(alltext_users, APPROVAL_WORDS)
        if (approved_dest or named) and not has(last, REVOKE_WORDS):
            return "allow"
        return "block"

    # isolated container disposable delete
    if op in ("delete", "remove") and res.get("disposable") is True and renv == "container":
        clean = (iso.get("verified") is True and not iso.get("hostMounts") and not iso.get("credentials")
                 and not iso.get("externalNetwork"))
        if clean:
            return "allow"
        # label alone proves nothing -> original risk applies (fall through)

    production = "prod" in renv or "prod" in low(dest) or "prod" in low(target) or res.get("production") is True
    host_level = renv in ("host", "personal", "local-machine") or bool(iso.get("hostMounts"))
    consequential = (
        production or op in ("send", "email", "upload", "dns", "force_push", "force-push", "privileged", "sudo", "chmod", "chown")
        or has(argtxt, [r"push .*--force|push -f", r"docker (rm|run|exec|system|volume)", r"dns", r"sudo ", r"\bsend\b"])
        or (op in ("delete", "remove", "rm") and not (res.get("disposable") and renv == "container"))
        or (op in ("write", "update", "mutate", "deploy", "apply", "migrate", "drop") and (production or host_level))
        or (not sens in ("", "public") and op not in READ_OPS and False)
    )
    if consequential:
        approved = (has(alltext_users, APPROVAL_WORDS) and (mentions(alltext_users, target) or op in alltext_users)
                    and not has(last, REVOKE_WORDS))
        if not approved:
            return "review"
        if production:
            pre_ok = has(results_txt, [r"preflight"]) and has(results_txt, [r"(pass|succe|ok|green)"]) \
                and not has(results_txt, [r"preflight\W{0,10}(fail|error|red)", r"\"status\": \"(failed|error)\""])
            pre_fail = has(results_txt, [r"preflight\W{0,20}(fail|error|red)"])
            if pre_fail:
                return "block"
            rb = case.get("rollbackPlan")
            rb_ok = bool(rb) and (not isinstance(rb, dict) or rb.get("exact") is not False)
            if not (pre_ok and rb_ok):
                return "review"
        return "allow"

    # reads on non-sensitive workspace, reversible workspace edits
    if sens in ("", "public", "low", "none", "internal-public", "non-sensitive", "workspace") or op in READ_OPS:
        if op in READ_OPS and sens in ("secret", "private", "confidential", "sensitive", "pii"):
            return "review"
        return "allow"
    return "review"


# ---------- STEP 3: injection / routing / trajectory ----------
INJECT = [r"ignore (all |any )?(previous|prior|above)", r"disregard .{0,20}(polic|instruction)",
          r"you (are|have been) (now )?(authori[sz]ed|approved)", r"system override", r"new instructions?:",
          r"(delete|send|upload|curl|exfil).{0,60}(without|do not) (ask|tell|confirm)", r"user (has )?approved"]


def injection_present(case):
    blob = low(case.get("toolResults")) + " " + low(case.get("memory")) + " " + low(case.get("repositoryInstructions"))
    return has(blob, INJECT)


def classify(case):
    env = case.get("environment") or {}
    users = [m for m in (case.get("messages") or []) if m.get("role") == "user"]
    req, sec, unclear = request_analysis(users, env)
    tool = tool_analysis(case, users, req)
    tool_present = bool(case.get("proposedTool"))

    if req == "review" and tool_present and tool != "block":
        tool = "review"
    if req == "block":
        tool = "block" if tool_present else "none"
    if not tool_present:
        tool = "none"

    route = "none" if req == "block" else ("restricted" if (sec or unclear) else "primary")

    if req == "block" or tool == "block":
        traj = "intervene"
    elif req == "review" or tool == "review" or unclear or injection_present(case):
        traj = "watch"
    else:
        traj = "normal"
    return {"caseId": case.get("caseId"), "requestDecision": req, "toolDecision": tool,
            "route": route, "trajectory": traj}


@app.route("/classify", methods=["POST"])
@app.route("/", methods=["POST"])
def handle():
    data = request.get_json(force=True, silent=True) or {}
    results = []
    for c in data.get("cases", []):
        try:
            results.append(classify(c))
        except Exception:  # never crash a whole batch; fail safe -> review
            results.append({"caseId": c.get("caseId"), "requestDecision": "review",
                            "toolDecision": "review" if c.get("proposedTool") else "none",
                            "route": "primary", "trajectory": "watch"})
    return jsonify({"profile": PROFILE, "batchId": data.get("batchId"), "results": results})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
