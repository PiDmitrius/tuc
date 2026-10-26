"""Deployment and restore checks through the documented HTTPS endpoint."""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import sys
import time

state = Path("/state")
state.mkdir(exist_ok=True)
os.umask(0o077)
context = ssl.create_default_context(cafile="/trust.pem")
host = "ca.example.test"

def request(method, path, data=None, headers=None, expected=200, plain=False):
    connection = http.client.HTTPConnection(host, timeout=10) if plain else http.client.HTTPSConnection(host, context=context, timeout=10)
    if isinstance(data, dict):
        data = json.dumps(data).encode()
        headers = {"Content-Type": "application/json", **(headers or {})}
    connection.request(method, path, body=data, headers=headers or {})
    response = connection.getresponse()
    body = response.read()
    code = response.status
    connection.close()
    if code != expected:
        raise AssertionError(f"unexpected HTTP {code}, expected {expected} for {method}")
    return body


def api(path, body):
    return json.loads(request("POST", path, body))


def openssl(*args, data=None, good=True):
    result = subprocess.run(["openssl", *args], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if good and result.returncode:
        raise AssertionError("OpenSSL operation failed: " + result.stderr.decode(errors="replace"))
    return result


def issue(info, name):
    req = openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(state / (name + ".key")), "-subj", "/CN=" + name, "-outform", "DER").stdout
    password = base64.b64encode(("tuc:" + info["issue"]).encode()).decode()
    body = request("POST", "/.well-known/est/" + info["inter"]["id"] + "/simpleenroll", base64.b64encode(req), {"Content-Type": "application/pkcs10", "Authorization": "Basic " + password})
    pem = openssl("pkcs7", "-inform", "DER", "-print_certs", data=base64.b64decode(body)).stdout
    (state / (name + ".pem")).write_bytes(pem)
    der = openssl("x509", "-outform", "DER", data=pem).stdout
    return hashlib.sha1(der).hexdigest().upper()


def chains(info):
    for role in ("root", "inter"):
        der = request("GET", "/" + info[role]["id"] + ".crt")
        if hashlib.sha256(der).hexdigest() != info[role + "_hash"]:
            raise AssertionError("CA certificate changed")
        (state / (role + ".pem")).write_bytes(openssl("x509", "-inform", "DER", data=der).stdout)
    crls = b""
    for role in ("root", "inter"):
        crls += openssl("crl", "-inform", "DER", data=request("GET", "/" + info[role]["id"] + ".crl")).stdout
    (state / "crls.pem").write_bytes(crls)
    args = ("verify", "-CAfile", str(state / "root.pem"), "-untrusted", str(state / "inter.pem"), "-CRLfile", str(state / "crls.pem"), "-crl_check_all")
    openssl(*args, str(state / "leaf.pem"))
    rejected = openssl(*args, str(state / "revoked.pem"), good=False)
    if rejected.returncode == 0 or b"certificate revoked" not in rejected.stderr:
        raise AssertionError("saved revocation is missing")


def service_fingerprint(pem, purpose):
    for cert in re.findall(b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, flags=re.S):
        usage = openssl("x509", "-noout", "-ext", "extendedKeyUsage", data=cert).stdout
        if purpose.encode() in usage:
            return hashlib.sha256(openssl("x509", "-outform", "DER", data=cert).stdout).hexdigest()
    raise AssertionError("service certificate is missing")


def services(info):
    openssl("ocsp", "-issuer", str(state / "inter.pem"), "-cert", str(state / "leaf.pem"), "-reqout", str(state / "ocsp.req"))
    reply = request("POST", "/" + info["inter"]["id"] + "/ocsp", (state / "ocsp.req").read_bytes(), {"Content-Type": "application/ocsp-request"})
    (state / "ocsp.resp").write_bytes(reply)
    openssl("ocsp", "-respin", str(state / "ocsp.resp"), "-issuer", str(state / "inter.pem"), "-cert", str(state / "leaf.pem"), "-CAfile", str(state / "root.pem"), "-verify_other", str(state / "inter.pem"), "-no_nonce")
    text = openssl("ocsp", "-respin", str(state / "ocsp.resp"), "-text", "-noverify").stdout
    ocsp = service_fingerprint(text, "OCSP Signing")
    (state / "data").write_bytes(b"restore verification")
    openssl("ts", "-query", "-data", str(state / "data"), "-sha256", "-cert", "-out", str(state / "query.tsq"))
    reply = request("POST", "/" + info["inter"]["id"] + "/tsp", (state / "query.tsq").read_bytes(), {"Content-Type": "application/timestamp-query"})
    (state / "reply.tsr").write_bytes(reply)
    openssl("ts", "-verify", "-in", str(state / "reply.tsr"), "-queryfile", str(state / "query.tsq"), "-CAfile", str(state / "root.pem"), "-untrusted", str(state / "inter.pem"))
    token = openssl("ts", "-reply", "-in", str(state / "reply.tsr"), "-token_out").stdout
    tsa = service_fingerprint(openssl("pkcs7", "-inform", "DER", "-print_certs", data=token).stdout, "Time Stamping")
    return {"ocsp": ocsp, "tsa": tsa}


mode = sys.argv[1]
if mode == "wait":
    deadline = time.monotonic() + 20
    while True:
        try:
            request("GET", "/livez")
            break
        except (OSError, AssertionError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(.1)
    request("GET", "/readyz", expected=int(sys.argv[2]))
    print("HTTPS liveness/readiness checked")
elif mode == "pre":
    root = api("/new", {"subject": "CN=Deployment Root", "algo": "ecdsa256"})
    inter = api("/" + root["id"] + "/new", {"token": root["admin"], "subject": "CN=Deployment Issuer", "algo": "gost256", "closed": True})
    admin = api("/" + inter["id"] + "/admin", {"token": inter["admin"]})
    info = {"root": root, "inter": inter, "issue": admin["issue"], "enroll": admin["enroll"]}
    for role in ("root", "inter"):
        der = request("GET", "/" + info[role]["id"] + ".crt")
        info[role + "_hash"] = hashlib.sha256(der).hexdigest()
        (state / (role + ".pem")).write_bytes(openssl("x509", "-inform", "DER", data=der).stdout)
    info["leaf"] = issue(info, "leaf")
    info["revoked"] = issue(info, "revoked")
    api("/" + inter["id"] + "/revoke", {"token": inter["admin"], "cert": info["revoked"]})
    chains(info)
    info["services"] = services(info)
    (state / "state.json").write_text(json.dumps(info))
    print("issuance, mixed chain, revocation, OCSP and TSP checked")
elif mode == "post":
    info = json.loads((state / "state.json").read_text())
    request("POST", "/" + info["inter"]["id"] + "/admin", {"token": info["root"]["admin"]}, expected=403)
    admin = api("/" + info["inter"]["id"] + "/admin", {"token": info["inter"]["admin"]})
    if admin["enroll"] != info["enroll"]:
        raise AssertionError("old enrollment capability changed")
    if services(info) != info["services"]:
        raise AssertionError("service signing certificates changed")
    chains(info)
    branch = api("/" + info["root"]["id"] + "/new", {"token": info["root"]["admin"], "subject": "CN=Restored Branch", "algo": "ecdsa256"})
    branch_der = request("GET", "/" + branch["id"] + ".crt")
    (state / "branch.pem").write_bytes(openssl("x509", "-inform", "DER", data=branch_der).stdout)
    openssl("verify", "-CAfile", str(state / "root.pem"), str(state / "branch.pem"))
    issue(info, "restored")
    password = secrets.token_urlsafe(20)
    pfx = request("POST", info["enroll"].removeprefix("https://" + host) + "/pfx", {"name": "restored PFX", "algo": "ecdsa256", "password": password})
    (state / "restored.pfx").write_bytes(pfx)
    openssl("pkcs12", "-in", str(state / "restored.pfx"), "-passin", "stdin", "-noout", data=(password + "\n").encode())
    api("/" + info["inter"]["id"] + "/revoke", {"token": info["inter"]["admin"], "cert": info["leaf"]})
    current = openssl("crl", "-inform", "DER", data=request("GET", "/" + info["inter"]["id"] + ".crl")).stdout
    (state / "updated-crl.pem").write_bytes(current)
    rejected = openssl("verify", "-CAfile", str(state / "root.pem"), "-untrusted", str(state / "inter.pem"), "-CRLfile", str(state / "updated-crl.pem"), "-crl_check", str(state / "leaf.pem"), good=False)
    if rejected.returncode == 0 or b"certificate revoked" not in rejected.stderr:
        raise AssertionError("new revocation after recovery is missing")
    print("restored old capabilities, CA/service keys, chain and revocation; new issuance and PFX checked")
elif mode == "publication":
    info = json.loads((state / "state.json").read_text())
    ident = info["inter"]["id"]
    text = openssl("x509", "-in", str(state / "leaf.pem"), "-noout", "-text").stdout.decode()
    for tail in (".crt", ".crl", "/ocsp"):
        assert "http://" + host + "/" + ident + tail in text
    assert "https://" + host not in text
    for method, path in (("GET", "/"), ("GET", "/" + ident), ("POST", "/new"), ("GET", "/.well-known/est/" + ident + "/cacerts")):
        connection = http.client.HTTPConnection(host, timeout=10)
        connection.request(method, path)
        response = connection.getresponse()
        assert response.status == 308 and response.getheader("Location") == "https://" + host + path
        response.read(); connection.close()
    for role in ("root", "inter"):
        path = "/" + info[role]["id"]
        assert request("GET", path + ".crt", plain=True) == request("GET", path + ".crt")
        assert request("GET", path + ".crl", plain=True) == request("GET", path + ".crl")
    query = (state / "ocsp.req").read_bytes()
    for method, path, data in (("POST", "/" + ident + "/ocsp", query), ("GET", "/" + ident + "/ocsp/" + base64.b64encode(query).decode(), None)):
        reply = request(method, path, data, plain=True)
        (state / "http.ocsp").write_bytes(reply)
        openssl("ocsp", "-respin", str(state / "http.ocsp"), "-text", "-noverify")
    reply = request("POST", "/" + ident + "/tsp", (state / "query.tsq").read_bytes(), {"Content-Type": "application/timestamp-query"}, plain=True)
    (state / "http.tsr").write_bytes(reply)
    openssl("ts", "-verify", "-in", str(state / "http.tsr"), "-queryfile", str(state / "query.tsq"), "-CAfile", str(state / "root.pem"), "-untrusted", str(state / "inter.pem"))
    print("HTTP AIA/CRL/OCSP/TSP, certificate URLs and HTTPS redirects checked")
elif mode == "public-id":
    print(json.loads((state / "state.json").read_text())["inter"]["id"])
elif mode == "writer":
    info = json.loads((state / "state.json").read_text())
    deadline = time.monotonic() + 30
    count = 0
    while not (state / "writer.stop").exists():
        if time.monotonic() > deadline:
            raise TimeoutError("backup did not stop its writer fixture")
        issue(info, "concurrent-" + str(count))
        count += 1
        (state / "writer.running").touch()
    print(f"concurrent issuance completed: {count} certificates")
elif mode == "writer-wait":
    deadline = time.monotonic() + 5
    while not (state / "writer.running").exists():
        if time.monotonic() > deadline:
            raise TimeoutError("writer did not start")
        time.sleep(.01)
elif mode == "backend-denied":
    import socket
    try:
        connection = socket.create_connection((sys.argv[2], 8080), timeout=2)
    except OSError:
        print("direct backend connection denied")
    else:
        connection.close()
        raise AssertionError("outside client reached backend directly")
elif mode == "outside-open":
    api("/new", {"subject": "CN=Open Profile", "algo": "ecdsa256"})
    print("open profile allows external CA creation")
elif mode == "outside-closed":
    ident = sys.argv[2]
    for path in ("/", "/readyz", "/" + ident, "/.well-known/est/" + ident + "/cacerts"):
        request("GET", path, headers={"X-Forwarded-For": sys.argv[3]}, expected=403)
    for path in ("/new", "/" + ident + "/admin", "/" + ident + "/pfx", "/" + ident + "/revoke", "/.well-known/est/" + ident + "/simpleenroll", "/" + ident + "/ocsp/../admin", "/" + ident + "/tsp"):
        request("POST", path, {}, expected=403)
    for tail in (".crt", ".crl", "/ca.crt", "/crl"):
        request("GET", "/" + ident + tail)
    query = sys.stdin.buffer.read()
    reply = request("POST", "/" + ident + "/ocsp", query)
    (state / "outside.ocsp").write_bytes(reply)
    openssl("ocsp", "-respin", str(state / "outside.ocsp"), "-text", "-noverify")
    from urllib.parse import quote
    request("GET", "/" + ident + "/ocsp/" + quote(base64.b64encode(query).decode(), safe=""))
    request("GET", "/", expected=308, plain=True)
    for tail in (".crt", ".crl"):
        request("GET", "/" + ident + tail, plain=True)
    request("POST", "/" + ident + "/ocsp", query, plain=True)
    tsquery = openssl("ts", "-query", "-digest", hashlib.sha256(b"public HTTP timestamp").hexdigest(), "-sha256", "-cert").stdout
    response = request("POST", "/" + ident + "/tsp", tsquery, {"Content-Type": "application/timestamp-query"}, plain=True)
    (state / "public.tsr").write_bytes(response)
    assert b"Granted" in openssl("ts", "-reply", "-in", str(state / "public.tsr"), "-text").stdout
    print("closed profile exposes CA certificates/CRL/OCSP; business endpoints and spoofed forwarded address denied")
else:
    raise ValueError("unknown test phase")
