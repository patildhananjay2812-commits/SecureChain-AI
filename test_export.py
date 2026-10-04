import urllib.request
import urllib.parse
from http.cookiejar import CookieJar
import json

def test_export():
    cj = CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    
    data = urllib.parse.urlencode({
        "project_name": "test_project",
        "package_data": json.dumps({"dependencies": {"requets": "1.0.0", "requests": "^2.0.0"}}),
        "typosquatting_findings": json.dumps([{"package": "requets"}]),
        "findings": json.dumps([{"name": "requests", "version": "^2.0.0"}])
    }).encode('utf-8')
    
    try:
        r = opener.open("http://127.0.0.1:5000/export-remediated-manifest", data=data)
        print("Export Status:", r.getcode())
        print("Filename:", r.headers.get("Content-Disposition"))
        body = r.read().decode('utf-8')
        print("Body:", body)
    except urllib.error.HTTPError as e:
        print("Failed:", e.code, e.read().decode('utf-8')[:500])

if __name__ == "__main__":
    test_export()
