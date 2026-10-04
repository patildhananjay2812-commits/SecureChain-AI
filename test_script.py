import urllib.request
import urllib.parse
from http.cookiejar import CookieJar

def test_app():
    cj = CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    
    # 1. Home
    r = opener.open("http://127.0.0.1:5000/")
    assert r.getcode() == 200, "Home page failed"

    # 2. Register
    data = urllib.parse.urlencode({"email": "test2@example.com", "password": "password123"}).encode('utf-8')
    r = opener.open("http://127.0.0.1:5000/register", data=data)
    
    # 3. Login
    data = urllib.parse.urlencode({"email": "test2@example.com", "password": "password123"}).encode('utf-8')
    r = opener.open("http://127.0.0.1:5000/login", data=data)
    
    print("Login url after redirect:", r.geturl())
    
    # 4. Upload GitHub
    data = urllib.parse.urlencode({
        "upload_source": "github",
        "github_url": "https://github.com/expressjs/express"
    }).encode('utf-8')
    try:
        r = opener.open("http://127.0.0.1:5000/upload", data=data)
        print("GitHub Upload Status:", r.getcode())
        if r.getcode() == 200:
            print("Success!")
    except urllib.error.HTTPError as e:
        print("Failed:", e.code, e.read().decode('utf-8')[:500])

if __name__ == "__main__":
    test_app()
