import urllib.request
import urllib.parse
from http.cookiejar import CookieJar
import json

def test_zip():
    cj = CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    
    # Register/Login
    data = urllib.parse.urlencode({"email": "test4@example.com", "password": "password123"}).encode('utf-8')
    opener.open("http://127.0.0.1:5000/register", data=data)
    opener.open("http://127.0.0.1:5000/login", data=data)
    
    import io, zipfile
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr("package.json", json.dumps({
            "name": "test-project",
            "dependencies": {
                "requests": "^2.31.0",
                "requets": "1.0.0",
                "express": "4.18.2",
                "jest": "29.5.0"
            }
        }))
    
    # Upload zip
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    body = (
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"upload_source\"\r\n\r\n"
        f"zip\r\n"
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"zip_file\"; filename=\"test.zip\"\r\n"
        f"Content-Type: application/zip\r\n\r\n"
    ).encode('utf-8') + zip_buffer.getvalue() + f"\r\n--{boundary}--\r\n".encode('utf-8')
    
    req = urllib.request.Request("http://127.0.0.1:5000/upload", data=body)
    req.add_header('Content-Type', f'multipart/form-data; boundary={boundary}')
    
    try:
        r = opener.open(req)
        body = r.read().decode('utf-8')
        print("ZIP Upload Status:", r.getcode())
        print("Success! Response size:", len(body))
        print(body[:500])
    except urllib.error.HTTPError as e:
        print("Failed:", e.code, e.read().decode('utf-8')[:500])

if __name__ == "__main__":
    test_zip()
