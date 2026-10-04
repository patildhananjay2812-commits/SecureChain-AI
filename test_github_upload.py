import urllib.request
import urllib.parse
from http.cookiejar import CookieJar
import ssl

def test_github_upload():
    # Ignore SSL errors in the client as well
    context = ssl._create_unverified_context()
    cj = CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj), urllib.request.HTTPSHandler(context=context))
    
    # 1. Register/Login
    data = urllib.parse.urlencode({"email": "github_test@example.com", "password": "password123"}).encode('utf-8')
    opener.open("http://127.0.0.1:5000/register", data=data)
    opener.open("http://127.0.0.1:5000/login", data=data)
    
    # 2. Upload GitHub
    print("Sending GitHub repository (left-pad/left-pad) to local SecureChain AI analyzer...")
    data = urllib.parse.urlencode({
        "upload_source": "github",
        "github_url": "https://github.com/left-pad/left-pad"
    }).encode('utf-8')
    
    try:
        r = opener.open("http://127.0.0.1:5000/upload", data=data)
        body = r.read().decode('utf-8')
        print(f"Status Code: {r.getcode()}")
        print(f"Response Size: {len(body)} bytes")
        
        # Extract some interesting parts from the HTML
        if "Analysis Results" in body:
            print("Successfully received Analysis Results page!")
            
            # Simple extraction for demo purposes
            if "Total Dependencies" in body:
                print("Dependencies were extracted successfully.")
    except urllib.error.HTTPError as e:
        print("HTTP Error:", e.code, e.read().decode('utf-8')[:500])
    except Exception as e:
        print("Error:", str(e))

if __name__ == "__main__":
    test_github_upload()
