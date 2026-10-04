import urllib.request
try:
    urllib.request.urlopen("https://api.github.com/", timeout=5)
    print("Success")
except Exception as e:
    print(e)
