import requests
import json

url = 'http://127.0.0.1:5000/upload'
files = {'zip_file': open('test_samples/test-project.zip', 'rb')}
data = {'upload_source': 'zip'}
# Need to login first or is it authenticated?
# Let's check test_suite.py for how it bypasses auth or registers
