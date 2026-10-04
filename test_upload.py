import sys
import os
sys.path.append(os.path.abspath('backend'))
from backend.app import app
from backend.storage import init_db, create_user, find_user_by_email, get_connection
import io
import zipfile

init_db()
if not find_user_by_email("test@example.com"):
    create_user("test@example.com", "hash")
user = find_user_by_email("test@example.com")
with get_connection() as conn:
    workspace = conn.execute("SELECT id FROM workspaces WHERE owner_id = ?", (user['id'],)).fetchone()
    workspace_id = workspace['id'] if workspace else 1

with app.test_client() as client:
    with client.session_transaction() as sess:
        sess['user_id'] = user['id']
        sess['user_email'] = user['email']
        sess['workspace_id'] = workspace_id
        
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr("package.json", '{"name": "test", "dependencies": {"express": "4.17.1", "requets": "1.0.0"}}')
        z.writestr("package-lock.json", '{"name": "test"}')
    buf.seek(0)
    
    data = {"upload_source": "zip", "zip_file": (buf, "test.zip")}
    res = client.post('/upload', data=data, content_type='multipart/form-data')
    print("STATUS:", res.status_code)
    if res.status_code == 200:
        html = res.data.decode('utf-8')
        if "test" in html:
            print("Project Name present.")
        if "requets" in html:
            print("Typosquatting present.")
        if "Download Security Report" in html:
            print("JSON report button present.")
    else:
        print("ERROR")
