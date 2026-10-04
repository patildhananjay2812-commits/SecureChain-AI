import unittest
import io
import json
import zipfile
from backend.app import app, normalize_version, get_github_package_json, get_zip_package_json
from backend.typosquatting import detect_typosquatting
from backend.risk_engine import calculate_risk

class TestSecureChain(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
        
        from backend.storage import init_db, get_connection, create_user, find_user_by_email
        init_db()
        
        if not find_user_by_email("test@example.com"):
            create_user("test@example.com", "hash")
            
        user = find_user_by_email("test@example.com")
        
        with get_connection() as conn:
            workspace = conn.execute("SELECT id FROM workspaces WHERE owner_id = ?", (user['id'],)).fetchone()
            workspace_id = workspace['id'] if workspace else 1

        with self.app.session_transaction() as sess:
            sess['user_id'] = user['id']
            sess['user_email'] = user['email']
            sess['workspace_id'] = workspace_id

    def test_normalize_version(self):
        self.assertEqual(normalize_version("2.31.0"), "2.31.0")
        self.assertEqual(normalize_version("^2.31.0"), "2.31.0")
        self.assertEqual(normalize_version("~2.31.0"), "2.31.0")
        self.assertEqual(normalize_version(">=1.0.0 <2.0.0"), "1.0.0")

    def test_typosquatting_detection(self):
        self.assertIsNotNone(detect_typosquatting("requets"))
        self.assertIsNone(detect_typosquatting("requests"))

    def test_risk_calculation(self):
        findings = [{"severity": "CRITICAL"}]
        typo = [{"severity": "HIGH"}]
        score, level = calculate_risk(findings, typo)
        self.assertEqual(score, 70)
        self.assertEqual(level, "HIGH")

    def test_login_redirect(self):
        with self.app.session_transaction() as sess:
            sess['user_id'] = None
        
        # Test that login without auth renders auth template
        res = self.app.get('/login')
        self.assertEqual(res.status_code, 200)

    def test_invalid_zip(self):
        data = {"upload_source": "zip", "zip_file": (io.BytesIO(b"not a zip"), "test.zip")}
        res = self.app.post('/upload', data=data, content_type='multipart/form-data')
        self.assertEqual(res.status_code, 422)

    def test_missing_package_json_zip(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z:
            z.writestr("test.txt", "hello")
        buf.seek(0)
        
        data = {"upload_source": "zip", "zip_file": (buf, "test.zip")}
        res = self.app.post('/upload', data=data, content_type='multipart/form-data')
        self.assertEqual(res.status_code, 400)
        self.assertIn(b"No package.json", res.data)

    def test_github_url_validation(self):
        data = {"upload_source": "github", "github_url": "invalid_url"}
        res = self.app.post('/upload', data=data)
        self.assertEqual(res.status_code, 400)
        self.assertIn(b"valid public GitHub repository URL", res.data)

if __name__ == '__main__':
    unittest.main()
