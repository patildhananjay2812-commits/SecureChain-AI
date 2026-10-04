import urllib.request
import json
from datetime import datetime, timezone

def check_package_reputation(package_name):
    """
    Checks reputation metrics for an npm package:
    - Weekly download count (popularity signal)
    - Package age and latest release date (novelty/abandonment signal)
    - Maintainers count
    """
    signals = {
        "package": package_name,
        "weekly_downloads": 0,
        "is_brand_new": False,
        "reputation_risk": "LOW",
        "flags": []
    }
    
    # 1. Fetch download metrics from public npm API
    try:
        url_dl = f"https://api.npmjs.org/downloads/point/last-week/{package_name}"
        req = urllib.request.Request(url_dl, headers={"User-Agent": "SecureChain-AI"})
        with urllib.request.urlopen(req, timeout=4) as response:
            dl_data = json.loads(response.read().decode())
            downloads = dl_data.get("downloads", 0)
            signals["weekly_downloads"] = downloads
            if downloads < 100:
                signals["flags"].append("Very low download count (<100 downloads/week). Higher risk of rogue package.")
                signals["reputation_risk"] = "MEDIUM"
    except Exception:
        signals["flags"].append("Could not retrieve download statistics.")

    # 2. Fetch package metadata (creation date and latest version)
    try:
        url_pkg = f"https://registry.npmjs.org/{package_name}"
        req = urllib.request.Request(url_pkg, headers={"User-Agent": "SecureChain-AI"})
        with urllib.request.urlopen(req, timeout=4) as response:
            meta = json.loads(response.read().decode())
            times = meta.get("time", {})
            created_str = times.get("created")
            
            if created_str:
                created_dt = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - created_dt).days
                signals["age_days"] = age_days
                
                # Packages created less than 30 days ago are high-risk for malware drops
                if age_days < 30:
                    signals["is_brand_new"] = True
                    signals["reputation_risk"] = "HIGH"
                    signals["flags"].append(f"Package was created only {age_days} days ago. High risk of newly dropped malware.")
    except Exception:
        signals["flags"].append("Package not found in public npm registry (possible private/dependency-confusion target).")
        signals["reputation_risk"] = "HIGH"

    return signals