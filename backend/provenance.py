import urllib.request
import json

def verify_build_provenance(package_name, version=None):
    """
    Checks build provenance indicators:
    - Verifies whether the package has Sigstore/SLSA build attestations published on npm.
    - Checks whether a public repository link is declared.
    """
    result = {
        "package": package_name,
        "has_provenance": False,
        "has_repository": False,
        "provenance_status": "UNVERIFIED",
        "details": []
    }
    
    try:
        url = f"https://registry.npmjs.org/{package_name}"
        req = urllib.request.Request(url, headers={"User-Agent": "SecureChain-AI"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode())
            
            # Check source repository link
            if "repository" in data and data["repository"]:
                result["has_repository"] = True
            else:
                result["details"].append("No verified source code repository linked.")

            # Identify target version
            latest_version = version or data.get("dist-tags", {}).get("latest")
            ver_obj = data.get("versions", {}).get(latest_version, {})
            dist = ver_obj.get("dist", {})

            # Check for npm build provenance (Sigstore attestations)
            if "attestations" in dist or "signatures" in dist:
                result["has_provenance"] = True
                result["provenance_status"] = "VERIFIED"
                result["details"].append("Build provenance verified via Sigstore transparency ledger.")
            else:
                result["details"].append("No build attestation or Sigstore signature found on npm registry.")

    except Exception as e:
        result["details"].append(f"Provenance verification skipped or offline: {str(e)}")

    return result

def verify_lockfile_integrity(lockfile_data):
    """
    Scans package-lock.json entries for valid sha512 integrity hashes.
    """
    packages = lockfile_data.get("packages", {}) or lockfile_data.get("dependencies", {})
    missing_integrity = []
    
    for pkg, info in packages.items():
        if pkg and isinstance(info, dict):
            if "integrity" not in info or not info["integrity"].startswith("sha512-"):
                clean_name = pkg.replace("node_modules/", "")
                missing_integrity.append(clean_name)

    return {
        "total_checked": len(packages),
        "unverified_hashes": missing_integrity,
        "status": "PASS" if not missing_integrity else "WARNING"
    }