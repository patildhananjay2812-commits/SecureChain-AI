from copy import deepcopy
from io import BytesIO
import ssl
ssl._create_default_https_context = ssl._create_unverified_context

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

import os
import json
import re

from zipfile import BadZipFile, ZipFile
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib import request as url_request

from werkzeug.security import check_password_hash, generate_password_hash

from vulnerability_db import VULNERABILITY_DB
from typosquatting import detect_typosquatting
from risk_engine import calculate_risk
from llm_advisor import answer_question, generate_advice

# Import new capabilities
from reputation import check_package_reputation
from provenance import verify_build_provenance, verify_lockfile_integrity
from storage import (
    create_scan,
    create_user,
    find_user_by_email,
    get_scan,
    get_workspace,
    list_scans,
)


app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config["SECRET_KEY"] = os.getenv(
    "SECURECHAIN_SECRET_KEY",
    "securechain-development-key"
)


# ---------------------------------------------------------
# Folder setup
# ---------------------------------------------------------

BASE_DIR = os.path.dirname(__file__)


# ---------------------------------------------------------
# Home page
# ---------------------------------------------------------

@app.route("/")
def home():
    return render_template(
        "index.html",
        current_user=current_user()
    )


def current_user():
    user_id = session.get("user_id")

    if not user_id:
        return None

    user = find_user_by_email(
        session.get("user_email", "")
    )

    return user if user and user["id"] == user_id else None


def require_user():
    user = current_user()

    if not user:
        return None, redirect(url_for("login"))

    return user, None


# ---------------------------------------------------------
# Register
# ---------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        if "@" not in email or len(email) > 254:

            flash(
                "Enter a valid email address.",
                "error"
            )

        elif len(password) < 8:

            flash(
                "Password must be at least 8 characters.",
                "error"
            )

        elif find_user_by_email(email):

            flash(
                "An account with that email already exists.",
                "error"
            )

        else:

            user = create_user(
                email,
                generate_password_hash(password)
            )

            session.clear()

            session.update(user)

            return redirect(
                url_for("home")
            )

    return render_template(
        "auth.html",
        mode="register",
        current_user=current_user()
    )


# ---------------------------------------------------------
# Login
# ---------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        user = find_user_by_email(email)

        if not user or not check_password_hash(
            user["password_hash"],
            password
        ):

            flash(
                "Email or password is incorrect.",
                "error"
            )

        else:

            workspace = get_workspace_for_user(
                user["id"]
            )

            session.clear()

            session.update({
                "user_id": user["id"],
                "user_email": user["email"],
                "workspace_id": workspace["id"],
            })

            # FIX:
            # Do not redirect back to /upload.
            # /upload accepts POST only.
            return redirect(
                url_for("home")
            )

    return render_template(
        "auth.html",
        mode="login",
        current_user=current_user()
    )


# ---------------------------------------------------------
# Logout
# ---------------------------------------------------------

@app.route("/logout", methods=["POST"])
def logout():

    session.clear()

    return redirect(
        url_for("home")
    )


# ---------------------------------------------------------
# Workspace
# ---------------------------------------------------------

def get_workspace_for_user(user_id):

    from storage import get_connection

    with get_connection() as connection:

        row = connection.execute(
            """
            SELECT id, name
            FROM workspaces
            WHERE owner_id = ?
            ORDER BY id
            LIMIT 1
            """,
            (user_id,),
        ).fetchone()

        return dict(row) if row else None


# ---------------------------------------------------------
# History
# ---------------------------------------------------------

@app.route("/history")
def history():

    user, redirect_response = require_user()

    if redirect_response:
        return redirect_response

    scans = list_scans(
        session["workspace_id"],
        user["id"]
    )

    return render_template(
        "history.html",
        scans=scans,
        current_user=user
    )


@app.route("/history/<int:scan_id>")
def history_detail(scan_id):

    user, redirect_response = require_user()

    if redirect_response:
        return redirect_response

    scan = get_scan(
        scan_id,
        session["workspace_id"],
        user["id"]
    )

    if not scan:
        return "Scan not found.", 404

    return render_template(
        "scan_detail.html",
        scan=scan,
        current_user=user
    )


# ---------------------------------------------------------
# AI Question
# ---------------------------------------------------------

@app.route("/ask", methods=["POST"])
def ask():

    data = request.get_json(
        silent=True
    ) or {}

    question = str(
        data.get("question", "")
    )[:1000]

    scan_context = data.get(
        "scan_context",
        {}
    )

    if not isinstance(scan_context, dict):
        scan_context = {}

    return {
        "answer": answer_question(
            question,
            scan_context
        )
    }


# ---------------------------------------------------------
# Export remediated package.json
# ---------------------------------------------------------

@app.route(
    "/export-remediated-manifest",
    methods=["POST"]
)
def export_remediated_manifest():

    data = request.get_json(
        silent=True
    ) or request.form

    try:

        package_data = data.get(
            "package_data"
        )

        if isinstance(package_data, str):

            package_data = json.loads(
                package_data
            )

        typosquatting_findings = data.get(
            "typosquatting_findings",
            []
        )

        findings = data.get(
            "findings",
            []
        )

        if isinstance(
            typosquatting_findings,
            str
        ):

            typosquatting_findings = json.loads(
                typosquatting_findings
            )

        if isinstance(findings, str):

            findings = json.loads(
                findings
            )

    except (
        TypeError,
        json.JSONDecodeError
    ):

        return {
            "error": "The remediation data is invalid."
        }, 400

    if not isinstance(
        package_data,
        dict
    ):

        return {
            "error": "A valid package.json manifest is required."
        }, 400

    remediated = deepcopy(
        package_data
    )

    removed_packages = {
        str(
            finding.get(
                "package",
                ""
            )
        ).lower()

        for finding in typosquatting_findings

        if isinstance(
            finding,
            dict
        )
    }

    dependency_sections = (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    )

    for section in dependency_sections:

        dependencies = remediated.get(
            section
        )

        if not isinstance(
            dependencies,
            dict
        ):
            continue

        for package_name in list(
            dependencies
        ):

            if package_name.lower() in removed_packages:

                del dependencies[
                    package_name
                ]

    fixed_versions = {}

    for finding in findings:

        if not isinstance(
            finding,
            dict
        ):
            continue

        package_name = str(
            finding.get(
                "name",
                ""
            )
        ).lower()

        vulnerability = VULNERABILITY_DB.get(
            package_name,
            {}
        )

        clean_version = normalize_version(
            finding.get(
                "version",
                ""
            )
        )

        if (
            vulnerability.get("fixed_version")
            and clean_version
            == vulnerability.get("affected_version")
        ):

            fixed_versions[
                package_name
            ] = vulnerability[
                "fixed_version"
            ]

    for section in dependency_sections:

        dependencies = remediated.get(
            section
        )

        if not isinstance(
            dependencies,
            dict
        ):
            continue

        for package_name, fixed_version in fixed_versions.items():

            matching_name = next(
                (
                    name
                    for name in dependencies
                    if name.lower() == package_name
                ),
                None
            )

            if matching_name:

                original_version = str(
                    dependencies[
                        matching_name
                    ]
                )

                prefix = original_version[
                    :len(original_version)
                    - len(
                        original_version.lstrip("^~")
                    )
                ]

                dependencies[
                    matching_name
                ] = f"{prefix}{fixed_version}"

    project_name = str(
        data.get(
            "project_name",
            "securechain"
        )
    )

    filename = "".join(
        character
        if character.isalnum()
        or character in "-_."
        else "_"
        for character in project_name
    ) or "securechain"

    payload = json.dumps(
        remediated,
        indent=2,
        ensure_ascii=False
    ).encode("utf-8")

    return send_file(
        BytesIO(payload),
        mimetype="application/json",
        as_attachment=True,
        download_name=f"{filename}-package.remediated.json"
    )


# ---------------------------------------------------------
# Repository & Archive Analysis
# ---------------------------------------------------------

@app.route(
    "/upload",
    methods=["POST"]
)
def upload():

    user, redirect_response = require_user()

    if redirect_response:
        return redirect_response

    upload_source = request.form.get(
        "upload_source",
        "github"
    ).strip().lower()

    github_url = request.form.get(
        "github_url",
        ""
    ).strip()

    zip_file = request.files.get(
        "zip_file"
    )

    try:

        if upload_source == "zip":

            project_name, package_data, lock_data = (
                get_zip_package_json(
                    zip_file
                )
            )

        elif upload_source == "github":

            project_name, package_data, lock_data = (
                get_github_package_json(
                    github_url
                )
            )

        else:

            raise ValueError(
                "Choose either GitHub repository or ZIP file analysis."
            )

    except ValueError as error:
        return render_template("index.html", error=str(error), current_user=user), 400
    except BadZipFile:
        return render_template("index.html", error="The uploaded file is not a valid ZIP archive.", current_user=user), 422
    except HTTPError as e:
        if e.code == 404:
            return render_template("index.html", error="The GitHub repository or file could not be found.", current_user=user), 404
        elif e.code == 403:
            return render_template("index.html", error="GitHub API rate limit exceeded or access forbidden.", current_user=user), 403
        else:
            return render_template("index.html", error=f"GitHub API error: {e.code}", current_user=user), 502
    except TimeoutError:
        return render_template("index.html", error="Connection to GitHub timed out.", current_user=user), 504
    except URLError:
        return render_template("index.html", error="Network error while connecting to GitHub.", current_user=user), 502
    except json.JSONDecodeError:
        return render_template("index.html", error="The repository package.json contains invalid JSON.", current_user=user), 422


    # -----------------------------------------------------
    # Extract dependencies
    # -----------------------------------------------------

    dependencies = package_data.get(
        "dependencies",
        {}
    )

    dev_dependencies = package_data.get(
        "devDependencies",
        {}
    )

    all_dependencies = {}

    all_dependencies.update(
        dependencies
    )

    all_dependencies.update(
        dev_dependencies
    )


    # =====================================================
    # VULNERABILITY ANALYSIS
    # =====================================================

    findings = []

    for name, version in all_dependencies.items():

        package_key = str(
            name
        ).lower()

        clean_version = normalize_version(
            version
        )

        if package_key in VULNERABILITY_DB:

            vuln = VULNERABILITY_DB[
                package_key
            ]

            if clean_version == vuln.get(
                "affected_version"
            ):

                findings.append({
                    "name": name,
                    "version": version,
                    "severity": vuln.get(
                        "severity",
                        "MEDIUM"
                    ),
                    "description": vuln.get(
                        "description",
                        "Vulnerability detected."
                    ),
                    "remediation": vuln.get(
                        "remediation",
                        "Update to the latest version."
                    )
                })

            else:

                findings.append({
                    "name": name,
                    "version": version,
                    "severity": "LOW",
                    "description": (
                        "No matching demo vulnerability "
                        "was found for this version."
                    ),
                    "remediation": (
                        "Keep this dependency updated."
                    )
                })

        else:

            findings.append({
                "name": name,
                "version": version,
                "severity": "UNKNOWN",
                "description": (
                    "Package is not present in the "
                    "demo vulnerability database."
                ),
                "remediation": (
                    "Verify the package using a "
                    "trusted vulnerability source."
                )
            })


    # =====================================================
    # TYPOSQUATTING ANALYSIS
    # =====================================================

    typosquatting_findings = []

    for name in all_dependencies:

        result = detect_typosquatting(
            name
        )

        if result:

            typosquatting_findings.append(
                result
            )


    # =====================================================
    # PACKAGE REPUTATION & BUILD PROVENANCE CHECKS
    # =====================================================

    reputation_findings = []
    provenance_findings = []

    for name, version in all_dependencies.items():

        clean_ver = (
            str(version)
            .replace("^", "")
            .replace("~", "")
            .strip()
        )

        rep = check_package_reputation(
            name
        )

        prov = verify_build_provenance(
            name,
            clean_ver
        )

        reputation_findings.append(
            rep
        )

        provenance_findings.append(
            prov
        )

    lockfile_integrity = (
        verify_lockfile_integrity(
            lock_data
        )
        if lock_data
        else {
            "status": "NOT_PROVIDED",
            "missing_hashes": [],
            "total_packages": 0
        }
    )


    # =====================================================
    # RISK SCORE & ADVICE
    # =====================================================

    risk_score, risk_level = calculate_risk(
        findings,
        typosquatting_findings
    )

    recommendations = build_recommendations(
        findings,
        typosquatting_findings,
        reputation_findings,
        provenance_findings,
        risk_level
    )

    llm_advice = generate_advice(
        project_name,
        findings,
        typosquatting_findings,
        risk_score,
        risk_level
    )

    scan_id = create_scan(
        session["workspace_id"],
        project_name,
        upload_source,
        risk_score,
        risk_level,
        len(all_dependencies),
        findings,
        typosquatting_findings,
        package_data,
    )


    # =====================================================
    # RESULTS PAGE
    # =====================================================

    return render_template(
        "results.html",
        project_name=project_name,
        dependencies=all_dependencies,
        dependency_count=len(all_dependencies),
        findings=findings,
        typosquatting_findings=typosquatting_findings,
        reputation_findings=reputation_findings,
        provenance_findings=provenance_findings,
        lockfile_integrity=lockfile_integrity,
        risk_score=risk_score,
        risk_level=risk_level,
        recommendations=recommendations,
        llm_advice=llm_advice,
        package_data=package_data,
        scan_id=scan_id,
        current_user=user,
    )


# ---------------------------------------------------------
# Recommendations
# ---------------------------------------------------------

def build_recommendations(
    findings,
    typosquatting_findings,
    reputation_findings,
    provenance_findings,
    risk_level
):

    recommendations = []

    urgent_findings = [
        finding
        for finding in findings
        if str(
            finding.get(
                "severity",
                ""
            )
        ).upper()
        in (
            "CRITICAL",
            "HIGH"
        )
    ]

    for finding in urgent_findings:

        recommendations.append({
            "priority": "URGENT",
            "title": (
                f"Update or remove {finding['name']}"
            ),
            "text": (
                f"Version {finding['version']} "
                f"is marked "
                f"{finding['severity'].upper()}. "
                f"{finding['remediation']}"
            )
        })

    for finding in typosquatting_findings:

        recommendations.append({
            "priority": "URGENT",
            "title": (
                f"Verify or remove "
                f"{finding.get('package', 'unknown')}"
            ),
            "text": (
                f"It closely resembles "
                f"{finding.get('possible_match', 'popular package')} "
                "and may be a typosquatting package. "
                "Check the publisher before installing it."
            )
        })


    # Provenance flags

    unverified_provenance = [
        p
        for p in provenance_findings
        if p.get(
            "provenance_status"
        ) != "VERIFIED"
    ]

    if unverified_provenance:

        recommendations.append({
            "priority": "REVIEW",
            "title": "Unverified Build Provenance",
            "text": (
                f"{len(unverified_provenance)} package(s) "
                "lack cryptographic SLSA/Sigstore build "
                "attestations on the public registry."
            )
        })


    # Reputation flags

    high_rep_risks = [
        r
        for r in reputation_findings
        if r.get(
            "reputation_risk"
        ) == "HIGH"
    ]

    for r in high_rep_risks:

        recommendations.append({
            "priority": "URGENT",
            "title": (
                f"Suspicious reputation: "
                f"{r['package']}"
            ),
            "text": " ".join(
                r.get(
                    "flags",
                    [
                        "Package has low community trust "
                        "or was recently published."
                    ]
                )
            )
        })


    unknown_count = sum(
        1
        for finding in findings
        if str(
            finding.get(
                "severity",
                ""
            )
        ).upper() == "UNKNOWN"
    )

    if unknown_count:

        recommendations.append({
            "priority": "REVIEW",
            "title": "Review unverified dependencies",
            "text": (
                f"{unknown_count} package(s) are not in "
                "the demo vulnerability database. "
                "Check their advisories, maintainers, "
                "download source, and release history."
            )
        })


    if risk_level in (
        "HIGH",
        "CRITICAL"
    ):

        recommendations.append({
            "priority": "NEXT STEP",
            "title": (
                "Run a dependency audit before release"
            ),
            "text": (
                "Run npm audit, review the dependency "
                "lockfile, and retest the application "
                "after upgrades before merging or deploying."
            )
        })

    elif findings or typosquatting_findings:

        recommendations.append({
            "priority": "NEXT STEP",
            "title": "Keep dependencies maintained",
            "text": (
                "Update dependencies regularly, "
                "commit the lockfile, and run an "
                "automated dependency audit in CI."
            )
        })


    if not recommendations:

        recommendations.append({
            "priority": "GOOD",
            "title": "No urgent dependency action found",
            "text": (
                "Continue monitoring dependencies and "
                "keep the project lockfile up to date."
            )
        })

    return recommendations


# ---------------------------------------------------------
# Version normalization
# ---------------------------------------------------------

def normalize_version(version):
    """
    Extract a comparable semver from common
    package.json version ranges.
    """

    # FIXED REGEX
    match = re.search(
        r"\d+\.\d+\.\d+",
        str(version)
    )

    return (
        match.group(0)
        if match
        else str(version).strip()
    )


# ---------------------------------------------------------
# GitHub package.json reader
# ---------------------------------------------------------

def get_github_package_json(github_url):
    """
    Find and read package.json and optional
    package-lock.json from a public GitHub repository.
    """

    parsed_url = urlparse(
        github_url
    )

    if (
        parsed_url.scheme
        not in ("http", "https")
        or parsed_url.netloc.lower()
        != "github.com"
    ):

        raise ValueError(
            "Please enter a valid public GitHub repository URL."
        )

    path_parts = [
        part
        for part in parsed_url.path.split("/")
        if part
    ]

    if len(path_parts) < 2:
        raise ValueError(
            "Use a repository URL in this format: "
            "https://github.com/owner/repository"
        )

    owner = path_parts[0]
    repository = path_parts[1]

    repository = repository.removesuffix(
        ".git"
    )

    repository_name = (
        f"{owner}/{repository}"
    )

    api_headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "SecureChain-AI",
    }

    repository_url = (
        f"https://api.github.com/repos/"
        f"{quote(owner)}/"
        f"{quote(repository)}"
    )

    repository_data = read_json_url(
        repository_url,
        api_headers
    )

    default_branch = repository_data.get(
        "default_branch"
    )

    if not default_branch:

        raise ValueError(
            "The GitHub repository does not have a default branch."
        )

    tree_url = (
        f"{repository_url}/git/trees/"
        f"{quote(default_branch, safe='')}"
        "?recursive=1"
    )

    tree_data = read_json_url(
        tree_url,
        api_headers
    )

    blobs = {
        item["path"]: item
        for item in tree_data.get(
            "tree",
            []
        )
        if item.get("type") == "blob"
    }

    package_files = [
        path
        for path in blobs
        if path.lower().endswith(
            "package.json"
        )
    ]

    if not package_files:

        raise ValueError(
            "No package.json was found in this GitHub repository."
        )

    package_path = min(
        package_files,
        key=lambda path: path.count("/")
    )

    raw_url = (
        "https://raw.githubusercontent.com/"
        f"{quote(owner)}/"
        f"{quote(repository)}/"
        f"{quote(default_branch, safe='')}/"
        f"{quote(package_path, safe='/')}"
    )

    package_data = read_json_url(
        raw_url,
        {
            "User-Agent": "SecureChain-AI"
        }
    )


    # Check for optional lockfile

    lock_data = None

    lock_candidates = [
        path
        for path in blobs
        if path.lower().endswith(
            "package-lock.json"
        )
    ]

    if lock_candidates:

        lock_path = min(
            lock_candidates,
            key=lambda path: path.count("/")
        )

        lock_raw_url = (
            "https://raw.githubusercontent.com/"
            f"{quote(owner)}/"
            f"{quote(repository)}/"
            f"{quote(default_branch, safe='')}/"
            f"{quote(lock_path, safe='/')}"
        )

        try:

            lock_data = read_json_url(
                lock_raw_url,
                {
                    "User-Agent": "SecureChain-AI"
                }
            )

        except Exception:

            lock_data = None

    return (
        repository_name,
        package_data,
        lock_data
    )


# ---------------------------------------------------------
# ZIP package.json reader
# ---------------------------------------------------------

def get_zip_package_json(zip_file):
    """
    Read package.json and optional package-lock.json
    from an uploaded ZIP archive.
    """

    if (
        not zip_file
        or not zip_file.filename
    ):

        raise ValueError(
            "Choose a ZIP file to analyze."
        )

    if not zip_file.filename.lower().endswith(
        ".zip"
    ):

        raise ValueError(
            "Please upload a .zip file."
        )

    with ZipFile(
        zip_file.stream
    ) as archive:

        package_files = [
            info
            for info in archive.infolist()
            if not info.is_dir()
            and info.filename.lower().endswith(
                "package.json"
            )
        ]

        if not package_files:

            raise ValueError(
                "No package.json was found in the uploaded ZIP file."
            )

        package_info = min(
            package_files,
            key=lambda info: info.filename.replace(
                "\\",
                "/"
            ).count("/")
        )

        package_data = json.loads(
            archive.read(
                package_info
            ).decode("utf-8")
        )


        # Look for package-lock.json

        lock_files = [
            info
            for info in archive.infolist()
            if not info.is_dir()
            and info.filename.lower().endswith(
                "package-lock.json"
            )
        ]

        lock_data = None

        if lock_files:

            lock_info = min(
                lock_files,
                key=lambda info: info.filename.replace(
                    "\\",
                    "/"
                ).count("/")
            )

            try:

                lock_data = json.loads(
                    archive.read(
                        lock_info
                    ).decode("utf-8")
                )

            except Exception:

                lock_data = None

    project_name = os.path.splitext(
        os.path.basename(
            zip_file.filename
        )
    )[0]

    return (
        project_name,
        package_data,
        lock_data
    )


# ---------------------------------------------------------
# JSON URL reader
# ---------------------------------------------------------

def read_json_url(
    url,
    headers
):

    req = url_request.Request(
        url,
        headers=headers
    )

    import ssl
    context = ssl._create_unverified_context()
    
    with url_request.urlopen(
        req,
        timeout=10,
        context=context
    ) as response:

        return json.loads(
            response.read().decode(
                "utf-8"
            )
        )


# ---------------------------------------------------------
# Run application
# ---------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)
