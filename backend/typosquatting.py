from difflib import SequenceMatcher


# Small reference list for our MVP.
# Later we can expand this using real package metadata.
POPULAR_PACKAGES = [
    "requests",
    "express",
    "cross-env",
    "axios",
    "lodash",
    "react",
    "react-dom",
    "flask",
    "django",
    "numpy",
    "pandas",
]


def similarity(package_a, package_b):
    """Return name similarity between 0 and 1."""
    return SequenceMatcher(
        None,
        package_a.lower(),
        package_b.lower()
    ).ratio()


def detect_typosquatting(package_name):
    """
    Check whether a package name is suspiciously similar
    to a known popular package.
    """

    package_name = package_name.lower()

    # Exact popular package = not suspicious
    if package_name in POPULAR_PACKAGES:
        return None

    best_match = None
    best_score = 0.0

    for popular_package in POPULAR_PACKAGES:

        score = similarity(
            package_name,
            popular_package
        )

        if score > best_score:
            best_score = score
            best_match = popular_package

    # High similarity suggests a possible typo/look-alike.
    if best_score >= 0.80:

        return {
            "package": package_name,
            "possible_match": best_match,
            "similarity": round(best_score * 100, 2),
            "severity": "HIGH",
            "reason": (
                "Package name is highly similar to a popular "
                "package and may indicate typosquatting."
            ),
            "remediation": (
                "Verify the package publisher and source before "
                "using it. Remove it if it is not trusted."
            )
        }

    return None