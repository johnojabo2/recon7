import os
import logging
import re
from typing import List, Dict, Any, Set, Optional
import httpx
from core.config import settings

logger = logging.getLogger(__name__)

EMAIL_REGEX = re.compile(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)")


def get_github_headers(token: Optional[str] = None) -> Dict[str, str]:
    """
    Builds GitHub API headers.
    If a Personal Access Token (PAT) is provided or configured in settings/env,
    it attaches Bearer authentication to increase rate limits from 60/hr to 5,000/hr.
    If absent, falls back gracefully to default unauthenticated settings.
    """
    pat = (token or getattr(settings, "GITHUB_TOKEN", None) or os.getenv("GITHUB_TOKEN") or "").strip()

    headers = {
        "User-Agent": "R7-ReconEngine/1.0",
        "Accept": "application/vnd.github.v3+json",
    }

    if pat:
        # GitHub Personal Access Tokens (classic ghp_... or fine-grained github_pat_...)
        auth_prefix = "Bearer" if (pat.startswith("ghp_") or pat.startswith("github_pat_")) else "token"
        headers["Authorization"] = f"{auth_prefix} {pat}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
        logger.info("[people.github_enum] Authenticated with GitHub PAT (higher 5,000 req/hr quota active)")
    else:
        logger.info("[people.github_enum] Querying GitHub in default unauthenticated mode (60 req/hr quota)")

    return headers


def enumerate_github_commits(
    domain: str,
    org_name: Optional[str] = None,
    token: Optional[str] = None,
    timeout: int = 10,
) -> List[Dict[str, Any]]:
    """
    Queries public GitHub API for commit authors, public users, and org members.
    Extracts verified employee names, profile links, and commit author emails.
    Automatically uses GitHub PAT if provided or configured in settings.
    """
    logger.info(f"[people.github_enum] Querying GitHub events/commits for '{domain}'")
    results: List[Dict[str, Any]] = []
    seen_emails: Set[str] = set()
    seen_profiles: Set[str] = set()

    org_guess = org_name if org_name else domain.split(".")[0]
    org_candidates = list(set([org_guess.replace(" ", ""), domain.split(".")[0], f"{domain.split('.')[0]}HQ"]))

    headers = get_github_headers(token=token)

    def check_rate_limit(resp: httpx.Response) -> bool:
        if resp.status_code in (403, 429):
            remaining = resp.headers.get("x-ratelimit-remaining")
            if remaining == "0" or "rate limit" in resp.text.lower():
                logger.warning(
                    "[people.github_enum] GitHub API rate limit reached. "
                    "Configure a GitHub PAT in API Integrations to increase quota."
                )
                return True
        return False

    with httpx.Client(timeout=timeout, headers=headers) as client:
        # 1. Search public commits matching domain
        try:
            url = f"https://api.github.com/search/commits?q=author-email:{domain}&sort=author-date&order=desc"
            resp = client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("items", []):
                    commit = item.get("commit", {})
                    author = commit.get("author", {})
                    name = author.get("name", "")
                    email = author.get("email", "").lower().strip()
                    author_obj = item.get("author") or {}
                    html_url = author_obj.get("html_url", "")

                    if email and domain in email and email not in seen_emails:
                        if not email.endswith("noreply.github.com"):
                            seen_emails.add(email)
                            results.append({
                                "name": name,
                                "email": email,
                                "title": "GitHub Commit Author",
                                "profile_url": html_url,
                                "platform": "GitHub",
                                "confidence": 90,
                                "source": "github_commits",
                            })
            else:
                check_rate_limit(resp)
        except Exception as e:
            logger.debug(f"GitHub commit search failed: {e}")

        # 2. Query public user/org profiles for candidate names
        for cand in org_candidates:
            if not cand or len(cand) < 2:
                continue
            try:
                user_url = f"https://api.github.com/users/{cand}"
                resp = client.get(user_url)
                if resp.status_code == 200:
                    user_data = resp.json()
                    html_url = user_data.get("html_url", "")
                    name = user_data.get("name", "")
                    if html_url and html_url not in seen_profiles:
                        seen_profiles.add(html_url)
                        results.append({
                            "name": name if name else cand,
                            "email": user_data.get("email") or "",
                            "title": user_data.get("bio") or f"GitHub User ({user_data.get('type', 'User')})",
                            "profile_url": html_url,
                            "platform": "GitHub",
                            "confidence": 90,
                            "source": "github_user_api",
                        })
                else:
                    if check_rate_limit(resp):
                        break
            except Exception as e:
                logger.debug(f"GitHub user query for {cand} failed: {e}")

            # 3. Query public org events
            try:
                org_url = f"https://api.github.com/orgs/{cand}/events"
                resp = client.get(org_url)
                if resp.status_code == 200:
                    events = resp.json()
                    for ev in events:
                        payload = ev.get("payload", {})
                        commits = payload.get("commits", [])
                        for c in commits:
                            author = c.get("author", {})
                            name = author.get("name", "")
                            email = author.get("email", "").lower().strip()
                            if email and domain in email and email not in seen_emails:
                                if not email.endswith("noreply.github.com"):
                                    seen_emails.add(email)
                                    results.append({
                                        "name": name,
                                        "email": email,
                                        "title": "GitHub Contributor",
                                        "profile_url": f"https://github.com/{ev.get('actor', {}).get('login', '')}",
                                        "platform": "GitHub",
                                        "confidence": 90,
                                        "source": "github_org_events",
                                    })
                else:
                    if check_rate_limit(resp):
                        break
            except Exception as e:
                logger.debug(f"GitHub org event search failed for {cand}: {e}")

    logger.info(f"[people.github_enum] Discovered {len(results)} author and member findings from GitHub")
    return results
