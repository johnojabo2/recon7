import logging
import random
import re
import smtplib
import socket
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Tuple
import dns.resolver

logger = logging.getLogger(__name__)


def resolve_mx_records(domain: str, timeout: int = 3) -> List[str]:
    """
    Resolves active Mail Exchanger (MX) hosts for a target domain using DNS.
    Returns sorted list of MX server hostnames by priority.
    """
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    resolver.timeout = timeout
    resolver.lifetime = timeout

    try:
        answers = resolver.resolve(domain, "MX")
        mx_records = sorted(answers, key=lambda r: r.preference)
        hosts = [str(r.exchange).rstrip(".") for r in mx_records]
        logger.info(f"[people.verifier] Discovered {len(hosts)} MX hosts for '{domain}': {hosts[:3]}")
        return hosts
    except Exception as e:
        logger.debug(f"MX record lookup failed for '{domain}': {e}")
        return []


def test_port25_connectivity(mx_host: str, timeout: float = 2.0) -> bool:
    """Fast check to see if outbound port 25 is reachable (not blocked by ISP/firewall)."""
    try:
        with socket.create_connection((mx_host, 25), timeout=timeout):
            return True
    except Exception:
        return False


def detect_catch_all(mx_host: str, domain: str, timeout: int = 3) -> bool:
    """
    Tests if an MX server is configured as a 'Catch-All' (accepts all incoming addresses).
    Sends a test RCPT TO with a randomized nonexistent canary mailbox.
    """
    rand_suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    canary_email = f"canary_{rand_suffix}@{domain}"

    try:
        with smtplib.SMTP(timeout=timeout) as server:
            server.connect(mx_host, 25)
            server.ehlo_or_helo_if_needed()
            server.mail("verify@recon7.local")
            code, _ = server.rcpt(canary_email)
            server.quit()

            if code in [250, 251]:
                logger.info(f"[people.verifier] Mail domain '{domain}' is CATCH-ALL (accepted canary code {code})")
                return True
    except Exception as e:
        logger.debug(f"Catch-all canary check on {mx_host} error: {e}")

    return False


def verify_single_email_smtp(
    email: str,
    mx_host: str,
    is_catch_all: bool,
    timeout: int = 3,
) -> Tuple[str, int, str]:
    """
    Performs non-intrusive SMTP RCPT TO deliverability check.
    Does NOT deliver email; disconnects immediately after receiving recipient response code.
    """
    if is_catch_all:
        return "catch_all", 85, "Domain MX active (Catch-All configuration)"

    try:
        with smtplib.SMTP(timeout=timeout) as server:
            server.connect(mx_host, 25)
            server.ehlo_or_helo_if_needed()
            server.mail("verify@recon7.local")
            code, resp_msg = server.rcpt(email)
            server.quit()

            resp_str = resp_msg.decode("utf-8", errors="ignore") if isinstance(resp_msg, bytes) else str(resp_msg)

            if code in [250, 251]:
                return "deliverable", 99, f"SMTP 250 OK via {mx_host}"
            elif code in [550, 551, 552, 553, 554]:
                return "undeliverable", 10, f"SMTP {code} User Not Found ({resp_str[:30]})"
            elif code in [421, 450, 451, 452]:
                return "unverified", 75, f"SMTP {code} Greylisted / Rate-limited"
    except Exception as e:
        logger.debug(f"SMTP check error on {mx_host} for {email}: {e}")

    return "unverified", 70, "MX active; SMTP probe unconfirmed"


ROLE_MAILBOX_PREFIXES = {
    "info", "contact", "contactus", "support", "help", "sales", "admin", "administrator",
    "jobs", "careers", "press", "media", "hello", "team", "security", "billing", "inbox",
    "general", "office", "enquiries", "inquiries", "helpdesk", "feedback", "newsletter",
    "postmaster", "webmaster", "marketing", "notifications", "community", "legal", "hr",
    "finance", "accounting", "operations", "dev", "engineering", "leads", "investorrelations",
    "nuims", "netco.enquiries", "nnpcretailcontact", "corp", "privacy", "compliance", "procurement",
    "tenders", "bids", "reception", "switchboard", "customercare", "customercareteam", "mail",
    "directcontact", "contact-us", "info-desk", "enquiry"
}


def is_role_mailbox(email: str) -> bool:
    """Returns True if the email is a generic role or department mailbox."""
    if not email or "@" not in email:
        return False
    local = email.split("@")[0].lower().strip()
    clean_local = re.sub(r"[^a-z0-9]", "", local)
    return local in ROLE_MAILBOX_PREFIXES or clean_local in ROLE_MAILBOX_PREFIXES


def induce_email_pattern(
    observed_emails: List[str],
    domain: str,
) -> Dict[str, Any]:
    """
    Mathematically induces the dominant corporate email naming convention
    strictly from confirmed HUMAN email seeds, ignoring generic role mailboxes.
    """
    domain_clean = domain.lower().strip()
    target_emails = [
        e.lower().strip() for e in observed_emails
        if e and "@" in e and e.lower().strip().endswith(domain_clean)
    ]

    human_seeds = [e for e in target_emails if not is_role_mailbox(e)]
    role_count = len(target_emails) - len(human_seeds)

    if not human_seeds:
        return {
            "pattern": "{first}.{last}@" + domain_clean,
            "pattern_code": "first.last",
            "confidence": 45,
            "sample_count": 0,
            "human_seed_count": 0,
            "role_mailbox_count": role_count,
            "status": "UNVERIFIED_DEFAULT",
            "breakdown": {},
            "description": f"Default baseline pattern (Zero verified human seeds found across {len(target_emails)} addresses; role inboxes excluded)",
        }

    pattern_counts: Dict[str, int] = {
        "first.last": 0,      # john.doe@domain.com
        "f.last": 0,          # j.doe@domain.com
        "flast": 0,           # jdoe@domain.com
        "first_last": 0,      # john_doe@domain.com
        "firstl": 0,          # johnd@domain.com
        "first": 0,           # john@domain.com
        "last.first": 0,      # doe.john@domain.com
        "lastf": 0,           # doej@domain.com
        "firstlast": 0,       # johndoe@domain.com
    }

    total_classified = 0

    for email in human_seeds:
        user_part = email.split("@")[0]
        if "." in user_part:
            parts = user_part.split(".")
            if len(parts) == 2:
                if len(parts[0]) == 1:
                    pattern_counts["f.last"] += 1
                else:
                    pattern_counts["first.last"] += 1
                total_classified += 1
        elif "_" in user_part:
            parts = user_part.split("_")
            if len(parts) == 2:
                pattern_counts["first_last"] += 1
                total_classified += 1
        elif "-" in user_part:
            parts = user_part.split("-")
            if len(parts) == 2:
                pattern_counts["first.last"] += 1
                total_classified += 1
        else:
            if len(user_part) <= 5:
                pattern_counts["first"] += 1
                total_classified += 1
            else:
                pattern_counts["flast"] += 1
                total_classified += 1

    if total_classified == 0:
        top_pattern = "first.last"
        conf = 45
        status = "UNVERIFIED_DEFAULT"
    else:
        top_pattern = max(pattern_counts, key=pattern_counts.get)
        top_count = pattern_counts[top_pattern]
        raw_ratio = top_count / total_classified
        if total_classified == 1:
            conf = int(min(65, raw_ratio * 65))
            status = "LOW_SAMPLE_INDUCED"
        elif total_classified == 2:
            conf = int(min(80, raw_ratio * 80))
            status = "MODERATE_SAMPLE_INDUCED"
        else:
            conf = int(min(99, raw_ratio * 100))
            status = "HIGH_CONFIDENCE_INDUCED"

    pattern_map = {
        "first.last": "{first}.{last}@" + domain_clean,
        "f.last": "{f}.{last}@" + domain_clean,
        "flast": "{f}{last}@" + domain_clean,
        "first_last": "{first}_{last}@" + domain_clean,
        "firstl": "{first}{l}@" + domain_clean,
        "first": "{first}@" + domain_clean,
        "last.first": "{last}.{first}@" + domain_clean,
        "lastf": "{last}{f}@" + domain_clean,
        "firstlast": "{first}{last}@" + domain_clean,
    }

    return {
        "pattern": pattern_map.get(top_pattern, "{first}.{last}@" + domain_clean),
        "pattern_code": top_pattern,
        "confidence": conf,
        "sample_count": total_classified,
        "human_seed_count": len(human_seeds),
        "role_mailbox_count": role_count,
        "status": status,
        "breakdown": pattern_counts,
        "description": f"Induced syntax: {pattern_map.get(top_pattern)} ({conf}% confidence across {total_classified} human seeds)",
    }


def synthesize_candidate_email(
    name: str,
    pattern_code: str,
    domain: str,
) -> Optional[str]:
    """
    Synthesizes a candidate corporate email for a person's name based on induced pattern.
    """
    if not name or not domain:
        return None

    cleaned_name = re.sub(r"[^a-zA-Z\s]", "", name).strip().lower()
    parts = cleaned_name.split()
    if len(parts) < 2:
        return None

    first = parts[0]
    last = parts[-1]
    f = first[0] if first else ""
    l = last[0] if last else ""
    domain_clean = domain.lower().strip()

    if pattern_code == "first.last":
        return f"{first}.{last}@{domain_clean}"
    elif pattern_code == "f.last":
        return f"{f}.{last}@{domain_clean}"
    elif pattern_code == "flast":
        return f"{f}{last}@{domain_clean}"
    elif pattern_code == "first_last":
        return f"{first}_{last}@{domain_clean}"
    elif pattern_code == "firstl":
        return f"{first}{l}@{domain_clean}"
    elif pattern_code == "first":
        return f"{first}@{domain_clean}"
    elif pattern_code == "last.first":
        return f"{last}.{first}@{domain_clean}"
    elif pattern_code == "lastf":
        return f"{last}{f}@{domain_clean}"
    elif pattern_code == "firstlast":
        return f"{first}{last}@{domain_clean}"

    return f"{first}.{last}@{domain_clean}"


def batch_verify_emails(
    people_records: List[Dict[str, Any]],
    domain: str,
    timeout: int = 15,
) -> List[Dict[str, Any]]:
    """
    Batch processes deliverability verification across all extracted email candidates.
    Applies RocketReach-style scoring and status tags.
    """
    mx_hosts = resolve_mx_records(domain)
    is_catch_all = False
    port25_reachable = False

    if mx_hosts:
        port25_reachable = test_port25_connectivity(mx_hosts[0], timeout=2.0)
        if port25_reachable:
            is_catch_all = detect_catch_all(mx_hosts[0], domain, timeout=3)
        else:
            logger.info(f"[people.verifier] Outbound port 25 probe shielded/blocked; applying MX-validated pattern scoring")

    # Induce corporate email pattern across human email seeds
    observed_emails = [p.get("email") for p in people_records if p.get("email")]
    pattern_info = induce_email_pattern(observed_emails, domain)

    def process_person(p: Dict[str, Any]) -> Dict[str, Any]:
        email = p.get("email", "").strip().lower()
        name = p.get("name", "").strip()
        is_human = p.get("is_human", True)
        entity_type = p.get("entity_type", "human")

        # Never synthesize candidate emails for non-human corporate/brand handles!
        if not is_human or entity_type in ["corporate_directory", "regional_account", "subsidiary_brand", "system_bot"]:
            p["deliverability"] = "corporate_handle"
            p["verification_status"] = "Corporate Handle"
            p["verification_details"] = "Non-human corporate directory / brand profile"
            p["confidence"] = 90
            return p

        # If no direct email exists but valid human name is present, synthesize candidate corporate email
        if not email and name:
            synth_email = synthesize_candidate_email(name, pattern_info["pattern_code"], domain)
            if synth_email:
                p["email"] = synth_email
                p["inferred"] = True
                email = synth_email

        if not email or "@" not in email:
            p["deliverability"] = "no_email"
            p["verification_status"] = "Public Handle"
            p["verification_details"] = "Profile link without direct email"
            return p

        is_direct_scrape = not p.get("inferred", False)

        if not mx_hosts:
            p["deliverability"] = "mx_missing"
            p["confidence"] = 50
            p["verification_status"] = "No MX Records"
            p["verification_details"] = "Target domain has no mail exchangers"
            return p

        if port25_reachable:
            status, conf, details = verify_single_email_smtp(email, mx_hosts[0], is_catch_all, timeout=3)
        else:
            status = "mx_valid"
            conf = 90 if is_direct_scrape else (pattern_info.get("confidence", 60))
            details = f"MX Active ({mx_hosts[0]})"

        if status == "deliverable":
            final_conf = 99
            status_label = "SMTP Deliverable (250 OK)"
        elif is_direct_scrape:
            final_conf = 92
            status_label = "Direct Scrape Verified"
        elif status == "catch_all":
            final_conf = 80 if is_direct_scrape else 70
            status_label = "Catch-All Mailbox"
        elif status == "undeliverable":
            final_conf = 10
            status_label = "Mailbox Not Found"
        else:
            if pattern_info.get("status") == "UNVERIFIED_DEFAULT":
                final_conf = 45
                status_label = "Synthetic (Uncorroborated Pattern)"
            else:
                final_conf = pattern_info.get("confidence", 65)
                status_label = "Dominant Pattern Match"

        p["deliverability"] = status
        p["confidence"] = final_conf
        p["verification_status"] = status_label
        p["verification_details"] = details
        p["email_pattern"] = pattern_info["pattern"]
        return p

    # Execute with worker threads for sub-second execution
    results = []
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(process_person, dict(p)) for p in people_records]
        for f in as_completed(futures):
            try:
                results.append(f.result())
            except Exception as e:
                logger.debug(f"Verification worker error: {e}")

    return results
