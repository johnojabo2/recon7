import logging
import re
from typing import List, Dict, Any, Optional, Tuple, Set

from core.scope import extract_root_domain
from people.harvester_wrapper import run_harvester
from people.site_crawler import crawl_site_for_people
from people.doc_metadata import extract_public_doc_metadata
from people.github_enum import enumerate_github_commits
from people.search_dork import search_dork_snippets
from people.wayback import extract_wayback_people
from people.verifier import batch_verify_emails
from people.linkedin_enum import enumerate_linkedin_profiles, is_valid_human_name
from people.pgp_enum import enumerate_pgp_keys

logger = logging.getLogger(__name__)

CDN_ISP_NAMES = {
    "cloudflarenet", "cloudflare", "amazon", "amazon-aes", "amazon-02",
    "google", "google-cloud", "microsoft", "microsoft-corp", "digitalocean",
    "linode", "hetzner", "ovh", "akamai", "fastly", "unknown", "none"
}


def aggregate_people_osint(
    domain: str,
    org_name: Optional[str] = None,
    seed_ceo: Optional[str] = None,
    subdomains: Optional[List[str]] = None,
    timeout: int = 60,
) -> Dict[str, Any]:
    """
    Step 8: Runs all people OSINT submodules with strict human identification filtering.
    Prioritizes real human employee profiles (LinkedIn, PGP keyservers, staff rosters, GitHub users),
    infers corporate email syntax, verifies deliverability, and separates human staff from corporate handles.
    Incorporates seed CEO / key worker names for precision pivot dorking.
    """
    root_domain = extract_root_domain(domain)
    domain_stem = root_domain.split(".")[0].capitalize()
    clean_org = domain_stem
    if org_name and org_name.lower().strip() not in CDN_ISP_NAMES:
        clean_org = org_name.strip()

    logger.info(f"[people.aggregate] Aggregating Human-Centric People OSINT for '{domain}' (Org: '{clean_org}', Seed Person: '{seed_ceo}')")
    
    raw_findings: List[Dict[str, Any]] = []

    # 0. Seed Intel Candidate
    if seed_ceo and len(seed_ceo.strip()) > 2:
        raw_findings.append({
            "name": seed_ceo.strip(),
            "email": "",
            "title": f"Key Leadership / Personnel at {clean_org}",
            "profile_url": "",
            "platform": "Seed Intel",
            "confidence": 100,
            "is_human": True,
            "source": "seed_input",
        })

    # 1. Dedicated LinkedIn Human OSINT Engine (Top Priority)
    try:
        raw_findings.extend(enumerate_linkedin_profiles(domain, org_name=clean_org, timeout=min(timeout, 20)))
    except Exception as e:
        logger.debug(f"LinkedIn enum module failed: {e}")

    # 1.5. Native SpiderFoot-inspired PGP Public Key Server Harvester (100% Ground Truth)
    try:
        raw_findings.extend(enumerate_pgp_keys(domain, timeout=min(timeout, 15)))
        if root_domain != domain:
            raw_findings.extend(enumerate_pgp_keys(root_domain, timeout=min(timeout, 15)))
    except Exception as e:
        logger.debug(f"PGP keyserver module failed: {e}")

    # 2. theHarvester
    try:
        raw_findings.extend(run_harvester(domain, timeout=timeout))
        if root_domain != domain:
            raw_findings.extend(run_harvester(root_domain, timeout=timeout))
    except Exception as e:
        logger.debug(f"Harvester module failed: {e}")

    # 3. Live Deep In-Scope Site Crawler (Team, Contact cards, Cloudflare XOR, JSON-LD)
    try:
        raw_findings.extend(crawl_site_for_people(domain, subdomains=subdomains, timeout=min(timeout, 20)))
    except Exception as e:
        logger.debug(f"Site crawler module failed: {e}")

    # 4. GitHub Commits & Contributors
    try:
        raw_findings.extend(enumerate_github_commits(domain, org_name=clean_org, timeout=min(timeout, 10)))
        if root_domain != domain:
            raw_findings.extend(enumerate_github_commits(root_domain, org_name=clean_org, timeout=min(timeout, 10)))
    except Exception as e:
        logger.debug(f"GitHub enum module failed: {e}")

    # 5. Advanced Search Engine OSINT Dorks
    try:
        raw_findings.extend(search_dork_snippets(domain, org_name=clean_org, seed_ceo=seed_ceo, timeout=min(timeout, 20)))
    except Exception as e:
        logger.debug(f"Search dork module failed: {e}")

    # 6. Document Full-Text Metadata (PDFs, Word docs, Spreadsheets, Historical Archives)
    doc_forensics_payload: Dict[str, Any] = {"entities": [], "document_exposures": [], "ad_usernames": [], "internal_paths": []}
    try:
        doc_forensics_payload = extract_public_doc_metadata(domain, org_name=clean_org, seed_ceo=seed_ceo, timeout=min(timeout, 20))
        raw_findings.extend(doc_forensics_payload.get("entities", []))
        if root_domain != domain:
            secondary_doc = extract_public_doc_metadata(root_domain, org_name=clean_org, seed_ceo=seed_ceo, timeout=min(timeout, 20))
            raw_findings.extend(secondary_doc.get("entities", []))
            doc_forensics_payload["document_exposures"].extend(secondary_doc.get("document_exposures", []))
            doc_forensics_payload["ad_usernames"].extend(secondary_doc.get("ad_usernames", []))
            doc_forensics_payload["internal_paths"].extend(secondary_doc.get("internal_paths", []))
    except Exception as e:
        logger.debug(f"Doc metadata module failed: {e}")

    # 7. Wayback Machine Historical Archives
    try:
        raw_findings.extend(extract_wayback_people(root_domain, timeout=min(timeout, 15)))
    except Exception as e:
        logger.debug(f"Wayback archive module failed: {e}")

    # 8. Discover Real Multi-Anchor Corporate Subsidiaries
    from people.subsidiaries import discover_corporate_subsidiaries
    from people.verifier import is_role_mailbox, induce_email_pattern
    from core.identity.resolution import classify_entity_type, is_valid_human_name, classify_department_and_seniority

    discovered_urls = [item.get("profile_url") or item.get("url") for item in raw_findings if item.get("profile_url") or item.get("url")]
    doc_snippets = [doc.get("title") or doc.get("filename") for doc in doc_forensics_payload.get("document_exposures", [])]
    verified_subsidiaries = discover_corporate_subsidiaries(
        parent_domain=root_domain,
        org_name=clean_org,
        candidate_urls_and_domains=discovered_urls + (subdomains or []),
        document_snippets=doc_snippets,
    )

    # 9. Strict Entity Classification Gate (Separating Humans vs Digital Footprint)
    human_people: Dict[str, Dict[str, Any]] = {}          # name/profile_url -> human person
    confirmed_human_emails: Dict[str, Dict[str, Any]] = {} # email -> human person
    role_mailboxes: Dict[str, Dict[str, Any]] = {}        # email -> generic inbox
    unresolved_footprint: List[Dict[str, Any]] = []       # corporate handles, regional accounts, brand profiles

    for item in raw_findings:
        raw_name = (item.get("name") or "").strip()
        email = (item.get("email") or "").strip().lower().rstrip(".")
        phone = (item.get("phone") or "").strip()
        title = (item.get("title") or "").strip() or "Staff / Member"
        profile_url = (item.get("profile_url") or item.get("url") or "").strip()
        platform = item.get("platform", "OSINT")
        source = item.get("source", "osint")
        confidence = item.get("confidence", 70)

        # Entity Classification Gate
        entity_type, class_reason = classify_entity_type(raw_name, title, profile_url)

        # Non-human entity routing (Corporate handles, regional accounts, subsidiary brands, bots)
        if entity_type != "human" and not (email and not is_role_mailbox(email)):
            if raw_name or profile_url:
                unresolved_footprint.append({
                    "name": raw_name or f"Official {platform} Asset",
                    "title": title,
                    "profile_url": profile_url,
                    "platform": platform,
                    "source": source,
                    "entity_type": entity_type,
                    "classification_reason": class_reason,
                    "email": email,
                    "confidence": 85,
                })
            continue

        # Handle Email Records
        if email:
            if is_role_mailbox(email):
                if email not in role_mailboxes:
                    role_mailboxes[email] = {
                        "name": raw_name or "Functional / Role Mailbox",
                        "email": email,
                        "title": title,
                        "profile_url": profile_url,
                        "platform": platform,
                        "source": source,
                        "is_human": False,
                        "deliverability": "role_mailbox",
                        "verification_status": "Role / Department Mailbox",
                    }
            else:
                # Confirmed Human Email
                if email not in confirmed_human_emails:
                    confirmed_human_emails[email] = {
                        "name": clean_person_name(raw_name).get("cleaned_name", raw_name) if raw_name else "",
                        "email": email,
                        "phone": phone,
                        "title": title,
                        "profile_url": profile_url,
                        "platform": platform,
                        "sources": [source],
                        "confidence": confidence,
                        "is_human": True,
                        "inferred": False,
                    }
                else:
                    confirmed_human_emails[email]["sources"].append(source)
                    if raw_name and not confirmed_human_emails[email]["name"]:
                        confirmed_human_emails[email]["name"] = clean_person_name(raw_name).get("cleaned_name", raw_name)

        # Handle Human Staff Profiles (No direct email)
        elif raw_name and is_valid_human_name(raw_name, clean_org):
            cleaned = clean_person_name(raw_name).get("cleaned_name", raw_name)
            key = cleaned.lower()
            if key not in human_people:
                human_people[key] = {
                    "name": cleaned,
                    "email": "",
                    "phone": phone,
                    "title": title,
                    "profile_url": profile_url,
                    "platform": platform,
                    "sources": [source],
                    "confidence": confidence,
                    "is_human": True,
                    "inferred": True,
                }
            else:
                human_people[key]["sources"].append(source)
                if profile_url and not human_people[key]["profile_url"]:
                    human_people[key]["profile_url"] = profile_url

    # 10. Statistical Corporate Email Pattern Induction (Strictly trained on human seeds!)
    human_email_list = list(confirmed_human_emails.keys())
    pattern_info = induce_email_pattern(human_email_list, root_domain)
    detected_pattern = pattern_info.get("pattern", f"{{first}}.{{last}}@{root_domain}")
    logger.info(f"[people.aggregate] Inferred syntax pattern for '{root_domain}': '{detected_pattern}' (Status: {pattern_info.get('status')}, {pattern_info.get('confidence')}% confidence)")

    # 11. Synthesize candidate emails strictly for biological human staff
    inferred_people: List[Dict[str, Any]] = []
    for key, p in human_people.items():
        name = p.get("name", "")
        clean_info = clean_person_name(name)
        if clean_info.get("title"):
            p["title"] = clean_info["title"]
        if clean_info.get("cleaned_name"):
            p["cleaned_name"] = clean_info["cleaned_name"]

        # Check if already covered in confirmed human emails
        if name and any(c.get("name", "").lower() in (name.lower(), clean_info.get("cleaned_name", "").lower()) for c in confirmed_human_emails.values()):
            continue

        inferred_email = ""
        if name and detected_pattern:
            inferred_email = generate_email_from_name(name, detected_pattern, root_domain) or ""

        p["email"] = inferred_email
        p["inferred"] = True if inferred_email else False
        inferred_people.append(p)

    # 12. Combine verified human staff only
    candidate_human_list = inferred_people + list(confirmed_human_emails.values())

    # 13. Deliverability & Verification Engine (MX Resolution + Catch-All + Non-intrusive SMTP Probe)
    logger.info(f"[people.aggregate] Running deliverability verification on {len(candidate_human_list)} human candidate profiles...")
    verified_people = batch_verify_emails(candidate_human_list, root_domain, timeout=min(timeout, 15))

    # 14. Classify Department, Seniority, HVT/HET status, and Temporal Status
    department_counts: Dict[str, int] = {}
    hvt_records: List[Dict[str, Any]] = []

    for p in verified_people:
        title = p.get("title", "")
        dept, seniority, is_hvt, is_het = classify_department_and_seniority(title)
        p["department"] = dept
        p["seniority"] = seniority
        p["is_hvt"] = is_hvt
        p["is_het"] = is_het

        sources_list = p.get("sources", [])
        if any("wayback" in str(s).lower() for s in sources_list) and not any("site_crawl" in str(s).lower() or "linkedin" in str(s).lower() for s in sources_list):
            p["temporal_status"] = "historical"
        else:
            p["temporal_status"] = "active"

        department_counts[dept] = department_counts.get(dept, 0) + 1
        if is_hvt:
            hvt_records.append(p)

    # 15. Strict Ranking: Real Humans with LinkedIn/GitHub & HVTs at the TOP!
    def sort_priority(p: Dict[str, Any]) -> Tuple[int, int, int]:
        has_human_name = bool(p.get("name") and p.get("is_human", False))
        is_linkedin = p.get("platform") == "LinkedIn" and "/in/" in (p.get("profile_url") or "")
        has_email = bool(p.get("email"))
        is_hvt_flag = p.get("is_hvt", False)

        if is_hvt_flag and has_email:
            tier = 0  # Ultra Priority: High-Value Targets with direct email
        elif is_linkedin and has_human_name:
            tier = 1  # Top Priority: Verified LinkedIn Human Staff
        elif has_human_name:
            tier = 2  # Human Staff (GitHub / Website)
        elif has_email:
            tier = 3  # Direct Corporate Mailbox
        else:
            tier = 4  # Public Handle

        return (tier, 0 if has_email else 1, -p.get("confidence", 0))

    verified_people.sort(key=sort_priority)

    # 16. Generate Actionable Defensive Exposure Findings
    exposures: List[Dict[str, Any]] = []
    
    # 16a. Executive Spear-Phishing Exposure
    if hvt_records:
        hvt_names = [h.get("name") for h in hvt_records if h.get("name")][:5]
        exposures.append({
            "id": "EXPOSURE-EXECUTIVE-SPEARPHISHING",
            "title": f"High-Value Executive Identity Exposure ({len(hvt_records)} Key Personnel)",
            "severity": "high",
            "category": "Identity & Social Engineering",
            "affected_count": len(hvt_records),
            "evidence": f"Identified {len(hvt_records)} executive and privileged personnel ({', '.join(hvt_names)}) with mapped corporate emails and public profiles.",
            "remediation": "Deploy hardware FIDO2 security keys, enforce strict external email warning banners, and conduct targeted executive spear-phishing drills.",
            "sample_records": hvt_records[:5],
        })

    # 16b. Document Metadata & Active Directory Leaks
    leaked_ad_users = doc_forensics_payload.get("ad_usernames", [])
    leaked_paths = doc_forensics_payload.get("internal_paths", [])
    if leaked_ad_users or leaked_paths:
        exposures.append({
            "id": "EXPOSURE-DOC-METADATA-AD-LEAK",
            "title": f"Active Directory & Internal File Share Leak in Public Documents",
            "severity": "high" if leaked_ad_users else "medium",
            "category": "Document Forensics",
            "affected_count": len(leaked_ad_users) + len(leaked_paths),
            "evidence": f"Publicly hosted documents revealed {len(leaked_ad_users)} internal Active Directory account(s) ({', '.join(leaked_ad_users[:3])}) and {len(leaked_paths)} internal file share path(s).",
            "remediation": "Enforce automatic metadata scrubbing (e.g., ExifTool / CI pipeline) on all public-facing PDFs and web asset uploads.",
            "details": {
                "ad_usernames": leaked_ad_users,
                "internal_paths": leaked_paths,
            }
        })

    # 16c. Corporate Email Enumeration Footprint
    deliverable_count = sum(1 for p in verified_people if p.get("deliverability") in ["deliverable", "catch_all"] or (not p.get("inferred") and p.get("email")))
    confirmed_count = sum(1 for p in verified_people if not p.get("inferred") and p.get("email"))
    inferred_count = sum(1 for p in verified_people if p.get("inferred") and p.get("email"))
    human_count = len(verified_people)

    if confirmed_count > 0 or len(role_mailboxes) > 0:
        total_discovered_mailboxes = confirmed_count + len(role_mailboxes)
        exposures.append({
            "id": "EXPOSURE-CORPORATE-EMAIL-ENUMERATION",
            "title": f"Public Corporate Email Footprint ({total_discovered_mailboxes} Discovered Mailboxes)",
            "severity": "medium",
            "category": "Corporate Footprint",
            "affected_count": total_discovered_mailboxes,
            "evidence": f"Discovered {confirmed_count} verified human mailboxes and {len(role_mailboxes)} role inboxes with pattern status '{pattern_info.get('status')}'.",
            "remediation": "Review public employee directories and ensure all web forms use contact proxies rather than cleartext mailto links.",
        })

    # 16d. Subsidiary Multi-Tenant Risk
    if len(verified_subsidiaries) > 0:
        sub_domains = [s.get("candidate_domain") for s in verified_subsidiaries][:4]
        exposures.append({
            "id": "EXPOSURE-SUBSIDIARY-MULTI-TENANT-RISK",
            "title": f"Discovered {len(verified_subsidiaries)} Corporate Subsidiaries / Operating Units",
            "severity": "info",
            "category": "Attack Surface Topology",
            "affected_count": len(verified_subsidiaries),
            "evidence": f"Multi-anchor cryptographic and DNS correlation confirmed {len(verified_subsidiaries)} operational subsidiary domains: {', '.join(sub_domains)}.",
            "remediation": "Audit subsidiary cloud tenant configurations and ensure centralized IAM/MFA policies are uniformly enforced across operating units.",
            "subsidiaries": verified_subsidiaries,
        })

    logger.info(f"[people.aggregate] Completed human aggregation: {human_count} identified human employees, {len(hvt_records)} HVTs, {len(unresolved_footprint)} footprint assets, {len(verified_subsidiaries)} subsidiaries")

    return {
        "domain": domain,
        "root_domain": root_domain,
        "email_pattern": detected_pattern,
        "pattern_info": pattern_info,
        "deliverable_count": deliverable_count,
        "confirmed_count": confirmed_count,
        "inferred_count": inferred_count,
        "human_count": human_count,
        "hvt_count": len(hvt_records),
        "total_count": human_count,
        "departments": department_counts,
        "hvt_list": hvt_records,
        "document_forensics": doc_forensics_payload.get("document_exposures", []),
        "ad_usernames": leaked_ad_users,
        "internal_paths": leaked_paths,
        "exposures": exposures,
        "people": verified_people,
        "unresolved_footprint": unresolved_footprint,
        "role_mailboxes": list(role_mailboxes.values()),
        "subsidiaries": verified_subsidiaries,
    }


GENERIC_MAILBOXES = {
    "admin", "support", "info", "contact", "sales", "security", "help",
    "billing", "careers", "jobs", "press", "media", "privacy", "events",
    "event", "team", "hello", "hi", "mail", "general", "office", "enquiries",
    "inquiries", "helpdesk", "feedback", "newsletter", "postmaster",
    "webmaster", "marketing", "notifications", "community", "legal", "hr",
    "finance", "accounting", "operations", "dev", "engineering", "leads",
}


def infer_email_pattern(emails: List[str], domain: str) -> Optional[str]:
    """Infers corporate email syntax from confirmed emails."""
    pattern_votes: Dict[str, int] = {
        "{first}.{last}": 0,
        "{f}.{last}": 0,
        "{first}_{last}": 0,
        "{first}-{last}": 0,
        "{first}{last}": 0,
        "{first}": 0,
        "{last}.{first}": 0,
    }

    clean_dom = domain.lower()

    for email in emails:
        if "@" not in email:
            continue
        local_part, mail_domain = email.split("@", 1)
        if clean_dom not in mail_domain.lower():
            continue

        local_part = local_part.lower().strip()
        if local_part in GENERIC_MAILBOXES:
            continue

        if "." in local_part:
            parts = local_part.split(".")
            if len(parts) == 2:
                if len(parts[0]) == 1 and len(parts[1]) > 1:
                    pattern_votes["{f}.{last}"] += 3
                elif len(parts[0]) > 1 and len(parts[1]) > 1:
                    pattern_votes["{first}.{last}"] += 3
        elif "_" in local_part:
            parts = local_part.split("_")
            if len(parts) == 2 and len(parts[0]) > 1 and len(parts[1]) > 1:
                pattern_votes["{first}_{last}"] += 3
        elif "-" in local_part:
            parts = local_part.split("-")
            if len(parts) == 2 and len(parts[0]) > 1 and len(parts[1]) > 1:
                pattern_votes["{first}-{last}"] += 3

    best_pattern = max(pattern_votes.items(), key=lambda x: x[1])
    if best_pattern[1] > 0:
        return f"{best_pattern[0]}@{domain}"
    
    return f"{{first}}.{{last}}@{domain}"


COMMON_TITLES = {
    # Academic & Research
    "prof", "professor", "assoc prof", "asst prof", "associate professor",
    "assistant professor", "dr", "doctor", "emeritus", "lecturer", "dean",
    "vc", "dvc", "provost", "rector",
    # Engineering & Technical
    "engr", "engineer", "tech", "architect", "arch", "surv", "surveyor",
    "pharm", "pharmacist",
    # Legal & Judicial
    "barr", "barrister", "adv", "advocate", "solicitor", "atty", "attorney",
    "judge", "justice", "magistrate", "esq",
    # Medical
    "nurse", "midwife", "surgeon", "vet",
    # Cultural, Traditional & Political
    "chief", "otunba", "obalong", "emir", "oba", "igwe", "asagba",
    "senator", "sen", "hon", "honorable", "honourable", "gov", "governor",
    "amb", "ambassador", "minister", "commissioner", "councillor",
    # Religious
    "rev", "reverend", "pastor", "pst", "bishop", "archbishop", "apostle",
    "deacon", "deaconess", "elder", "evangelist", "imam", "sheikh", "mallam",
    "alhaj", "alhaji", "al-hajj", "hajia", "hajiya",
    # Standard Salutations
    "mr", "mrs", "ms", "miss", "mister", "madam", "sir", "dame", "lady", "lord",
}

COMMON_SUFFIXES = {
    # Degrees & Accreditations
    "phd", "ph.d", "ph.d.", "dphil", "md", "m.d", "m.d.", "msc", "m.sc", "ms",
    "bsc", "b.sc", "ba", "b.a", "ma", "m.a", "llb", "ll.b", "llm", "ll.m",
    "mbbs", "m.b.b.s", "mba", "m.b.a", "dvm", "beng", "b.eng", "meng", "m.eng",
    # Professional Fellowships & Honors (SAN, FCA, CFR, etc.)
    "san", "s.a.n", "fnse", "mnse", "fca", "aca", "fcna", "cpa", "pmp",
    "cfr", "con", "oon", "mon", "ofr", "mfr", "fcp", "fcs", "fcf",
    # Generational Suffixes
    "jr", "jr.", "junior", "sr", "sr.", "senior", "ii", "iii", "iv", "v",
    # Other
    "esq", "esq.", "esquire",
}


def clean_person_name(raw_name: str) -> Dict[str, str]:
    """
    Cleans honorifics, titles, degrees, and professional post-nominals
    from a person's raw name to extract genuine first and last names.
    """
    if not raw_name:
        return {"title": "", "cleaned_name": "", "first_name": "", "last_name": ""}
        
    # 1. Remove parenthetical qualifications, e.g. (Ph.D.), (FNSE)
    name = re.sub(r"\(.*?\)", "", raw_name).strip()
    
    # 2. Split comma-separated tokens (e.g. 'Prof. Aleruchi Chuku, Ph.D., SAN')
    comma_parts = [p.strip() for p in name.split(",") if p.strip()]
    if not comma_parts:
        return {"title": "", "cleaned_name": "", "first_name": "", "last_name": ""}
        
    main_name = comma_parts[0]
    words = [w for w in main_name.split() if w]
    found_titles = []
    
    # 3. Strip recognized titles/honorifics from the beginning
    while words:
        if len(words) >= 2:
            two_word = f"{words[0]} {words[1]}".lower().replace(".", "")
            if two_word in COMMON_TITLES:
                found_titles.append(f"{words[0]} {words[1]}")
                words = words[2:]
                continue
        single_word = words[0].lower().replace(".", "")
        if single_word in COMMON_TITLES:
            found_titles.append(words[0])
            words = words[1:]
            continue
        break
        
    # 4. Strip recognized suffixes from the end
    while words:
        last_word = words[-1].lower().replace(".", "")
        if last_word in COMMON_SUFFIXES:
            words = words[:-1]
        else:
            break
            
    if not words:
        return {"title": " ".join(found_titles), "cleaned_name": "", "first_name": "", "last_name": ""}
        
    first_name = re.sub(r"[^a-zA-Z]", "", words[0])
    last_name = re.sub(r"[^a-zA-Z]", "", words[-1]) if len(words) > 1 else ""
    cleaned_name = " ".join(words)
    
    return {
        "title": " ".join(found_titles),
        "cleaned_name": cleaned_name,
        "first_name": first_name,
        "last_name": last_name,
    }


def generate_email_from_name(name: str, pattern_str: str, domain: str) -> Optional[str]:
    """
    Generates an email address from a person's full name and pattern template,
    stripping academic titles, honorifics, and post-nominal degrees.
    """
    clean_info = clean_person_name(name)
    first = clean_info["first_name"].lower()
    last = clean_info["last_name"].lower()
    
    if not first or not last:
        parts = [re.sub(r"[^a-zA-Z]", "", p).lower() for p in name.strip().split() if re.sub(r"[^a-zA-Z]", "", p)]
        if len(parts) >= 2:
            first = parts[0]
            last = parts[-1]
        else:
            return None

    # Strictly reject single-letter or invalid names (e.g. "FULafia V" -> last name "v")
    if len(first) < 2 or len(last) < 2:
        return None
        
    f_initial = first[0]
    
    template = pattern_str.split("@")[0]
    local_part = (
        template
        .replace("{first}", first)
        .replace("{last}", last)
        .replace("{f}", f_initial)
    )
    
    return f"{local_part}@{domain}"
