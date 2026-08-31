import re
import logging
from typing import List, Dict, Any, Optional, Set, Tuple
from core.confidence import calculate_confidence

logger = logging.getLogger(__name__)

# Weight hierarchy per Spec Section 13
WEIGHT_VERY_STRONG = 0.90
WEIGHT_STRONG = 0.70
WEIGHT_MEDIUM = 0.45
WEIGHT_WEAK = 0.20


class ResolvedPerson:
    """Represents a deduplicated, evidence-backed person entity."""

    def __init__(self, canonical_id: str, primary_name: str):
        self.canonical_id = canonical_id
        self.primary_name = primary_name
        self.aliases: Set[str] = {primary_name} if primary_name else set()
        self.emails: Set[str] = set()
        self.usernames: Set[str] = set()
        self.job_titles: Set[str] = set()
        self.organizations: Set[str] = set()
        self.profiles: List[Dict[str, str]] = []
        self.locations: Set[str] = set()
        self.sources: Set[str] = set()
        self.supporting_evidence: List[str] = []
        self.contradicting_evidence: List[str] = []
        self.match_reasons: List[str] = []
        self.status: str = "confirmed"  # confirmed | likely | possible_match
        self.confidence: float = 0.85
        self.department: str = "General Staff"
        self.seniority: str = "Staff"
        self.is_hvt: bool = False
        self.is_het: bool = False
        self.temporal_status: str = "active"  # active | historical

    def to_dict(self) -> Dict[str, Any]:
        return {
            "canonical_id": self.canonical_id,
            "primary_name": self.primary_name,
            "aliases": list(self.aliases),
            "emails": list(self.emails),
            "usernames": list(self.usernames),
            "job_titles": list(self.job_titles),
            "organizations": list(self.organizations),
            "profiles": self.profiles,
            "locations": list(self.locations),
            "sources": list(self.sources),
            "supporting_evidence": self.supporting_evidence,
            "contradicting_evidence": self.contradicting_evidence,
            "match_reasons": self.match_reasons,
            "status": self.status,
            "confidence": self.confidence,
            "department": self.department,
            "seniority": self.seniority,
            "is_hvt": self.is_hvt,
            "is_het": self.is_het,
            "temporal_status": self.temporal_status,
        }


def classify_department_and_seniority(job_title: str) -> Tuple[str, str, bool, bool]:
    """
    Infers department, seniority tier, and HVT/HET status from job title string.
    Returns (department, seniority, is_hvt, is_het).
    """
    t_lower = (job_title or "").lower()
    
    is_hvt = False
    is_het = False
    seniority = "Staff"
    department = "General Staff"
    
    # Seniority hierarchy
    if any(k in t_lower for k in ["ceo", "cto", "cfo", "coo", "ciso", "cro", "chief", "president", "founder", "co-founder"]):
        seniority = "Executive / C-Suite"
        is_hvt = True
    elif any(k in t_lower for k in ["vice president", "vp", "head of", "director", "general manager"]):
        seniority = "Director / VP"
        is_hvt = True
    elif any(k in t_lower for k in ["manager", "lead", "principal", "architect", "staff engineer"]):
        seniority = "Manager / Lead"
    
    # Department domain (specific technical C-level roles mapped to domain before generic executive)
    if any(k in t_lower for k in ["ciso", "security", "infosec", "soc", "penetration", "threat", "vulnerability", "appsec"]):
        department = "Cybersecurity & SecOps"
        is_hvt = True
    elif any(k in t_lower for k in ["cfo", "finance", "accounting", "treasury", "controller", "payroll", "billing"]):
        department = "Finance & Accounting"
        is_hvt = True
    elif any(k in t_lower for k in ["devops", "cloud", "sre", "infrastructure", "sysadmin", "system admin", "platform", "database"]):
        department = "DevOps & Infrastructure"
        is_hvt = True
    elif any(k in t_lower for k in ["ceo", "president", "founder", "executive", "board", "coo", "chief"]):
        department = "Executive Leadership"
        is_hvt = True
    elif any(k in t_lower for k in ["hr", "human resources", "talent", "recruiter", "recruiting", "people ops"]):
        department = "HR & Recruiting"
        is_het = True
    elif any(k in t_lower for k in ["engineer", "developer", "software", "architect", "programmer", "frontend", "backend", "fullstack", "qa"]):
        department = "Software Engineering"
    elif any(k in t_lower for k in ["sales", "marketing", "pr", "public relations", "business development", "account executive", "growth", "communications"]):
        department = "Sales & Marketing"
        is_het = True

    return department, seniority, is_hvt, is_het


# Corporate & Non-Human Entity Filter Tokens
CORPORATE_ENTITY_TOKENS = {
    "inc", "incorporated", "ltd", "limited", "llc", "plc", "corp", "corporation",
    "co", "company", "group", "procurement", "services", "solutions", "enterprises",
    "holdings", "ventures", "authority", "commission", "ministry", "foundation",
    "fund", "trust", "agency", "division", "bureau", "directory", "official",
    "department", "unit", "affiliate", "subsidiary", "petroleum", "energy",
    "refinery", "trading", "retail", "upstream", "downstream", "producing",
    "exploration", "pipeline", "gas", "power", "consulting", "associates",
}

GEOGRAPHIC_PLATFORM_TOKENS = {
    "iran", "nigeria", "uk", "usa", "ghana", "india", "egypt", "dubai",
    "london", "kenya", "sa", "uae", "canada", "france", "germany", "china",
    "linkedin", "twitter", "facebook", "instagram", "github", "youtube",
}


def classify_entity_type(name: str, title: str = "", profile_url: str = "") -> Tuple[str, str]:
    """
    Classifies a candidate entity into:
    - 'human': Biological person / employee profile
    - 'corporate_directory': Official company handle / directory page (e.g. 'NNPC, Inc.')
    - 'regional_account': Country/region branch profile (e.g. 'Linkedin Iran')
    - 'subsidiary_brand': Operating company / subsidiary profile (e.g. 'Antan Producing Limited')
    - 'system_bot': Generic mailbox or automation artifact
    Returns (entity_type, classification_reason).
    """
    if not name:
        return "system_bot", "Missing entity name string"

    clean = re.sub(r"[^a-zA-Z\s]", " ", name).lower().strip()
    words = [w for w in clean.split() if w]
    t_lower = (title or "").lower()
    url_lower = (profile_url or "").lower()

    # 1. Check Directory / Official Organization Handles
    if "official" in words or "directory" in words or "contact" in words or "corporate" in words:
        return "corporate_directory", f"Explicit corporate directory label in name '{name}'"

    if "/company/" in url_lower or "/organization/" in url_lower:
        return "corporate_directory", f"Corporate organization profile URL ({profile_url})"

    # 2. Check Corporate Suffixes (e.g., 'NNPC, Inc.', 'Antan Producing Limited')
    has_corp_token = any(w in CORPORATE_ENTITY_TOKENS for w in words)
    has_geo_token = any(w in GEOGRAPHIC_PLATFORM_TOKENS for w in words)

    if has_corp_token and has_geo_token:
        return "subsidiary_brand", f"Subsidiary / regional business entity name '{name}'"

    if has_corp_token:
        if any(w in ["producing", "refinery", "exploration", "pipeline", "trading", "retail", "energy", "petroleum"] for w in words):
            return "subsidiary_brand", f"Operating subsidiary / industrial brand name '{name}'"
        return "corporate_directory", f"Corporate legal suffix in name '{name}'"

    # 3. Check Regional / Platform Handles (e.g., 'Linkedin Iran')
    if len(words) <= 2 and has_geo_token:
        return "regional_account", f"Regional / platform geographic account '{name}'"

    # 4. Check Generic Titles (e.g. 'Organization Staff', 'Direct Contact / Inbox')
    if any(phrase in name.lower() for phrase in ["organization staff", "direct contact", "inbox", "document author", "cited in document"]):
        return "system_bot", f"Generic scraper placeholder string '{name}'"

    # 5. Check Single Word / Nickname Noise
    if len(words) == 1 and len(words[0]) < 3:
        return "system_bot", f"Single short abbreviation token '{name}'"

    return "human", "Validated biological person name structure"


def is_valid_human_name(name: str, org_name: str = "") -> bool:
    """
    Returns True only if entity name represents a biological human being.
    Rejects company names, regional accounts, and scraper noise.
    """
    if not name:
        return False
    entity_type, _ = classify_entity_type(name)
    if entity_type != "human":
        return False
    
    # If name is identical to target org name
    if org_name and org_name.lower().strip() == name.lower().strip():
        return False

    return True


def _normalize_name(name: str) -> str:
    """Normalizes person name string for consistent matching."""
    if not name:
        return ""
    cleaned = re.sub(r"[^a-zA-Z\s]", "", name).strip().lower()
    return " ".join(cleaned.split())


def _names_compatible(name_a: str, name_b: str) -> Tuple[bool, float]:
    """
    Checks whether two names are compatible (e.g., 'John Smith' vs 'John A. Smith').
    Returns (is_compatible, match_weight).
    """
    norm_a = _normalize_name(name_a)
    norm_b = _normalize_name(name_b)
    if not norm_a or not norm_b:
        return False, 0.0

    if norm_a == norm_b:
        return True, WEIGHT_MEDIUM

    parts_a = norm_a.split()
    parts_b = norm_b.split()

    if len(parts_a) >= 2 and len(parts_b) >= 2:
        if parts_a[0] == parts_b[0] and parts_a[-1] == parts_b[-1]:
            return True, WEIGHT_MEDIUM

    return False, 0.0


def resolve_identities(
    candidates: List[Dict[str, Any]],
    target_org: Optional[str] = None,
) -> List[ResolvedPerson]:
    """
    Multi-signal Bayesian Identity Resolution.
    Clusters candidate observations into resolved persons using hierarchical weights,
    calculates explainable confidence, and preserves contradictions.
    """
    resolved: List[ResolvedPerson] = []
    target_org_norm = target_org.lower().strip() if target_org else None

    for cand in candidates:
        name = (cand.get("name") or "").strip()
        email = (cand.get("email") or "").strip().lower()
        username = (cand.get("username") or "").strip()
        job_title = (cand.get("job_title") or cand.get("title") or "").strip()
        org = (cand.get("org") or cand.get("organization") or "").strip()
        profile_url = (cand.get("profile_url") or cand.get("url") or "").strip()
        location = (cand.get("location") or "").strip()
        source = cand.get("source") or "unverified"
        evidence_claim = cand.get("evidence_claim") or f"Observed identity '{name or username or email}' from {source}"

        best_person: Optional[ResolvedPerson] = None
        best_score = 0.0
        best_reasons = []
        has_contradiction = False
        contradiction_note = ""

        for person in resolved:
            score = 0.0
            reasons = []
            contra = False
            contra_msg = ""

            # Check email match (VERY STRONG)
            if email and email in person.emails:
                score += WEIGHT_VERY_STRONG
                reasons.append(f"Identical email address matched ({email})")

            # Check matching organization + company email
            if target_org_norm and email and target_org_norm in email:
                if person.primary_name and name and _names_compatible(person.primary_name, name)[0]:
                    score += WEIGHT_VERY_STRONG
                    reasons.append("Company-owned email matches organization and name")

            # Check name compatibility
            if name and person.primary_name:
                compat, w = _names_compatible(person.primary_name, name)
                if compat:
                    score += w
                    reasons.append(f"Compatible human name ({person.primary_name} ~ {name})")

            # Check username match
            if username and username in person.usernames:
                if org and any(org.lower() in p_org.lower() for p_org in person.organizations):
                    score += WEIGHT_STRONG
                    reasons.append(f"Username '{username}' verified with shared organization '{org}'")
                else:
                    score += WEIGHT_MEDIUM
                    reasons.append(f"Matching public username '{username}'")

            # Check Contradictions
            if org and person.organizations:
                conflict_org = True
                for p_org in person.organizations:
                    if org.lower() in p_org.lower() or p_org.lower() in org.lower():
                        conflict_org = False
                        score += WEIGHT_MEDIUM
                        reasons.append(f"Shared employer confirmed: {org}")
                        break
                if conflict_org and len(person.organizations) > 0 and org.lower() != (target_org_norm or ""):
                    contra = True
                    contra_msg = f"Conflicting employer: observed '{org}' vs existing '{list(person.organizations)}'"

            if score > best_score:
                best_score = score
                best_person = person
                best_reasons = reasons
                has_contradiction = contra
                contradiction_note = contra_msg

        # Threshold for merging (>= 0.60)
        if best_person and best_score >= 0.60 and not has_contradiction:
            if name:
                best_person.aliases.add(name)
            if email:
                best_person.emails.add(email)
            if username:
                best_person.usernames.add(username)
            if job_title:
                best_person.job_titles.add(job_title)
            if org:
                best_person.organizations.add(org)
            if location:
                best_person.locations.add(location)
            if profile_url:
                best_person.profiles.append({"source": source, "url": profile_url})
            if source:
                best_person.sources.add(source)
            best_person.supporting_evidence.append(evidence_claim)
            best_person.match_reasons.extend(best_reasons)
            
            # Recalculate confidence & department classification
            sources = list(best_person.sources) or [source]
            conf, _ = calculate_confidence(sources=sources, evidence_strength=0.90, contradiction_count=0)
            best_person.confidence = conf
            best_person.status = "confirmed" if conf >= 0.80 else "likely"

            if any(j for j in best_person.job_titles):
                dept, sen, hvt, het = classify_department_and_seniority(list(best_person.job_titles)[0])
                best_person.department = dept
                best_person.seniority = sen
                best_person.is_hvt = hvt
                best_person.is_het = het

            if any("wayback" in s for s in best_person.sources) and not any("site_crawl" in s or "linkedin" in s for s in best_person.sources):
                best_person.temporal_status = "historical"

        elif best_person and has_contradiction:
            canonical_key = f"person:possible_{re.sub(r'[^a-zA-Z0-9]', '_', name.lower()) or len(resolved)+1}"
            cand_person = ResolvedPerson(canonical_id=canonical_key, primary_name=name or username or "Unknown Identity")
            if email:
                cand_person.emails.add(email)
            if username:
                cand_person.usernames.add(username)
            if job_title:
                cand_person.job_titles.add(job_title)
            if org:
                cand_person.organizations.add(org)
            if location:
                cand_person.locations.add(location)
            if profile_url:
                cand_person.profiles.append({"source": source, "url": profile_url})
            if source:
                cand_person.sources.add(source)

            cand_person.supporting_evidence.append(evidence_claim)
            cand_person.contradicting_evidence.append(contradiction_note)
            cand_person.status = "possible_match"
            conf, _ = calculate_confidence(sources=[source], evidence_strength=0.60, contradiction_count=1)
            cand_person.confidence = conf
            
            if job_title:
                dept, sen, hvt, het = classify_department_and_seniority(job_title)
                cand_person.department = dept
                cand_person.seniority = sen
                cand_person.is_hvt = hvt
                cand_person.is_het = het

            resolved.append(cand_person)

        else:
            slug = re.sub(r"[^a-zA-Z0-9]", "_", name.lower()) if name else (username.lower() if username else f"entity_{len(resolved)+1}")
            canonical_key = f"person:{slug}"
            new_person = ResolvedPerson(canonical_id=canonical_key, primary_name=name or username or "Unknown Identity")
            if email:
                new_person.emails.add(email)
            if username:
                new_person.usernames.add(username)
            if job_title:
                new_person.job_titles.add(job_title)
            if org:
                new_person.organizations.add(org)
            if location:
                new_person.locations.add(location)
            if profile_url:
                new_person.profiles.append({"source": source, "url": profile_url})
            if source:
                new_person.sources.add(source)
            new_person.supporting_evidence.append(evidence_claim)

            conf, _ = calculate_confidence(sources=[source], evidence_strength=0.85, contradiction_count=0)
            new_person.confidence = conf
            new_person.status = "likely" if conf < 0.85 else "confirmed"
            
            if job_title:
                dept, sen, hvt, het = classify_department_and_seniority(job_title)
                new_person.department = dept
                new_person.seniority = sen
                new_person.is_hvt = hvt
                new_person.is_het = het

            if "wayback" in source:
                new_person.temporal_status = "historical"

            resolved.append(new_person)

    return resolved


def resolve_identities_and_footprint(
    candidates: List[Dict[str, Any]],
    target_org: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Separates incoming candidate records into:
    - resolved_persons: Verified biological human employees (with department, HVT, and Bayesian confidence).
    - unresolved_footprint: Corporate directories, regional accounts, brand handles, and generic artifacts.
    """
    human_candidates: List[Dict[str, Any]] = []
    unresolved_footprint: List[Dict[str, Any]] = []

    for cand in candidates:
        name = (cand.get("name") or "").strip()
        title = (cand.get("title") or cand.get("job_title") or "").strip()
        url = (cand.get("profile_url") or cand.get("url") or "").strip()

        entity_type, reason = classify_entity_type(name, title, url)
        if entity_type == "human":
            human_candidates.append(cand)
        else:
            footprint_entry = dict(cand)
            footprint_entry["entity_type"] = entity_type
            footprint_entry["classification_reason"] = reason
            unresolved_footprint.append(footprint_entry)

    resolved_humans = resolve_identities(human_candidates, target_org=target_org)

    return {
        "resolved_persons": resolved_humans,
        "unresolved_footprint": unresolved_footprint,
    }
