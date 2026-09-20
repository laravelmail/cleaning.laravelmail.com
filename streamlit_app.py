import re
import io
import chardet
import smtplib
import dns.resolver
import pandas as pd
import streamlit as st
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
import whois
from email_validator import validate_email as validate_syntax_strict, EmailNotValidError
import tldextract
import yagmail
import time
import random
import math
import os
import threading
# Streamlit Cloud manages sleeping/waking itself. A forced periodic rerun can interrupt
# long batches and make the UI look stuck, so no autorefresh loop is installed.

# --- Configs ---
# Default lists for disposable domains and role-based prefixes
DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com",
    "trashmail.com", "tempmail.com", "yopmail.com"
}
ROLE_BASED_PREFIXES = {
    "admin", "support", "info", "sales", "contact", "webmaster", "help"
}
# Default sender email for SMTP checks. This should be a syntactically valid placeholder.
# It does NOT need to be a real, authenticated email for validation SMTP checks.
SMTP_CHECK_FROM_EMAIL = "noreply@emailvalidator.com"

DEFAULT_FROM_EMAIL = "check@yourdomain.com"  # This is for the UI field, actual authenticated sending
DEFAULT_SMTP_HOST = "smtp.gmail.com"
DEFAULT_SMTP_PORT = 587

# NEW: max_concurrent=1 — all thread pools will use this value
MAX_CONCURRENT = max(1, min(32, int(os.getenv("STREAMLIT_MAX_CONCURRENT", "8"))))

# Caching for DNS MX records and WHOIS lookups to improve performance on repeat queries
mx_cache = {}
whois_cache = {}
mx_provider_cache = {}  # NEW: cache for MX provider detection

# NEW: caches for domain aging and SMTP response codes
domain_age_cache = {}       # registrable_domain → dict with creation_date, age_days, age_label
smtp_code_cache = {}        # email → int SMTP response code (or None)
catchall_locks = {}          # domain → lock; prevents duplicate probes in concurrent batches
catchall_locks_guard = threading.Lock()


# ─────────────────────────────────────────────
# NEW: Gaussian Sleep Helper
# ─────────────────────────────────────────────
def gaussian_sleep(mu=1.8, sigma=0.3, min_sleep=1.2, max_sleep=2.5):


    """
    Sleeps for a duration drawn from a Gaussian (normal) distribution,
    clamped to [min_sleep, max_sleep] seconds.
    Used to add human-like, randomised delays between SMTP handshakes.
    """
    duration = random.gauss(mu, sigma)
    duration = max(min_sleep, min(max_sleep, duration))
    time.sleep(duration)



# ─────────────────────────────────────────────
# NEW: MX Provider Detection
# ─────────────────────────────────────────────
# Known MX hostname patterns per provider
MX_PROVIDER_PATTERNS = {
    "Google Workspace": [
        "google.com", "googlemail.com", "aspmx.l.google.com",
        "alt1.aspmx.l.google.com", "alt2.aspmx.l.google.com",
        "aspmx2.googlemail.com", "aspmx3.googlemail.com",
    ],
    "Microsoft 365": [
        "mail.protection.outlook.com", "outlook.com", "hotmail.com",
        "microsoft.com",
    ],
    "Proofpoint": [
        "pphosted.com", "proofpoint.com",
    ],
    "Mimecast": [
        "mimecast.com",
    ],
    "Barracuda": [
        "barracudanetworks.com", "ess.barracuda.com", "cudamail.com",
    ],
}


def detect_mx_provider(registrable_domain: str) -> str:
    """
    Resolves the MX records for *registrable_domain* via public DNS and
    returns a human-readable label for the mail-routing provider, or
    'Unknown / Self-hosted' if no known pattern matches.
    Results are cached.
    """
    if registrable_domain in mx_provider_cache:
        return mx_provider_cache[registrable_domain]

    try:
        answers = dns.resolver.resolve(registrable_domain, "MX", "IN", lifetime=5)
        mx_hosts = [str(r.exchange).rstrip(".").lower() for r in answers]
    except Exception:
        mx_provider_cache[registrable_domain] = "DNS Error"
        return "DNS Error"

    for provider, patterns in MX_PROVIDER_PATTERNS.items():
        for host in mx_hosts:
            for pattern in patterns:
                if pattern in host:
                    mx_provider_cache[registrable_domain] = provider
                    return provider

    mx_provider_cache[registrable_domain] = "Unknown / Self-hosted"
    return "Unknown / Self-hosted"


# --- Helper Function for Domain Extraction ---
def get_registrable_domain(email_or_domain_string):
    """
    Extracts the registrable domain (e.g., 'google.com' from 'mail.google.com' or 'www.google.com').
    Uses tldextract for robust parsing according to Public Suffix List.
    """
    try:
        if '@' in email_or_domain_string:
            domain_part = email_or_domain_string.split('@')[1]
        else:
            domain_part = email_or_domain_string

        extracted = tldextract.extract(domain_part)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
        elif extracted.domain:
            return extracted.domain
        else:
            return None
    except Exception:
        return None


# --- Validators ---
def is_valid_syntax(email):
    """
    Checks email syntax strictly according to RFCs using the email_validator library.
    """
    try:
        validate_syntax_strict(email, check_deliverability=False)
        return True
    except EmailNotValidError:
        return False


def is_disposable(registrable_domain, disposable_domains):
    return registrable_domain in disposable_domains


def is_role_based(email_prefix, role_based_prefixes):
    return email_prefix.lower() in role_based_prefixes


def has_mx_record(registrable_domain):
    if registrable_domain in mx_cache:
        return mx_cache[registrable_domain]
    try:
        answers = dns.resolver.resolve(registrable_domain, 'MX', 'IN', lifetime=3)
        mx_cache[registrable_domain] = len(answers) > 0
        return mx_cache[registrable_domain]
    except Exception:
        mx_cache[registrable_domain] = False
        return False


# ─────────────────────────────────────────────
# NEW: Domain Aging Helper
# ─────────────────────────────────────────────
def get_domain_age(registrable_domain: str) -> dict:
    """
    Looks up the WHOIS creation date for *registrable_domain* and returns
    a dict with:
        creation_date : str   – ISO date string or 'N/A'
        age_days      : int   – days since creation, or -1 if unknown
        age_label     : str   – human-readable label (e.g. "3 years 45 days")
    Results are cached per domain.
    """
    if registrable_domain in domain_age_cache:
        return domain_age_cache[registrable_domain]

    result = {"creation_date": "N/A", "age_days": -1, "age_label": "Unknown"}
    try:
        w = whois.whois(registrable_domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation is not None:
            if isinstance(creation, str):
                from datetime import datetime
                # try common formats
                for fmt in ("%Y-%m-%d", "%d-%b-%Y", "%Y-%m-%dT%H:%M:%SZ"):
                    try:
                        creation = datetime.strptime(creation, fmt)
                        break
                    except ValueError:
                        pass
                else:
                    creation = None
            if creation is not None:
                from datetime import datetime, timezone
                now = datetime.now(timezone.utc) if creation.tzinfo else datetime.utcnow()
                delta = now - creation
                days = delta.days
                years = days // 365
                rem_days = days % 365
                result["creation_date"] = creation.strftime("%Y-%m-%d")
                result["age_days"] = days
                if years > 0:
                    result["age_label"] = f"{years}y {rem_days}d"
                else:
                    result["age_label"] = f"{days}d"
    except Exception:
        pass

    domain_age_cache[registrable_domain] = result
    return result


# ─────────────────────────────────────────────
# NEW: SMTP Verification returning raw response code
# ─────────────────────────────────────────────
def verify_smtp_with_code(email: str, registrable_domain: str) -> tuple[bool, int | None]:
    """
    Like verify_smtp() but also returns the raw SMTP RCPT TO response code.
    Returns:
        (is_valid: bool, smtp_code: int | None)
    smtp_code is None when a connection/DNS error prevented reaching RCPT TO.
    """
    server = None
    try:
        gaussian_sleep(mu=1.8, sigma=0.3, min_sleep=1.2, max_sleep=2.5)

        mx_records = dns.resolver.resolve(registrable_domain, 'MX', 'IN', lifetime=3)
        mx_records_sorted = sorted(mx_records, key=lambda r: r.preference)
        mx = str(mx_records_sorted[0].exchange).rstrip('.')

        server = smtplib.SMTP(mx, timeout=5)

        generic_from_domain = SMTP_CHECK_FROM_EMAIL.split('@')[1]
        server.helo(generic_from_domain)
        server.mail(SMTP_CHECK_FROM_EMAIL)

        code, _ = server.rcpt(email)
        smtp_code_cache[email] = code
        return code in [250, 251], code
    except Exception:
        smtp_code_cache[email] = None
        return False, None
    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                pass


# --- Core SMTP Verification Function (with proper QUIT + gaussian_sleep) ---
def verify_smtp(email, registrable_domain):
    """
    Attempts to verify the existence of an email mailbox via SMTP.
    Delegates to verify_smtp_with_code and discards the code.
    """
    valid, _ = verify_smtp_with_code(email, registrable_domain)
    return valid


# ─────────────────────────────────────────────
# NEW: Catch-All Domain Detection
# ─────────────────────────────────────────────
# Cache to avoid re-probing the same domain
catchall_cache = {}

def detect_catch_all(registrable_domain: str) -> bool | None:
    """
    Detects whether a domain accepts mail for any recipient (catch-all).

    Strategy:
      1. Connect to the domain's primary MX host.
      2. Issue RCPT TO: for a randomly-generated, almost-certainly-nonexistent
         address (e.g. xq7z3fake_probe_9182@<domain>).
      3. If the server returns 250/251, the domain accepts everything → catch-all.
         If it returns 550/551/553, it rejected the fake address → not catch-all.
         Any other outcome (timeout, DNS error, etc.) → None (unknown).

    Results are cached per domain to avoid redundant probes.
    Returns:
        True  – domain is catch-all
        False – domain is NOT catch-all
        None  – could not determine (connection error / greylisted / etc.)
    """
    if registrable_domain in catchall_cache:
        return catchall_cache[registrable_domain]
    with catchall_locks_guard:
        domain_lock = catchall_locks.setdefault(registrable_domain, threading.Lock())
    with domain_lock:
        if registrable_domain in catchall_cache:
            return catchall_cache[registrable_domain]
        return _detect_catch_all_uncached(registrable_domain)


def _detect_catch_all_uncached(registrable_domain: str) -> bool | None:
    # Build a fake address that is vanishingly unlikely to exist
    random_token = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=14))
    fake_address = f"xprobe_{random_token}@{registrable_domain}"

    server = None
    outcome = None
    try:
        gaussian_sleep(mu=1.8, sigma=0.3, min_sleep=1.2, max_sleep=2.5)

        mx_records = dns.resolver.resolve(registrable_domain, "MX", "IN", lifetime=3)
        mx_sorted = sorted(mx_records, key=lambda r: r.preference)
        mx_host = str(mx_sorted[0].exchange).rstrip(".")

        server = smtplib.SMTP(mx_host, timeout=6)
        generic_from_domain = SMTP_CHECK_FROM_EMAIL.split("@")[1]
        server.helo(generic_from_domain)
        server.mail(SMTP_CHECK_FROM_EMAIL)

        code, _ = server.rcpt(fake_address)
        if code in (250, 251):
            outcome = True   # accepted fake address → catch-all
        elif code in (550, 551, 552, 553, 450, 451, 452):
            outcome = False  # explicitly rejected → not catch-all
        else:
            outcome = None   # ambiguous
    except Exception:
        outcome = None
    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                pass

    catchall_cache[registrable_domain] = outcome
    return outcome


def get_domain_info(registrable_domain):
    if registrable_domain in whois_cache:
        return whois_cache[registrable_domain]

    company_name = "N/A"

    try:
        w = whois.whois(registrable_domain)
        if hasattr(w, 'organization') and w.organization:
            company_name = w.organization if isinstance(w.organization, str) else w.organization[0]
        elif hasattr(w, 'registrant_organization') and w.registrant_organization:
            company_name = w.registrant_organization if isinstance(w.registrant_organization, str) else w.registrant_organization[0]
        elif hasattr(w, 'name') and w.name:
            company_name = w.name if isinstance(w.name, str) else w.name[0]
        else:
            company_name = "Private/No Org Info"
    except Exception:
        company_name = "Lookup Failed"

    whois_cache[registrable_domain] = company_name
    return company_name


# --- Scoring Function ---
def calculate_deliverability_score(result):
    score = 100

    if not result["Syntax Valid"]:
        score -= 100
    elif result["Verdict"] == "❌ Invalid Domain Format":
        score -= 95
    elif result["Disposable"]:
        score -= 90
    elif result["Role-based"]:
        score -= 30
    else:
        if not result["MX Record"]:
            score -= 70
        if not result["SMTP Valid"]:
            score -= 50
        # NEW: catch-all penalty — SMTP accept is less trustworthy on catch-all domains
        if result.get("Catch-All") == "✅ Yes":
            score -= 20

    return max(0, score)


# --- Main Validation Logic ---
def validate_email(email, disposable_domains, role_based_prefixes, enable_company_lookup):
    """
    Performs a comprehensive validation of a single email address.
    Now also runs:
      • MX provider detection (Google Workspace / M365 / Proofpoint / Mimecast / Barracuda)
      • Domain aging (WHOIS creation date)
      • Raw SMTP RCPT TO response code
    """
    email = email.strip()

    result = {
        "Email": email,
        "Domain": "N/A",
        "Company/Org": "N/A (Pending)",
        "Syntax Valid": False,
        "MX Record": False,
        "MX Provider": "N/A",
        "Disposable": False,
        "Role-based": False,
        "SMTP Valid": False,
        "SMTP Code": None,          # NEW: raw SMTP RCPT TO response code
        "Catch-All": "N/A",
        "Domain Created": "N/A",    # NEW: domain creation date
        "Domain Age": "Unknown",    # NEW: human-readable age
        "Domain Age (days)": -1,    # NEW: numeric age for sorting
        "Verdict": "❌ Invalid",
        "Score": 0
    }

    # 1. Syntax Validation
    if not is_valid_syntax(email):
        result["Verdict"] = "❌ Invalid Syntax"
        result["Company/Org"] = "N/A (Invalid Syntax)"
        result["Score"] = calculate_deliverability_score(result)
        return result
    result["Syntax Valid"] = True

    local_part, full_domain_from_email = email.split('@')
    registrable_domain = get_registrable_domain(full_domain_from_email)
    result["Domain"] = registrable_domain if registrable_domain else full_domain_from_email

    if not registrable_domain:
        result["Verdict"] = "❌ Invalid Domain Format"
        result["Company/Org"] = "N/A (Invalid Domain)"
        result["Score"] = calculate_deliverability_score(result)
        return result

    # 2. Conditional Company Lookup
    if enable_company_lookup:
        result["Company/Org"] = get_domain_info(registrable_domain)
    else:
        result["Company/Org"] = "Lookup Disabled"

    # 3. Disposable & Role-based
    result["Disposable"] = is_disposable(registrable_domain, disposable_domains)
    result["Role-based"] = is_role_based(local_part, role_based_prefixes)

    # 4. MX Record Check
    result["MX Record"] = has_mx_record(registrable_domain)

    # 5. MX Provider Detection (runs for every email, regardless of MX outcome)
    result["MX Provider"] = detect_mx_provider(registrable_domain)

    # NEW: 5b. Domain Aging
    if enable_company_lookup:
        age_info = get_domain_age(registrable_domain)
        result["Domain Created"] = age_info["creation_date"]
        result["Domain Age"] = age_info["age_label"]
        result["Domain Age (days)"] = age_info["age_days"]

    # 6. SMTP Verification (now captures raw code)
    if result["MX Record"] and not result["Disposable"]:
        smtp_valid, smtp_code = verify_smtp_with_code(email, registrable_domain)
        result["SMTP Valid"] = smtp_valid
        result["SMTP Code"] = smtp_code
    else:
        result["SMTP Valid"] = False
        result["SMTP Code"] = None

    # 6b. Catch-All Detection (only when MX is present and domain is not disposable)
    if result["MX Record"] and not result["Disposable"]:
        catchall_outcome = detect_catch_all(registrable_domain)
        if catchall_outcome is True:
            result["Catch-All"] = "✅ Yes"
        elif catchall_outcome is False:
            result["Catch-All"] = "❌ No"
        else:
            result["Catch-All"] = "❓ Unknown"
    else:
        result["Catch-All"] = "N/A"

    # Final Verdict Logic
    if result["Disposable"]:
        result["Verdict"] = "⚠️ Disposable"
    elif result["Role-based"]:
        result["Verdict"] = "ℹ️ Role-based"
    elif all([result["Syntax Valid"], result["MX Record"], result["SMTP Valid"]]):
        if result.get("Catch-All") == "✅ Yes":
            result["Verdict"] = "⚠️ Valid (Catch-All)"
        else:
            result["Verdict"] = "✅ Valid"
    else:
        result["Verdict"] = "❌ Invalid"

    result["Score"] = calculate_deliverability_score(result)
    return result


# ─────────────────────────────────────────────
# NEW: Helper – build domain-aging summary DataFrame from results
# ─────────────────────────────────────────────
def build_domain_age_df(results: list[dict]) -> pd.DataFrame:
    """
    Extracts per-domain aging info from a list of validate_email() result dicts.
    Deduplicates by domain so each domain appears only once.
    """
    seen = {}
    for r in results:
        domain = r.get("Domain", "N/A")
        if domain not in seen:
            seen[domain] = {
                "Domain": domain,
                "Creation Date": r.get("Domain Created", "N/A"),
                "Age": r.get("Domain Age", "Unknown"),
                "Age (days)": r.get("Domain Age (days)", -1),
            }
    df = pd.DataFrame(list(seen.values()))
    if not df.empty:
        df = df.sort_values("Age (days)", ascending=False).reset_index(drop=True)
    return df


# ─────────────────────────────────────────────
# NEW: Helper – build SMTP code summary DataFrame from results
# ─────────────────────────────────────────────
def build_smtp_code_df(results: list[dict]) -> pd.DataFrame:
    """
    Extracts per-email SMTP RCPT TO response codes from validate_email() result dicts.
    """
    rows = []
    for r in results:
        code = r.get("SMTP Code")
        if code is None:
            code_str = "N/A (Error / Not Reached)"
            meaning = "Connection error, DNS failure, or disposable/no-MX skip"
        else:
            code_str = str(code)
            # Map common SMTP codes to human-readable meanings
            meanings = {
                250: "✅ OK – Mailbox exists",
                251: "✅ User not local; will forward",
                421: "⚠️ Service unavailable (try later)",
                450: "⚠️ Mailbox unavailable (temporary)",
                451: "⚠️ Aborted (local error in processing)",
                452: "⚠️ Insufficient system storage",
                500: "❌ Syntax error (command unrecognized)",
                501: "❌ Syntax error in parameters",
                503: "❌ Bad sequence of commands",
                521: "❌ Domain does not accept mail",
                550: "❌ Mailbox unavailable / does not exist",
                551: "❌ User not local; please try forwarding",
                552: "❌ Exceeded storage allocation",
                553: "❌ Mailbox name not allowed",
                554: "❌ Transaction failed",
            }
            meaning = meanings.get(code, f"SMTP code {code}")
        rows.append({
            "Email": r.get("Email", ""),
            "Domain": r.get("Domain", "N/A"),
            "SMTP Code": code_str,
            "Meaning": meaning,
            "SMTP Valid": "✅" if r.get("SMTP Valid") else "❌",
        })
    df = pd.DataFrame(rows)
    return df


# --- Email Sending Function ---
def send_email_via_yagmail(sender_email, sender_password, recipient_email, subject, body, smtp_host, smtp_port):
    try:
        if not sender_email or not sender_password or not recipient_email or not subject or not body:
            return False, "All sender email, password, recipient, subject, and body fields are required."

        if "@gmail.com" in sender_email.lower() and "@" not in sender_password:
            st.warning("For Gmail, if you have 2FA enabled, you might need an **App Password** instead of your regular password. See Google Account -> Security -> App Passwords.")

        if smtp_port == 465:
            yag = yagmail.SMTP(
                user=sender_email, password=sender_password,
                host=smtp_host, port=smtp_port, ssl=True
            )
        else:
            yag = yagmail.SMTP(
                user=sender_email, password=sender_password,
                host=smtp_host, port=smtp_port, starttls=True
            )

        yag.send(to=recipient_email, subject=subject, contents=body)
        return True, "Email sent successfully!"
    except Exception as e:
        error_message = str(e)
        if "SMTPAuthenticationError" in error_message or "Authentication failed" in error_message or "authentication required" in error_message:
            return False, f"Authentication failed. Check your sender email and password (or App Password for Gmail). Error: {error_message}"
        elif "SMTPConnectError" in error_message or "Connection refused" in error_message or "No route to host" in error_message:
            return False, f"Could not connect to SMTP server. Check host/port or internet connection. Error: {error_message}"
        elif "WRONG_VERSION_NUMBER" in error_message or "SSLError" in error_message or "certificate verify failed" in error_message:
            return False, f"SSL/TLS Error: Port/Encryption mismatch. Ensure you're using the correct port (e.g., 465 for SSL or 587 for TLS/STARTTLS) for your SMTP server. Error: {error_message}"
        return False, f"Failed to send email: An unexpected error occurred: {error_message}"


# --- Email Permutator Logic ---
def generate_email_permutations_raw(first_name, last_name, domain, nickname=None):
    first = first_name.lower().strip()
    last = last_name.lower().strip()
    dom = domain.lower().strip()
    nick = nickname.lower().strip() if nickname else None

    first_initial = first[0] if first else ''
    last_initial = last[0] if last else ''

    first_clean = re.sub(r'[^a-z0-9]', '', first)
    last_clean = re.sub(r'[^a-z0-9]', '', last)
    nick_clean = re.sub(r'[^a-z0-9]', '', nick) if nick else None

    permutations = set()
    patterns_to_try = []

    if first_clean and last_clean:
        patterns_to_try.extend([
            f"{first_clean}.{last_clean}", f"{first_clean}{last_clean}", f"{first_clean}_{last_clean}",
            f"{last_clean}.{first_clean}", f"{last_clean}{first_clean}", f"{last_clean}_{first_clean}",
        ])

    if first_initial and last_clean:
        patterns_to_try.extend([
            f"{first_initial}.{last_clean}", f"{first_initial}{last_clean}", f"{first_initial}_{last_clean}",
        ])

    if first_clean and last_initial:
        patterns_to_try.extend([
            f"{first_clean}.{last_initial}", f"{first_clean}{last_initial}", f"{first_clean}_{last_initial}",
        ])

    if first_initial and last_initial:
        patterns_to_try.extend([
            f"{first_initial}.{last_initial}", f"{first_initial}{last_initial}", f"{first_initial}_{last_initial}",
        ])

    if first_clean:
        patterns_to_try.append(first_clean)
    if last_clean:
        patterns_to_try.append(last_clean)

    if nick_clean:
        patterns_to_try.append(nick_clean)
        if first_clean and last_clean:
            patterns_to_try.extend([
                f"{nick_clean}.{last_clean}", f"{first_clean}.{nick_clean}",
                f"{nick_clean}{last_clean}", f"{first_clean}{nick_clean}",
                f"{nick_clean}_{last_clean}", f"{first_clean}_{nick_clean}",
            ])
        elif first_clean:
            patterns_to_try.extend([
                f"{nick_clean}{first_clean}", f"{first_clean}{nick_clean}",
                f"{nick_clean}_{first_clean}", f"{first_clean}_{nick_clean}"
            ])
        elif last_clean:
            patterns_to_try.extend([
                f"{nick_clean}{last_clean}", f"{last_clean}{nick_clean}",
                f"{nick_clean}_{last_clean}", f"{last_clean}_{nick_clean}"
            ])

    for p in patterns_to_try:
        if p:
            full_email = f"{p}@{dom}"
            if is_valid_syntax(full_email):
                permutations.add(full_email)

    return sorted(list(permutations))


# ─────────────────────────────────────────────
# NEW: Shared helper to render Domain Aging and SMTP Code tabs
# ─────────────────────────────────────────────
def render_domain_age_tab(results: list[dict], key_prefix: str = ""):
    """Renders the Domain Aging results inside whichever tab calls it."""
    if not results:
        st.info("No results available yet. Run a validation first.")
        return

    df_age = build_domain_age_df(results)
    if df_age.empty:
        st.info("No domain aging data could be retrieved.")
        return

    st.markdown("""
    The table below shows the **registration age** of each unique domain encountered during validation.
    Domain age is a trust signal — very young domains (< 90 days) may indicate spam or phishing infrastructure.
    """)

    # Highlight very young domains
    young_threshold = 90
    young_count = (df_age["Age (days)"] >= 0) & (df_age["Age (days)"] < young_threshold)
    if young_count.any():
        st.warning(f"⚠️ **{young_count.sum()}** domain(s) are younger than {young_threshold} days — treat with caution.")

    st.dataframe(df_age, use_container_width=True)

    csv_age = df_age.to_csv(index=False).encode("utf-8")
    st.download_button(
        "⬇️ Download Domain Aging CSV",
        data=csv_age,
        file_name="domain_aging.csv",
        mime="text/csv",
        key=f"{key_prefix}_dl_age",
    )


def render_smtp_code_tab(results: list[dict], key_prefix: str = ""):
    """Renders the SMTP Response Code results inside whichever tab calls it."""
    if not results:
        st.info("No results available yet. Run a validation first.")
        return

    df_smtp = build_smtp_code_df(results)
    if df_smtp.empty:
        st.info("No SMTP response code data available.")
        return

    st.markdown("""
    The table below shows the **raw SMTP RCPT TO response code** returned by each mail server
    during the handshake, along with a human-readable explanation.
    `N/A` means the SMTP stage was not reached (e.g. DNS failure, disposable domain, or no MX record).
    """)

    # Summary counts by code
    code_counts = df_smtp["SMTP Code"].value_counts().reset_index()
    code_counts.columns = ["SMTP Code", "Count"]
    st.subheader("📊 Code Distribution")
    st.dataframe(code_counts, use_container_width=True, hide_index=True)
    st.divider()

    st.subheader("📋 Per-Email Detail")
    st.dataframe(df_smtp, use_container_width=True)

    csv_smtp = df_smtp.to_csv(index=False).encode("utf-8")
    st.download_button(
        "⬇️ Download SMTP Codes CSV",
        data=csv_smtp,
        file_name="smtp_response_codes.csv",
        mime="text/csv",
        key=f"{key_prefix}_dl_smtp",
    )


# --- Streamlit UI ---
# ─────────────────────────────────────────────
# Safe CSV reader — handles non-UTF-8 files
# ─────────────────────────────────────────────
def read_csv_safe(file) -> pd.DataFrame:
    """
    Reads a CSV uploaded via Streamlit's file_uploader, gracefully handling
    files that are not UTF-8 encoded (e.g. Latin-1, CP1252, UTF-16).
    Strategy:
      1. Read raw bytes and let chardet detect the encoding.
      2. Try that detected encoding first.
      3. Fall back to latin-1, which accepts every possible byte value.
    """
    raw = file.read()
    detected = chardet.detect(raw)
    encoding = detected.get("encoding") or "utf-8"
    try:
        return pd.read_csv(io.BytesIO(raw), encoding=encoding)
    except (UnicodeDecodeError, LookupError):
        return pd.read_csv(io.BytesIO(raw), encoding="latin-1")


st.set_page_config(page_title="Email Validator", page_icon="✅", layout="wide")
st.title("📧 Email Validator & Permutator")

st.markdown("""
Welcome to the **Email Validator & Sender Tool**! This application is designed to help you ensure the quality and deliverability of your email lists.

**Key Features:**
* **Enhanced Email Validation:** Utilizes strict RFC-compliant syntax checks, accurate domain resolution (identifying the true registrable domain), MX record verification, and direct SMTP mailbox existence checks.
* **Deliverability Scoring:** Each validated email receives a numerical score (0-100) indicating its likely deliverability, helping you prioritize or segment your email lists.
* **Disposable & Role-Based Detection:** Automatically flags emails from temporary services or generic addresses like `admin@` or `info@`.
* **Optional Company/Organization Lookup:** Attempts to identify the company or organization associated with the email's domain using public WHOIS data. This feature can be toggled On/Off in settings as its reliability varies.
* **MX Provider Detection:** Identifies whether the domain routes mail through Google Workspace, Microsoft 365, Proofpoint, Mimecast, Barracuda, or another provider — shown for every email.
* **Catch-All Domain Detection:** Probes each domain with a fake, randomly-generated address to determine whether it accepts mail for any recipient. Emails on catch-all domains receive a reduced score and a dedicated verdict (`⚠️ Valid (Catch-All)`).
* **Domain Aging:** Shows the WHOIS registration date and age for every domain — helping flag suspiciously young or newly-registered domains.
* **SMTP Response Codes:** Captures and displays the raw SMTP RCPT TO response code for every handshake, with human-readable explanations.
* **Test Email Sending:** A built-in utility to send test emails, allowing you to verify your SMTP settings and ensure your messages can be sent successfully from within the app.
* **Email Permutator with Validation:** Generate common email address combinations for a given name and domain (including nicknames), and then **automatically validate** these generated emails for deliverability.
* **Customizable Configurations:** Easily adjust disposable domains, role-based prefixes, and SMTP sender details to match your specific needs.
* **Anti-Idle Protection:** The app automatically keeps itself alive for up to 240 minutes via a silent background refresh, preventing Streamlit Cloud from sleeping during long validation runs.
""")

st.divider()

# --- Top Section: Intro Text and Configuration in Columns ---
intro_text_col, config_col = st.columns([3, 1])

with intro_text_col:
    st.subheader("🚀 Get Started")
    st.markdown("""
    This tool offers three primary functionalities, accessible via the tabs below:
    
    1.  **⚡ Email Validator:**
        * Paste a list of email addresses (comma or newline separated) for comprehensive validation.
        * Get detailed results including a **Deliverability Score** (0-100) and **MX Provider**.
        * Two additional tabs show **Domain Aging** and **SMTP Response Codes** for every address.

    2.  **✉️ Send Test Email:**
        * Quickly send a test email from your configured sender account to verify SMTP settings.

    3.  **🧩 Email Permutator:**
        * Generate a list of common email address combinations for a person (First Name, Last Name, Nickname, Domain).
        * **Automatically validates** all generated emails, providing scores and deliverability verdicts directly in the results table.
        * Includes **Domain Aging** and **SMTP Response Code** tabs for permuted addresses too.
    
    **Important:** Please review and set up your **Configuration Settings** in the expander on the right.
    """)

with config_col:
    with st.expander("⚙️ Configuration Settings", expanded=True):
        st.info("Adjust the parameters for email validation and sending. Your changes will apply to all subsequent actions.")
        st.divider()

        with st.container(border=True):
            st.subheader("📬 SMTP Sender Details")
            st.write("For **sending test emails**, use your actual sender email and password. For **validation**, a generic internal address will be used for SMTP checks.")

            sender_email_input = st.text_input(
                "Your Sender Email (e.g., yourname@gmail.com):",
                value=DEFAULT_FROM_EMAIL,
                key="sender_email_input",
            )
            sender_password_input = st.text_input(
                "Sender Email Password / App Password:",
                type="password",
                key="sender_password_input",
            )

            st.markdown("---")
            st.write("**Advanced SMTP Settings (for non-Gmail or custom servers)**")
            st.info("""
            Common SMTP Ports:
            * **587:** Recommended for **STARTTLS** (explicit TLS). Most common.
            * **465:** For **SSL** (implicit TLS).
            * **25:** Unencrypted (often blocked/discouraged for sending).
            """)
            smtp_host_input = st.text_input(
                "SMTP Host (e.g., smtp.gmail.com):",
                value=DEFAULT_SMTP_HOST,
                key="smtp_host_input",
            )
            smtp_port_input = st.number_input(
                "SMTP Port (e.g., 587):",
                value=DEFAULT_SMTP_PORT,
                key="smtp_port_input",
                step=1,
            )

            from_email_valid_for_sending = is_valid_syntax(sender_email_input)
            if not from_email_valid_for_sending:
                st.error("🚨 Invalid Sender Email format. Please correct if you plan to send test emails.")
            if not sender_password_input:
                st.warning("⚠️ Sender Password is required for **sending test emails**.")

        st.divider()

        with st.container(border=True):
            st.subheader("🔍 Validation Specific Settings")
            st.write("Customize lists for email classification and enable/disable optional lookups.")

            enable_company_lookup = st.checkbox(
                "Enable Company/Organization + domain-age lookup (WHOIS)",
                value=False,
                help="WHOIS servers can be slow or unavailable from Streamlit Cloud. Leave this off for fast validation.",
            )
            if not enable_company_lookup:
                st.info("Company/Organization Lookup is currently disabled.")

            st.markdown("---")
            disposable_input = st.text_area(
                "Disposable Domains (comma or newline separated):",
                value=", ".join(DISPOSABLE_DOMAINS),
                height=100,
                key="disposable_domains_input",
            )
            disposable_domains_set = set(d.strip().lower() for d in disposable_input.replace(',', '\n').split('\n') if d.strip())

            st.markdown("---")
            role_based_input = st.text_area(
                "Role-based Prefixes (comma or newline separated):",
                value=", ".join(ROLE_BASED_PREFIXES),
                height=100,
                key="role_based_prefixes_input",
            )
            role_based_prefixes_set = set(p.strip().lower() for p in role_based_input.replace(',', '\n').split('\n') if p.strip())


st.divider()

# --- Initialize session state ---
if 'stop_validation' not in st.session_state:
    st.session_state.stop_validation = False
if 'is_validating' not in st.session_state:
    st.session_state.is_validating = False
if 'stop_permutation_validation' not in st.session_state:
    st.session_state.stop_permutation_validation = False
if 'is_permutating_and_validating' not in st.session_state:
    st.session_state.is_permutating_and_validating = False

# NEW: session state to persist results across tabs
if 'validator_results' not in st.session_state:
    st.session_state.validator_results = []
if 'permutator_results' not in st.session_state:
    st.session_state.permutator_results = []
if 'batch_csv_results' not in st.session_state:
    st.session_state.batch_csv_results = []
if 'batch_csv_source_df' not in st.session_state:
    st.session_state.batch_csv_source_df = None
if 'is_batch_validating' not in st.session_state:
    st.session_state.is_batch_validating = False
if 'stop_batch_validation' not in st.session_state:
    st.session_state.stop_batch_validation = False
if 'gmail_batch_results' not in st.session_state:
    st.session_state.gmail_batch_results = []
if 'gmail_batch_source_df' not in st.session_state:
    st.session_state.gmail_batch_source_df = None
if 'is_gmail_batch_validating' not in st.session_state:
    st.session_state.is_gmail_batch_validating = False
if 'stop_gmail_batch_validation' not in st.session_state:
    st.session_state.stop_gmail_batch_validation = False


def stop_validation_callback():
    st.session_state.stop_validation = True


def stop_permutation_validation_callback():
    st.session_state.stop_permutation_validation = True


def stop_batch_validation_callback():
    st.session_state.stop_batch_validation = True


def stop_gmail_batch_validation_callback():
    st.session_state.stop_gmail_batch_validation = True


# --- Main Tabs ---
tab_validator, tab_batch_csv, tab_gmail_batch, tab_extract, tab_sender, tab_permutator = st.tabs(["⚡ Email Validator", "📂 Batch CSV Import", "📨 Gmail Batch Validator", "📮 Provider Email Extractor", "✉️ Send Test Email", "🧩 Email Permutator"])

# ─────────────────────────────────────────────
# Email Validator Tab
# ─────────────────────────────────────────────
with tab_validator:
    st.header("🚀 Validate Your Emails")
    st.markdown("""
    Paste a list of email addresses below. The tool will conduct a deep validation, checking syntax,
    domain existence, MX records, SMTP mailbox verification, MX provider identification,
    domain aging, and raw SMTP response codes.
    """)
    st.divider()

    user_input = st.text_area(
        "Enter emails here (separated by commas or newlines):",
        placeholder="e.g., alice@example.com, bob@company.net\ncontact@marketing.org",
        height=250,
        key="email_input"
    )

    with st.container():
        col_start_btn, col_spacer = st.columns([1, 4])

        if col_start_btn.button("✅ Validate Emails", use_container_width=True, type="primary",
                                disabled=st.session_state.is_validating or st.session_state.is_permutating_and_validating):
            st.session_state.stop_validation = False
            st.session_state.is_validating = True

            raw_emails = [e.strip() for e in user_input.replace(',', '\n').split('\n') if e.strip()]

            if not raw_emails:
                st.warning("☝️ Please enter at least one email address to validate.")
                st.session_state.is_validating = False
            else:
                unique_emails = list(set(raw_emails))
                if len(raw_emails) != len(unique_emails):
                    st.info(f"✨ Detected and removed **{len(raw_emails) - len(unique_emails)}** duplicate email(s). Processing **{len(unique_emails)}** unique email(s).")
                emails_to_validate = unique_emails

                with st.status(f"Validating {len(emails_to_validate)} email(s)... Please wait.", expanded=True, state="running") as status_container:
                    st.button("⏹️ Stop Validation", key="status_stop_btn_validator",
                              on_click=stop_validation_callback,
                              help="Click to immediately halt the current validation process.")

                    progress_bar = st.progress(0, text="Starting validation...")

                    results = []
                    total_emails = len(emails_to_validate)

                    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT) as executor:
                        futures = {
                            executor.submit(validate_email, email, disposable_domains_set, role_based_prefixes_set, enable_company_lookup): email
                            for email in emails_to_validate
                        }

                        for i, future in enumerate(as_completed(futures)):
                            if st.session_state.stop_validation:
                                status_container.update(label="Validation Aborted by User! 🛑", state="error", expanded=True)
                                for f in futures:
                                    f.cancel()
                                break

                            results.append(future.result())
                            progress_percent = (i + 1) / total_emails
                            progress_bar.progress(progress_percent, text=f"Processing email {i + 1} of {total_emails}...")

                        if not st.session_state.stop_validation:
                            status_container.update(label="Validation Complete! 🎉", state="complete", expanded=False)

                    st.session_state.is_validating = False
                    st.session_state.stop_validation = False
                    # NEW: persist results for secondary tabs
                    st.session_state.validator_results = results

    # ── Results area (always shown if there are stored results) ──
    results = st.session_state.get("validator_results", [])
    if results:
        df = pd.DataFrame(results)

        # NEW: three sub-tabs for validator results
        vtab_main, vtab_age, vtab_smtp = st.tabs([
            "📋 Validation Results",
            "🕰️ Domain Aging",
            "📡 SMTP Response Codes",
        ])

        with vtab_main:
            st.subheader("📊 Validation Summary")
            verdict_counts = Counter(df['Verdict'])

            summary_cols = st.columns(min(len(verdict_counts) + 1, 5))
            col_idx = 0

            metric_icons = {
                "✅ Valid": "✨", "❌ Invalid": "🚫", "⚠️ Disposable": "🗑️",
                "ℹ️ Role-based": "👥", "❌ Invalid Syntax": "📝", "❌ Invalid Domain Format": "🌐",
                "⚠️ Valid (Catch-All)": "🪤"
            }

            for verdict in sorted(verdict_counts.keys()):
                count = verdict_counts[verdict]
                with summary_cols[col_idx % len(summary_cols)]:
                    st.metric(label=f"{metric_icons.get(verdict, '❓')} {verdict}", value=count)
                col_idx += 1

            if not df.empty:
                with summary_cols[col_idx % len(summary_cols)]:
                    avg_score = df['Score'].mean()
                    st.metric("⭐ Avg. Score", f"{avg_score:.2f}")

            st.divider()
            st.subheader("Detailed Results & Export")

            all_verdicts = df['Verdict'].unique().tolist()
            filter_options = ["All"] + sorted(all_verdicts)

            selected_verdict = st.selectbox(
                "🔍 Filter results by verdict type:",
                filter_options,
            )

            filtered_df = df if selected_verdict == "All" else df[df['Verdict'] == selected_verdict]
            st.dataframe(filtered_df, use_container_width=True, height=400)

            csv = filtered_df.to_csv(index=False).encode('utf-8')
            st.download_button(
                "⬇️ Download Filtered Results as CSV",
                data=csv,
                file_name="email_validation_results.csv",
                mime="text/csv",
            )

        with vtab_age:
            st.subheader("🕰️ Domain Aging")
            render_domain_age_tab(results, key_prefix="val")

        with vtab_smtp:
            st.subheader("📡 SMTP Response Codes")
            render_smtp_code_tab(results, key_prefix="val")

# ─────────────────────────────────────────────
# Batch CSV Import Tab
# ─────────────────────────────────────────────
with tab_batch_csv:
    st.header("📂 Batch CSV Import & Validate")
    st.markdown("""
    Upload **one or more CSV files** containing contact records. Each file must include an `email` column.
    All other recognised fields will be preserved alongside the validation results in the export.

    **Expected columns** (all optional except `email`):
    `email`, `ip`, `url`, `datetime`, `fname`, `lname`, `address`, `address2`, `city`, `state`, `zip`, `phone`, `dob`, `gender`
    """)
    st.divider()

    BATCH_EXPECTED_FIELDS = [
        "email", "ip", "url", "datetime", "fname", "lname",
        "address", "address2", "city", "state", "zip", "phone", "dob", "gender"
    ]

    uploaded_csvs = st.file_uploader(
        "Upload CSV file(s):",
        type=["csv"],
        accept_multiple_files=True,
        key="batch_csv_uploader",
        help="Each file must contain at least an email column. Multiple files will be merged."
    )

    if uploaded_csvs:
        preview_frames = []
        parse_errors = []
        for f in uploaded_csvs:
            try:
                tmp = read_csv_safe(f)
                tmp.columns = [c.strip().lower() for c in tmp.columns]
                if "email" not in tmp.columns:
                    parse_errors.append(f"⚠️ **{f.name}** — no email column found, skipped.")
                else:
                    preview_frames.append(tmp)
            except Exception as e:
                parse_errors.append(f"❌ **{f.name}** — could not parse: {e}")

        for err in parse_errors:
            st.warning(err)

        if preview_frames:
            merged_df = pd.concat(preview_frames, ignore_index=True)
            present_cols = [c for c in BATCH_EXPECTED_FIELDS if c in merged_df.columns]
            missing_cols = [c for c in BATCH_EXPECTED_FIELDS if c not in merged_df.columns]

            col_info1, col_info2 = st.columns(2)
            with col_info1:
                st.success(f"✅ **{len(merged_df):,}** rows loaded from {len(preview_frames)} file(s).")
                st.caption(f"Columns found: " + ", ".join(f"`{c}`" for c in present_cols))
            with col_info2:
                if missing_cols:
                    st.info("ℹ️ Columns not present (will be blank in output): " + ", ".join(f"`{c}`" for c in missing_cols))

            with st.expander("🔍 Preview first 10 rows", expanded=False):
                st.dataframe(merged_df.head(10), use_container_width=True)

            total_rows = len(merged_df)
            unique_emails_preview = merged_df["email"].dropna().str.strip().unique()
            n_dupes = total_rows - len(unique_emails_preview)
            if n_dupes > 0:
                st.info(f"✨ {n_dupes} duplicate email(s) detected — only unique addresses will be validated.")

            can_batch_validate = (
                not st.session_state.is_batch_validating
                and not st.session_state.is_validating
                and not st.session_state.is_permutating_and_validating
                and len(unique_emails_preview) > 0
            )

            if st.button(
                f"✅ Validate {len(unique_emails_preview):,} Email(s)",
                type="primary",
                disabled=not can_batch_validate,
                key="batch_validate_btn"
            ):
                st.session_state.stop_batch_validation = False
                st.session_state.is_batch_validating = True
                st.session_state.batch_csv_results = []
                st.session_state.batch_csv_source_df = merged_df.copy()

                emails_to_validate = [e.strip() for e in unique_emails_preview if isinstance(e, str) and e.strip()]

                with st.status(
                    f"Validating {len(emails_to_validate):,} email(s) from CSV… Please wait.",
                    expanded=True, state="running"
                ) as batch_status:
                    st.button(
                        "⏹️ Stop Batch Validation",
                        key="stop_batch_btn",
                        on_click=stop_batch_validation_callback
                    )
                    progress_bar = st.progress(0, text="Starting batch validation…")

                    batch_results = []
                    total_batch = len(emails_to_validate)

                    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT) as executor:
                        futures = {
                            executor.submit(
                                validate_email, email,
                                disposable_domains_set, role_based_prefixes_set, enable_company_lookup
                            ): email
                            for email in emails_to_validate
                        }

                        for i, future in enumerate(as_completed(futures)):
                            if st.session_state.stop_batch_validation:
                                batch_status.update(
                                    label="Batch Validation Aborted! 🛑", state="error", expanded=True
                                )
                                for f in futures:
                                    f.cancel()
                                break

                            batch_results.append(future.result())
                            progress_bar.progress(
                                (i + 1) / total_batch,
                                text=f"Validated {i + 1} of {total_batch}…"
                            )

                        if not st.session_state.stop_batch_validation:
                            batch_status.update(
                                label="Batch Validation Complete! 🎉", state="complete", expanded=False
                            )

                st.session_state.is_batch_validating = False
                st.session_state.stop_batch_validation = False
                st.session_state.batch_csv_results = batch_results

    batch_results = st.session_state.get("batch_csv_results", [])
    source_df = st.session_state.get("batch_csv_source_df")

    if batch_results:
        df_batch_val = pd.DataFrame(batch_results)

        if source_df is not None:
            BATCH_EXPECTED_FIELDS_MERGE = [
                "email", "ip", "url", "datetime", "fname", "lname",
                "address", "address2", "city", "state", "zip", "phone", "dob", "gender"
            ]
            source_df["email_key"] = source_df["email"].str.strip().str.lower()
            df_batch_val["email_key"] = df_batch_val["Email"].str.strip().str.lower()
            extra_cols = [c for c in BATCH_EXPECTED_FIELDS_MERGE if c != "email" and c in source_df.columns]
            src_lookup = source_df.drop_duplicates("email_key")[["email_key"] + extra_cols]
            df_merged_out = df_batch_val.merge(src_lookup, on="email_key", how="left").drop(columns=["email_key"])
        else:
            df_merged_out = df_batch_val

        btab_main, btab_age, btab_smtp = st.tabs([
            "📋 Batch Results",
            "🕰️ Domain Aging",
            "📡 SMTP Response Codes",
        ])

        with btab_main:
            st.subheader("📊 Batch Validation Summary")
            b_verdict_counts = Counter(df_batch_val["Verdict"])
            b_summary_cols = st.columns(min(len(b_verdict_counts) + 1, 5))
            b_col_idx = 0
            metric_icons_b = {
                "✅ Valid": "✨", "❌ Invalid": "🚫", "⚠️ Disposable": "🗑️",
                "ℹ️ Role-based": "👥", "❌ Invalid Syntax": "📝", "❌ Invalid Domain Format": "🌐",
                "⚠️ Valid (Catch-All)": "🪤"
            }
            for verdict in sorted(b_verdict_counts.keys()):
                with b_summary_cols[b_col_idx % len(b_summary_cols)]:
                    st.metric(
                        label=f"{metric_icons_b.get(verdict, '❓')} {verdict}",
                        value=b_verdict_counts[verdict]
                    )
                b_col_idx += 1
            if not df_batch_val.empty:
                with b_summary_cols[b_col_idx % len(b_summary_cols)]:
                    st.metric("⭐ Avg. Score", f"{df_batch_val['Score'].mean():.2f}")

            st.divider()
            st.subheader("Detailed Results & Export")

            b_all_verdicts = df_merged_out["Verdict"].unique().tolist()
            b_filter_options = ["All"] + sorted(b_all_verdicts)
            b_selected_verdict = st.selectbox(
                "🔍 Filter by verdict:", b_filter_options, key="batch_verdict_filter"
            )
            b_filtered_df = (
                df_merged_out if b_selected_verdict == "All"
                else df_merged_out[df_merged_out["Verdict"] == b_selected_verdict]
            )

            st.dataframe(b_filtered_df, use_container_width=True, height=450)
            st.download_button(
                "⬇️ Download Batch Results as CSV",
                data=b_filtered_df.to_csv(index=False).encode("utf-8"),
                file_name="batch_email_validation_results.csv",
                mime="text/csv",
                key="batch_dl_results",
            )

        with btab_age:
            st.subheader("🕰️ Domain Aging")
            render_domain_age_tab(batch_results, key_prefix="batch")

        with btab_smtp:
            st.subheader("📡 SMTP Response Codes")
            render_smtp_code_tab(batch_results, key_prefix="batch")

    elif not st.session_state.get("is_batch_validating") and not uploaded_csvs:
        st.info("Upload one or more CSV files above to get started.")

st.write("")

# ─────────────────────────────────────────────
# Gmail Batch Validator Tab
# ─────────────────────────────────────────────
with tab_gmail_batch:
    st.header("📨 Gmail-Only Batch Validator")
    st.markdown("""
    Upload **one or more CSV files** — only rows where the email ends in **@gmail.com** will be
    extracted and validated. All other addresses are silently skipped.

    Validation runs the full pipeline: syntax → MX → SMTP → Catch-All

    **Expected columns** (all optional except `email`):
    `email`, `ip`, `url`, `datetime`, `fname`, `lname`, `address`, `address2`,
    `city`, `state`, `zip`, `phone`, `dob`, `gender`
    """)
    st.divider()

    GMAIL_EXPECTED_FIELDS = [
        "email", "ip", "url", "datetime", "fname", "lname",
        "address", "address2", "city", "state", "zip", "phone", "dob", "gender"
    ]

    gmail_uploaded_csvs = st.file_uploader(
        "Upload CSV file(s):",
        type=["csv"],
        accept_multiple_files=True,
        key="gmail_batch_csv_uploader",
        help="Files must contain an 'email' column. Non-Gmail addresses are automatically filtered out."
    )

    if gmail_uploaded_csvs:
        gmail_preview_frames = []
        gmail_parse_errors = []
        for f in gmail_uploaded_csvs:
            try:
                tmp = read_csv_safe(f)
                tmp.columns = [c.strip().lower() for c in tmp.columns]
                if "email" not in tmp.columns:
                    gmail_parse_errors.append(f"⚠️ **{f.name}** — no `email` column found, skipped.")
                else:
                    gmail_preview_frames.append(tmp)
            except Exception as e:
                gmail_parse_errors.append(f"❌ **{f.name}** — could not parse: {e}")

        for err in gmail_parse_errors:
            st.warning(err)

        if gmail_preview_frames:
            gmail_merged_df = pd.concat(gmail_preview_frames, ignore_index=True)

            # ── Filter to @gmail.com only ──
            gmail_merged_df["email"] = gmail_merged_df["email"].astype(str).str.strip()
            gmail_only_df = gmail_merged_df[
                gmail_merged_df["email"].str.lower().str.endswith("@gmail.com")
            ].copy().reset_index(drop=True)

            total_rows = len(gmail_merged_df)
            total_gmail = len(gmail_only_df)
            skipped = total_rows - total_gmail

            gmail_present_cols = [c for c in GMAIL_EXPECTED_FIELDS if c in gmail_merged_df.columns]
            gmail_missing_cols = [c for c in GMAIL_EXPECTED_FIELDS if c not in gmail_merged_df.columns]

            col_g1, col_g2, col_g3 = st.columns(3)
            col_g1.metric("📥 Total Rows Loaded", f"{total_rows:,}")
            col_g2.metric("📨 Gmail Addresses Found", f"{total_gmail:,}")
            col_g3.metric("⏭️ Non-Gmail Skipped", f"{skipped:,}")

            if gmail_missing_cols:
                st.info("ℹ️ Columns not present (will be blank in output): " + ", ".join(f"`{c}`" for c in gmail_missing_cols))

            if total_gmail == 0:
                st.warning("⚠️ No @gmail.com addresses found in the uploaded files.")
            else:
                unique_gmail_emails = gmail_only_df["email"].str.lower().unique()
                n_gmail_dupes = total_gmail - len(unique_gmail_emails)
                if n_gmail_dupes > 0:
                    st.info(f"✨ {n_gmail_dupes} duplicate Gmail address(es) removed — {len(unique_gmail_emails):,} unique addresses to validate.")

                with st.expander("🔍 Preview Gmail addresses (first 10)", expanded=False):
                    st.dataframe(gmail_only_df.head(10), use_container_width=True)

                can_gmail_validate = (
                    not st.session_state.is_gmail_batch_validating
                    and not st.session_state.is_validating
                    and not st.session_state.is_batch_validating
                    and not st.session_state.is_permutating_and_validating
                    and len(unique_gmail_emails) > 0
                )

                if st.button(
                    f"✅ Validate {len(unique_gmail_emails):,} Gmail Address(es)",
                    type="primary",
                    disabled=not can_gmail_validate,
                    key="gmail_batch_validate_btn"
                ):
                    st.session_state.stop_gmail_batch_validation = False
                    st.session_state.is_gmail_batch_validating = True
                    st.session_state.gmail_batch_results = []
                    st.session_state.gmail_batch_source_df = gmail_only_df.copy()

                    emails_to_validate_gmail = list(unique_gmail_emails)

                    with st.status(
                        f"Validating {len(emails_to_validate_gmail):,} Gmail address(es)… Please wait.",
                        expanded=True, state="running"
                    ) as gmail_status:
                        st.button(
                            "⏹️ Stop Gmail Validation",
                            key="stop_gmail_batch_btn",
                            on_click=stop_gmail_batch_validation_callback
                        )
                        gmail_progress = st.progress(0, text="Starting Gmail validation…")

                        gmail_results_run = []
                        total_gmail_batch = len(emails_to_validate_gmail)

                        with ThreadPoolExecutor(max_workers=MAX_CONCURRENT) as executor:
                            futures = {
                                executor.submit(
                                    validate_email, email,
                                    disposable_domains_set, role_based_prefixes_set, enable_company_lookup
                                ): email
                                for email in emails_to_validate_gmail
                            }

                            for i, future in enumerate(as_completed(futures)):
                                if st.session_state.stop_gmail_batch_validation:
                                    gmail_status.update(
                                        label="Gmail Validation Aborted! 🛑", state="error", expanded=True
                                    )
                                    for f in futures:
                                        f.cancel()
                                    break

                                gmail_results_run.append(future.result())
                                gmail_progress.progress(
                                    (i + 1) / total_gmail_batch,
                                    text=f"Validated {i + 1} of {total_gmail_batch} Gmail addresses…"
                                )

                            if not st.session_state.stop_gmail_batch_validation:
                                gmail_status.update(
                                    label="Gmail Validation Complete! 🎉", state="complete", expanded=False
                                )

                    st.session_state.is_gmail_batch_validating = False
                    st.session_state.stop_gmail_batch_validation = False
                    st.session_state.gmail_batch_results = gmail_results_run

    # ── Gmail results area ──
    gmail_results = st.session_state.get("gmail_batch_results", [])
    gmail_source_df = st.session_state.get("gmail_batch_source_df")

    if gmail_results:
        df_gmail_val = pd.DataFrame(gmail_results)

        # Merge original CSV fields back in
        if gmail_source_df is not None:
            gmail_source_df["email_key"] = gmail_source_df["email"].str.strip().str.lower()
            df_gmail_val["email_key"] = df_gmail_val["Email"].str.strip().str.lower()
            extra_g_cols = [c for c in GMAIL_EXPECTED_FIELDS if c != "email" and c in gmail_source_df.columns]
            g_src_lookup = gmail_source_df.drop_duplicates("email_key")[["email_key"] + extra_g_cols]
            df_gmail_merged = df_gmail_val.merge(g_src_lookup, on="email_key", how="left").drop(columns=["email_key"])
        else:
            df_gmail_merged = df_gmail_val

        gtab_main, gtab_age, gtab_smtp = st.tabs([
            "📋 Gmail Results",
            "🕰️ Domain Aging",
            "📡 SMTP Response Codes",
        ])

        with gtab_main:
            st.subheader("📊 Gmail Validation Summary")
            g_verdict_counts = Counter(df_gmail_val["Verdict"])
            g_summary_cols = st.columns(min(len(g_verdict_counts) + 1, 5))
            g_col_idx = 0
            metric_icons_g = {
                "✅ Valid": "✨", "❌ Invalid": "🚫", "⚠️ Disposable": "🗑️",
                "ℹ️ Role-based": "👥", "❌ Invalid Syntax": "📝", "❌ Invalid Domain Format": "🌐",
                "⚠️ Valid (Catch-All)": "🪤"
            }
            for verdict in sorted(g_verdict_counts.keys()):
                with g_summary_cols[g_col_idx % len(g_summary_cols)]:
                    st.metric(
                        label=f"{metric_icons_g.get(verdict, '❓')} {verdict}",
                        value=g_verdict_counts[verdict]
                    )
                g_col_idx += 1
            if not df_gmail_val.empty:
                with g_summary_cols[g_col_idx % len(g_summary_cols)]:
                    st.metric("⭐ Avg. Score", f"{df_gmail_val['Score'].mean():.2f}")

            st.divider()
            st.subheader("Detailed Gmail Results & Export")

            g_all_verdicts = df_gmail_merged["Verdict"].unique().tolist()
            g_filter_options = ["All"] + sorted(g_all_verdicts)
            g_selected_verdict = st.selectbox(
                "🔍 Filter by verdict:", g_filter_options, key="gmail_verdict_filter"
            )
            g_filtered_df = (
                df_gmail_merged if g_selected_verdict == "All"
                else df_gmail_merged[df_gmail_merged["Verdict"] == g_selected_verdict]
            )

            st.dataframe(g_filtered_df, use_container_width=True, height=450)

            st.download_button(
                "⬇️ Download Gmail Results as CSV",
                data=g_filtered_df.to_csv(index=False).encode("utf-8"),
                file_name="gmail_batch_validation_results.csv",
                mime="text/csv",
                key="gmail_dl_results",
            )

        with gtab_age:
            st.subheader("🕰️ Domain Aging")
            render_domain_age_tab(gmail_results, key_prefix="gmail")

        with gtab_smtp:
            st.subheader("📡 SMTP Response Codes")
            render_smtp_code_tab(gmail_results, key_prefix="gmail")

    elif not st.session_state.get("is_gmail_batch_validating") and not gmail_uploaded_csvs:
        st.info("Upload one or more CSV files above to validate Gmail addresses.")

st.write("")

# ─────────────────────────────────────────────
# NEW: Provider Email Extractor Tab
# ─────────────────────────────────────────────
with tab_extract:
    st.header("📮 Provider Email Extractor")
    st.markdown("""
    Upload **one or more CSV files** and pull out just the rows whose email address belongs to the
    provider domain(s) you pick below — e.g. `@att.net`, `@bellsouth.net`, `@yahoo.com`. Rows with
    any other domain are skipped. This tab only **extracts and exports**; it does not run any
    validation checks.

    **Expected columns** (all optional except `email`):
    `email`, `ip`, `url`, `datetime`, `fname`, `lname`, `address`, `address2`, `city`, `state`, `zip`, `phone`, `dob`, `gender`
    """)
    st.divider()

    EXTRACT_EXPECTED_FIELDS = [
        "email", "ip", "url", "datetime", "fname", "lname",
        "address", "address2", "city", "state", "zip", "phone", "dob", "gender"
    ]

    COMMON_PROVIDER_DOMAINS = [
        "att.net", "bellsouth.net", "yahoo.com", "aol.com", "sbcglobal.net",
        "verizon.net", "comcast.net", "gmail.com", "hotmail.com", "outlook.com",
        "icloud.com", "msn.com", "live.com", "me.com",
    ]

    col_ex1, col_ex2 = st.columns([2, 1])
    with col_ex1:
        extract_selected_providers = st.multiselect(
            "Provider domain(s) to extract:",
            options=COMMON_PROVIDER_DOMAINS,
            default=["att.net", "bellsouth.net", "yahoo.com"],
            key="extract_provider_multiselect",
            help="Pick any of the common webmail/ISP domains, or add your own on the right.",
        )
    with col_ex2:
        extract_custom_domains_raw = st.text_input(
            "Add custom domain(s):",
            key="extract_custom_domains",
            placeholder="e.g. protonmail.com, gmx.com",
            help="Comma-separated list of extra domains to include.",
        )

    extract_custom_domains = [
        d.strip().lower().lstrip("@") for d in extract_custom_domains_raw.split(",") if d.strip()
    ]
    extract_all_providers = sorted(set([p.lower() for p in extract_selected_providers] + extract_custom_domains))

    extract_uploaded_csvs = st.file_uploader(
        "Upload CSV file(s):",
        type=["csv"],
        accept_multiple_files=True,
        key="extract_csv_uploader",
        help="Each file must contain an 'email' column. Multiple files will be merged before filtering.",
    )

    if not extract_all_providers:
        st.info("💡 Select at least one provider domain (or add a custom one) to enable extraction.")

    if extract_uploaded_csvs and extract_all_providers:
        extract_preview_frames = []
        extract_parse_errors = []
        for f in extract_uploaded_csvs:
            try:
                tmp = read_csv_safe(f)
                tmp.columns = [c.strip().lower() for c in tmp.columns]
                if "email" not in tmp.columns:
                    extract_parse_errors.append(f"⚠️ **{f.name}** — no `email` column found, skipped.")
                else:
                    extract_preview_frames.append(tmp)
            except Exception as e:
                extract_parse_errors.append(f"❌ **{f.name}** — could not parse: {e}")

        for err in extract_parse_errors:
            st.warning(err)

        if extract_preview_frames:
            extract_merged_df = pd.concat(extract_preview_frames, ignore_index=True)
            extract_merged_df["email"] = extract_merged_df["email"].astype(str).str.strip()

            def _extract_email_domain(addr):
                addr = addr.strip().lower()
                if "@" not in addr:
                    return None
                return addr.rsplit("@", 1)[-1]

            extract_merged_df["__domain"] = extract_merged_df["email"].apply(_extract_email_domain)

            extract_filtered_df = extract_merged_df[
                extract_merged_df["__domain"].isin(extract_all_providers)
            ].copy().reset_index(drop=True)

            extract_total_rows = len(extract_merged_df)
            extract_total_matched = len(extract_filtered_df)
            extract_skipped = extract_total_rows - extract_total_matched

            col_e1, col_e2, col_e3 = st.columns(3)
            col_e1.metric("📥 Total Rows Loaded", f"{extract_total_rows:,}")
            col_e2.metric("📮 Matching Addresses Found", f"{extract_total_matched:,}")
            col_e3.metric("⏭️ Skipped (other domains)", f"{extract_skipped:,}")

            if extract_total_matched == 0:
                st.warning("⚠️ No addresses matching the selected provider domain(s) were found.")
            else:
                extract_dedupe_key = extract_filtered_df["email"].str.lower()
                extract_n_dupes = extract_total_matched - extract_dedupe_key.nunique()
                if extract_n_dupes > 0:
                    st.info(f"✨ {extract_n_dupes} duplicate address(es) present among matched rows.")

                st.subheader("📊 Breakdown by Provider")
                extract_provider_counts = extract_filtered_df["__domain"].value_counts()
                extract_breakdown_cols = st.columns(min(len(extract_provider_counts), 5) or 1)
                for i, (domain, count) in enumerate(extract_provider_counts.items()):
                    with extract_breakdown_cols[i % len(extract_breakdown_cols)]:
                        st.metric(f"@{domain}", f"{count:,}")

                st.divider()
                st.subheader("Extracted Addresses & Export")

                extract_filter_options = ["All"] + sorted(extract_provider_counts.index.tolist())
                extract_selected_filter = st.selectbox(
                    "🔍 Filter preview by provider:",
                    extract_filter_options,
                    key="extract_provider_filter",
                )
                extract_display_df = (
                    extract_filtered_df if extract_selected_filter == "All"
                    else extract_filtered_df[extract_filtered_df["__domain"] == extract_selected_filter]
                )

                extract_export_cols = [c for c in EXTRACT_EXPECTED_FIELDS if c in extract_display_df.columns]
                extract_display_export_df = (
                    extract_display_df[extract_export_cols] if extract_export_cols
                    else extract_display_df.drop(columns=["__domain"], errors="ignore")
                )

                st.dataframe(extract_display_export_df, use_container_width=True, height=400)

                st.download_button(
                    "⬇️ Download Filtered Emails as CSV",
                    data=extract_display_export_df.to_csv(index=False).encode("utf-8"),
                    file_name="extracted_provider_emails.csv",
                    mime="text/csv",
                    key="extract_dl_filtered",
                )

                with st.expander("📦 Download a separate CSV per provider", expanded=False):
                    for domain in sorted(extract_provider_counts.index.tolist()):
                        per_provider_df = extract_filtered_df[extract_filtered_df["__domain"] == domain]
                        per_export_cols = [c for c in EXTRACT_EXPECTED_FIELDS if c in per_provider_df.columns]
                        per_export_df = (
                            per_provider_df[per_export_cols] if per_export_cols
                            else per_provider_df.drop(columns=["__domain"], errors="ignore")
                        )
                        st.download_button(
                            f"⬇️ Download @{domain} ({len(per_provider_df):,})",
                            data=per_export_df.to_csv(index=False).encode("utf-8"),
                            file_name=f"extracted_{domain.replace('.', '_')}.csv",
                            mime="text/csv",
                            key=f"extract_dl_{domain}",
                        )

    elif not extract_uploaded_csvs:
        st.info("Upload one or more CSV files above to extract provider-specific addresses.")

st.write("")

# ─────────────────────────────────────────────
# Send Test Email Tab
# ─────────────────────────────────────────────
with tab_sender:
    st.header("✉️ Send a Test Email")
    st.markdown("""
    Use this feature to send a test email from your configured sender account.
    This helps confirm your SMTP settings and ensure your messages can be sent successfully.
    """)
    st.divider()

    st.warning("""
        **Gmail Users with 2-Step Verification:** You **MUST** generate an **App Password** for your Google account and use that in the password field in `Configuration Settings`. Your regular Gmail password will likely not work.
        """)

    recipient_test_email = st.text_input("Recipient Email:", key="recipient_test_email", placeholder="test@example.com")
    test_subject = st.text_input("Subject:", key="test_subject", placeholder="Test Email from Streamlit App")
    test_body = st.text_area("Email Body:", key="test_body", height=150, placeholder="Hello, this is a test email sent from the Streamlit Email Tool!")

    can_send_email = (
        from_email_valid_for_sending and
        bool(sender_password_input) and
        bool(recipient_test_email) and
        bool(test_subject) and
        bool(test_body) and
        not st.session_state.is_validating and
        not st.session_state.is_permutating_and_validating
    )

    if not from_email_valid_for_sending or not sender_password_input:
        st.info("💡 Please set your 'Sender Email' and 'Password' in Configuration Settings to enable sending.")
    elif not (bool(recipient_test_email) and bool(test_subject) and bool(test_body)):
        st.info("💡 Fill in all fields (Recipient, Subject, Body) to enable sending the test email.")

    if st.button("🚀 Send Test Email", type="primary", disabled=not can_send_email):
        with st.spinner("Sending email..."):
            success, message = send_email_via_yagmail(
                sender_email_input, sender_password_input,
                recipient_test_email, test_subject, test_body,
                smtp_host_input, smtp_port_input
            )
            if success:
                st.success(f"✅ {message}")
            else:
                st.error(f"❌ {message}")

st.write("")

# ─────────────────────────────────────────────
# Email Permutator Tab
# ─────────────────────────────────────────────
with tab_permutator:
    st.header("🧩 Email Permutator & Validator")
    st.markdown("""
        Generate a list of common email address combinations for a person based on their name and domain.
        The tool will then **automatically validate** these generated emails against all deliverability checks,
        including MX provider detection, domain aging, and SMTP response codes.
        """)
    st.warning("⚠️ **Important:** While this tool generates possible emails, the validation process is crucial to determine their actual deliverability.")
    st.divider()

    col_name1, col_name2 = st.columns(2)
    with col_name1:
        perm_first_name = st.text_input("First Name:", key="perm_first_name", placeholder="John")
    with col_name2:
        perm_last_name = st.text_input("Last Name:", key="perm_last_name", placeholder="Doe")

    perm_nickname = st.text_input("Nickname (Optional):", key="perm_nickname", placeholder="Johnny")
    perm_domain = st.text_input("Domain (e.g., example.com):", key="perm_domain", placeholder="company.com")

    can_generate_and_validate = (
        (bool(perm_first_name) or bool(perm_last_name) or bool(perm_nickname)) and
        bool(perm_domain) and
        not st.session_state.is_permutating_and_validating and
        not st.session_state.is_validating
    )

    if not (bool(perm_first_name) or bool(perm_last_name) or bool(perm_nickname)):
        st.info("💡 Enter at least a First Name, Last Name, or Nickname to enable generation.")
    elif not perm_domain:
        st.info("💡 Enter a Domain (e.g., example.com) to enable generation.")

    if not from_email_valid_for_sending:
        st.warning("⚠️ **SMTP verification might be limited for generated emails!** Your Sender Email (in Configuration) is invalid.")

    col_gen_btn, col_stop_perm_btn_spacer = st.columns([1, 1])

    if col_gen_btn.button("✨ Generate & Validate Emails", type="primary", disabled=not can_generate_and_validate):
        st.session_state.stop_permutation_validation = False
        st.session_state.is_permutating_and_validating = True

        if not perm_first_name and not perm_last_name and not perm_nickname:
            st.warning("Please enter at least a First Name, Last Name, or Nickname to generate permutations.")
            st.session_state.is_permutating_and_validating = False
        elif not perm_domain:
            st.warning("Please enter a Domain to generate permutations.")
            st.session_state.is_permutating_and_validating = False
        else:
            with st.status("Generating email permutations...", expanded=True, state="running") as gen_status:
                generated_emails_raw = generate_email_permutations_raw(
                    first_name=perm_first_name,
                    last_name=perm_last_name,
                    domain=perm_domain,
                    nickname=perm_nickname if perm_nickname else None
                )
                if generated_emails_raw:
                    gen_status.update(label=f"Generated {len(generated_emails_raw)} unique permutations. Now validating...", state="running", expanded=True)
                else:
                    gen_status.update(label="No permutations generated. Check input.", state="complete", expanded=False)
                    st.warning("No email combinations could be generated with the provided details.")
                    st.session_state.is_permutating_and_validating = False
                    st.session_state.stop_permutation_validation = False
                    st.experimental_rerun()

            if generated_emails_raw and st.session_state.is_permutating_and_validating:
                with st.status(f"Validating {len(generated_emails_raw)} generated emails... Please wait.", expanded=True, state="running") as val_status_container:
                    st.button("⏹️ Stop Permutation Validation", key="status_stop_perm_btn",
                              on_click=stop_permutation_validation_callback)

                    progress_bar = st.progress(0, text="Starting validation of permutations...")

                    validated_results = []
                    total_generated = len(generated_emails_raw)

                    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT) as executor:
                        futures = {
                            executor.submit(validate_email, email, disposable_domains_set, role_based_prefixes_set, enable_company_lookup): email
                            for email in generated_emails_raw
                        }

                        for i, future in enumerate(as_completed(futures)):
                            if st.session_state.stop_permutation_validation:
                                val_status_container.update(label="Permutation Validation Aborted by User! 🛑", state="error", expanded=True)
                                for f in futures:
                                    f.cancel()
                                break

                            validated_results.append(future.result())
                            progress_percent = (i + 1) / total_generated
                            progress_bar.progress(progress_percent, text=f"Processing generated email {i + 1} of {total_generated}...")

                    if not st.session_state.stop_permutation_validation:
                        val_status_container.update(label="Permutation Validation Complete! 🎉", state="complete", expanded=False)

                st.session_state.is_permutating_and_validating = False
                st.session_state.stop_permutation_validation = False
                # NEW: persist permutator results
                st.session_state.permutator_results = validated_results

    # ── Permutator results area ──
    validated_results = st.session_state.get("permutator_results", [])
    if validated_results:
        df_validated_permutations = pd.DataFrame(validated_results)

        # NEW: three sub-tabs for permutator results
        ptab_main, ptab_age, ptab_smtp = st.tabs([
            "📋 Permutation Results",
            "🕰️ Domain Aging",
            "📡 SMTP Response Codes",
        ])

        with ptab_main:
            st.success("🎉 Permutations generated and validated! Here are the results:")

            st.subheader("📊 Permutation Validation Summary")
            perm_verdict_counts = Counter(df_validated_permutations['Verdict'])

            perm_summary_cols = st.columns(min(len(perm_verdict_counts) + 1, 5))
            perm_col_idx = 0

            metric_icons = {
                "✅ Valid": "✨", "❌ Invalid": "🚫", "⚠️ Disposable": "🗑️",
                "ℹ️ Role-based": "👥", "❌ Invalid Syntax": "📝", "❌ Invalid Domain Format": "🌐",
                "⚠️ Valid (Catch-All)": "🪤"
            }

            for verdict in sorted(perm_verdict_counts.keys()):
                count = perm_verdict_counts[verdict]
                with perm_summary_cols[perm_col_idx % len(perm_summary_cols)]:
                    st.metric(label=f"{metric_icons.get(verdict, '❓')} {verdict}", value=count)
                perm_col_idx += 1

            if not df_validated_permutations.empty:
                with perm_summary_cols[perm_col_idx % len(perm_summary_cols)]:
                    avg_perm_score = df_validated_permutations['Score'].mean()
                    st.metric("⭐ Avg. Score", f"{avg_perm_score:.2f}")

            st.divider()
            st.subheader("Detailed Permutation Results & Export")

            perm_all_verdicts = df_validated_permutations['Verdict'].unique().tolist()
            perm_filter_options = ["All"] + sorted(perm_all_verdicts)

            perm_selected_verdict = st.selectbox(
                "🔍 Filter permutation results by verdict type:",
                perm_filter_options,
                key="perm_filter_select",
            )

            perm_filtered_df = df_validated_permutations if perm_selected_verdict == "All" else df_validated_permutations[df_validated_permutations['Verdict'] == perm_selected_verdict]

            st.dataframe(perm_filtered_df, use_container_width=True, height=400)

            csv_permutations_validated = perm_filtered_df.to_csv(index=False).encode('utf-8')
            st.download_button(
                "⬇️ Download Validated Permutations as CSV",
                data=csv_permutations_validated,
                file_name="email_permutations_validated.csv",
                mime="text/csv",
            )

        with ptab_age:
            st.subheader("🕰️ Domain Aging")
            render_domain_age_tab(validated_results, key_prefix="perm")

        with ptab_smtp:
            st.subheader("📡 SMTP Response Codes")
            render_smtp_code_tab(validated_results, key_prefix="perm")

    elif not st.session_state.get("is_permutating_and_validating"):
        st.info("No validated permutations to display yet. Fill in the fields above and click **Generate & Validate Emails**.")

st.write("")
st.divider()
st.markdown("Developed with ❤️ with Streamlit and community libraries.")