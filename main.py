import concurrent.futures
import io
import json
import multiprocessing
import os
import random
import re
import shutil
import sqlite3
import subprocess
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from math import log2
from queue import Empty, Queue
from threading import Lock
from urllib.parse import parse_qsl, urlparse, urlsplit
import urllib.parse
import fitz  # PyMuPDF
import pandas as pd
import pytesseract
import requests
from bs4 import BeautifulSoup, Comment
from deep_translator import GoogleTranslator
from langdetect import detect
from PIL import Image, ImageOps
from pyzbar.pyzbar import decode as zbar_decode
from PyPDF2 import PdfReader
from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

stats = defaultdict(int)
stats_lock = threading.Lock()

results_lock = Lock()
results = []
# Total found in filtering
stats["photo_live"] = 0
stats["esign_total"] = 0
stats["paste_total"] = 0

# Passed live check
stats["photo_live"] = 0
stats["esign_live"] = 0
stats["paste_live"] = 0
stats["non_english"] = 0


SCREENSHOT_FOLDER = "..."
HTML_FOLDER = "..."
OCR_SCREENSHOT_FOLDER = "..."
OCR_HTML_FOLDER = "..."
PDF_FOLDER = os.path.join(os.getcwd(), "pdf_downloads")

RESULTS_DB = "..."
NUM_THREADS = 10
url_queue = Queue()
live_urls = 0
dead_urls = 0

# Create folders
os.makedirs(SCREENSHOT_FOLDER, exist_ok=True)
os.makedirs(HTML_FOLDER, exist_ok=True)

# Thread-safe variables
results_queue = Queue()
screenshot_counter = 1
counter_lock = threading.Lock()


INCLUSIVE_CONFIG = {
    "min_val_length": 16,
    "require_digit": True,
    "require_field_match": True,
    "min_html_length": 100,
    "min_structural_tags": 3,
    "allow_login_pages": False,
    "ocr_on_failure_only": True,
    "enable_translation": True,
    "max_translate_chars": 2000,
    "translate_langs": {"ja", "ar", "ru", "uk", "hi", "bn", "zh-cn", "zh-tw", "ko", "es", "pt", "fr", "de", "it"}
}

stats_lock = Lock()
stats = {
    "processed": 0, "live": 0, "dead": 0,
    "regular_ss": 0, "ocr_ss": 0, "ocr_leaks": 0,
    "http_leaks": 0, "non_english": 0,
    "photo_live": 0, "e_signature_live": 0, "paste_live": 0
}
SUSPICIOUS_URL_PARAMS_SET = {


    "envelope_id", "signing_token", "sessionid", "session_id", "session_key", "sign_token", "doc_hash",
    "signature_id", "access_code", "signing_session", "approve_token", "verify_token", "auth_key",
    "esign_request", "contract_id", "legal_doc", "agreement_id",
    "access_token", "refresh_token", "auth_token", "csrf", "xsrf", "session_token",
    "apikey", "api_key", "api_secret", "secret_key", "client_secret", "verification", "verify",
    "private_key", "public_key", "hash", "hmac", "security_code", "verification_code",
    "recovery_token", "reset_token", "oauth_token", "oauth_verifier", "bearer", "state_token",
    "security_login", "client_token", "sso_token", "authenticity_token",
    "csrftoken", "logincsrfparam", "requestverificationtoken", "security_token", "reservas", "csrf-token",

    "webhook_url", "webhook_token", "slack_webhook", "slack_token", "slack_bot_token",
    "discord_invite", "discord_bot_token", "telegram_bot_token", "telegram_chat_id",
    "github_token", "gitlab_token", "jenkins_token", "circleci_token", "ci_build_token",
    "build_hook", "api_webhook", "firebase_token", "twilio_sid", "twilio_token",
    "zendesk_token", "notion_token", "airtable_api_key", "api_url",

    "cart_id", "checkout", "order_number", "invoice_number", "purchase_id", "transaction_id",
    "transaction_token", "checkout_token", "order_reference", "payment_ref", "payment_token",
    "payment_id", "payment_method", "stripe_token", "paypal_token", "square_token",
    "debitcard", "creditcard", "cvc", "bank_account", "iban", "bic",
    "card_number", "account_number", "invoice_id", "receipt_number", "license_key",
    "discount_code", "promo_code", "coupon_code", "voucher_code", "voucher_id",
    "giftcard_number", "loyalty_card_id", "reward_points", "balance_amount", "billing",

    "file", "file_url", "fileid", "attachment", "attachment_id", "doc", "docid", "doc_token",
    "document", "document_id", "download_id", "download_token",
    "gdrive_file_id", "gdrive_share_link", "dropbox_link", "onedrive_link", "s3_bucket",
    "repository_url", "pdf_file", "docx_file", "xlsx_file", "gdrive", "onedrive",
    "backup_file", "database_dump", "config_file", "logfile", "snapshot_id", "backup", "config",

    "boardingpass", "visa", "pasabordo", "ticket", "ticket_id", "reservation_number",
    "booking_reference", "confirmation_number", "flight_number", "itinerary_id",
    "passport_number", "trip_id", "e_ticket_number", "booking_ref", "travel_doc_id",
    "miles_account_id", "frequent_flyer_number",

    "invite_link", "whatsapp_link", "messenger_thread_id", "facebook_id", "instagram_id",
    "snapchat_id", "skype_id", "social_user_id", "group_id", "chat_token",
    "customer_id", "user_id", "account_id", "member_id", "profile_id",
    "aadhaar_number", "nhs_number", "citizen_id", "residence_permit", "ssn_full",
    "student_id", "military_id", "beneficiary_id", "national_id", "social_security_number",
    "ssn", "driver_license_number", "tax_id", "pan_number", "pan_card", "identity_number",
    "ssn_last4", "health_id", "voter_id", "employee_id", "member_number",
    "email_address", "phone_number", "mobile_number", "fax_number", "emergency_contact",

    "billing_address", "shipping_address", "mailing_address", "home_address", "postal_code",
    "zip_code", "full_name", "first_name", "last_name", "middle_name", "dob", "date_of_birth",
    "place_of_birth", "gender", "nationality", "marital_status", "address",

    "insurance_number", "medical_record_id", "health_insurance_id", "vaccination_id",
    "blood_type", "healthcare_id", "dental_record_id", "employer_insurance_id",

    "tracking", "tracking_id", "tracking_number", "shipment_id", "parcel_id", "order_tracking_id",
    "delivery_note_number", "waybill_number", "dispatch_id",

    "employee_number", "staff_id", "internal_reference", "project_id", "vendor_id",
    "supplier_id", "purchase_order_id", "contract_number", "rfq_id", "invoice_reference",

    "wallet", "wallet_address", "crypto_token", "transaction_hash", "eth_address", "btc_address",
    "mnemonic_phrase", "seed_phrase", "keystore", "crypto_api_key", "crypto_secret_key",

    "audit_log_id", "incident_id", "security_alert_id", "fraud_case_id",
    "risk_score", "compliance_report_id",

    "file_name", "filename", "filepath", "doc_link", "dataset", "shared_link",
    "public_link", "direct_link", "temp_link", "auth", "signin", "login",
    "creds", "credentials", "password", "pwd", "passwd",
    "identity", "key", "certificate", "ssh_key", "oauth",
    "profile", "account", "settings", "media", "media_id", "photo",
    "image", "img_url", "video_url", "link"}

SUSPICIOUS_PARAMS_SET = {

    "envelope_id", "signing_token", "sessionid", "session_id", "session_key", "sign_token", "doc_hash",
    "signature_id", "access_code", "signing_session", "approve_token", "verify_token", "auth_key",
    "esign_request", "contract_id", "legal_doc", "agreement_id",
    "access_token", "refresh_token", "auth_token", "xsrf", "session_token", "csrf",
    "apikey", "api_key", "api_secret", "secret_key", "client_secret", "crypto_key", "crypto_address",
    "private_key", "private_key", "hmac", "security_code", "verification_code", "recovery_token", "reset_token", "oauth_token", "oauth_verifier", "crypto_wallet",
    "jwt", "bearer", "state_token", "token", "security-login", "client_token", "sso_token", "authenticity_token", "csrftoken", "logincsrfparam", "requestverificationtoken", "security_token",

    "national_id", "social_security_number", "driver_license_number",
    "tax_id", "pan_number", "pan_card", "identity_number", "ssn_last4", "health_id", "voter_id", "employee_id",

    "cart_id", "order_number", "invoice_number", "purchase_id", "transaction id", "transaction_token", "checkout_token",
    "order_reference", "payment_ref", "payment_token", "payment_id", "payment_method", "debitcard",
    "creditcard",  "bank_account",  "stripe_token", "card_number", "transaction_id",
    "invoice_id", "receipt_number", "account_number", "license_key",

    "fileid", "attachment_id", "docid", "doc_token", "document_id", "download_token",
    "gdrive_file_id", "gdrive_share_link", "dropbox_link", "onedrive_link", "s3_bucket", "repository_url",
    "pdf_file", "docx_file", "xlsx_file", "gdrive", "onedrive/",

    "ticket_id", "reservation_number", "booking_reference",
    "confirmation_number", "flight_number", "itinerary_id", "passport_number", "trip_id", "e_ticket_number", "booking_ref", "Boarding Pass", "Booking Reference", "Reservation Number",
    "Flight Number", "Confirmation Number", "E-Ticket Number",
    "Itinerary ID", "Passport Number", "Trip ID",

    "invite_link", "discord_invite", "discord_bot_token", "slack_webhook", "slack_bot_token",
    "telegram_bot_token", "telegram_chat_id", "social_user_id",
    "whatsapp_link", "facebook_id", "messenger_thread_id", "chat.whatsapp",
    "instagram_id", "snapchat_id", "skype_id",
    "discount_code", "promo_code", "coupon_code", "voucher_code", "voucher_id", "tracking_id",
    "tracking_number", "survey_id", "event_id", "chat_token", "customer_id",

    "citizen_id", "residence_permit",
    "ssn_full", "student_id", "military_id", "beneficiary_id",
    "billing_address", "shipping_address", "mailing_address",
    "insurance_number", "medical_record_id", "health_insurance_id", "vaccination_id",
    "Invoice Number", "Invoice ID", "Invoice #", "Invoice Total", "Invoice Amount", "Order Number", "Order ID", "Order #", "Order Total", "Order Amount",
    "Payment Method", "Payment Type", "Payment ID", "Payment Reference", "Card Number",
    "Credit Card Number", "Card Ending", "Cardholder Name", "Card Type", "Last 4 Digits",
    "Discord Invite", "Slack Invite", "Telegram Bot", "Messenger Thread",
    "WhatsApp Link", "Group ID", "Profile ID",
    "Wallet Address", "Crypto Token", "Transaction Hash", "Mnemonic", "Seed Phrase",
    "Download Link", "Document ID", "GDrive Link", "Dropbox Link",
}

E_SIGNATURE_DOMAINS = [
    "esignlive.com", "sandbox.esignlive.com", "docusign.net", "docusign.com", "secure.adobesign.com",
    "adobesign.com", "hellosign.com", "onespan.com", "signnow.com", "pandadoc.com", "dropboxsign.com",
    "rightsignature.com", "zohosign.com", "signrequest.com", "eversign.com", "assuresign.com",
    "formstack.com", "signeasy.com", "sertifi.com", "signable.com", "legalesign.com", "esignly.com",
    "signx.wondershare.com", "docsketch.com", "getaccept.com", "signaturit.com"
]

PHOTO_DOMAINS = [
    "photos.google.com", "lh3.googleusercontent.com", "drive.google.com",
    "dropboxusercontent.com", "imgur.com", "i.imgur.com", "i.redd.it", "preview.redd.it",
    "cdn.discordapp.com", "fbcdn.net", "scontent.xx.fbcdn.net", "telegra.ph",
    "cdn4.telegram-cdn.org", "mmg.whatsapp.net", "onedrive.live.com", "1drv.ms",
    "s3.amazonaws.com", "bucket.s3.amazonaws.com", "flickr.com", "staticflickr.com",
    "wetransfer.com", "transfer.sh", "user-images.githubusercontent.com", "prnt.sc",
    "snag.gy", "gyazo.com", "mail-attachment.googleusercontent.com", "attachments.office.net",
    "tinypic.com", "imageshack.us", "postimg.cc", "ibb.co", "freeimage.host", "imagevenue.com",
    "pixhost.to"
]

PASTE_DOMAINS = [
    "paste2.org", "jsbin.com", "play.golang.org", "paste.debian.net",
    "pastehtml.com", "pastebin.com", "snipplr.com", "snipt.net",
    "heypasteit.com", "pastebin.fr", "slexy.org", "hastebin.com",
    "dumpz.org", "codepad.org", "jsitor.com", "dpaste.org",
    "textsnip.com", "bitpaste.app", "justpaste.it", "jsfiddle.net",
    "dpaste.com", "codepen.io", "dartpad.dartlang.org",
    "ide.codingblocks.com", "dotnetfiddle.net", "ideone.com",
    "paste.fedoraproject.org", "paste.frubar.net", "repl.it",
    "paste.opensuse.org", "rextester.com", "paste.org.ru",
    "paste.ubuntu.com", "paste.pound-python.org", "paste.lisp.org",
    "paste.xinu.at", "try.ceylon-lang.org", "paste.org",
    "phpfiddle.org", "ide.geeksforgeeks.org"
]
# Normalize all suspicious param sets to lowercase for consistent matching
PHOTO_DOMAINS = [d.lower() for d in globals().get("PHOTO_DOMAINS", [])]
PASTE_DOMAINS = [d.lower() for d in globals().get("PASTE_DOMAINS", [])]
E_SIGNATURE_DOMAINS = [d.lower()
                       for d in globals().get("E_SIGNATURE_DOMAINS", [])]

SUSPICIOUS_URL_PARAMS_SET = {
    re.sub(r'[^a-z0-9]+', '_', s.lower()).strip('_') for s in SUSPICIOUS_URL_PARAMS_SET
}
SUSPICIOUS_PARAMS_SET = {
    re.sub(r'[^a-z0-9]+', '_', s.lower()).strip('_') for s in SUSPICIOUS_PARAMS_SET
}

def norm_key(
    s: str) -> str: return re.sub(r'[^a-z0-9]+', '_', (s or '').lower()).strip('_')

COMMON_JUNK = {
    "yes", "true", "ok", "none", "email", "submit", "click", "value", "button", "form",
    "name", "open", "more", "back", "next", "account", "password", "search", "video",
    "login", "register", "send", "go", "apply", "filter", "sort", "confirm", "cancel",
    "reset", "continue", "save", "update", "download", "upload", "admin", "user", "test",
    "e-mail", "name@host.com", "123456", "email or phone", "phone number", "enter your name", "sign in"
}
BAD_VALUES = COMMON_JUNK
JUNK_VALUES = COMMON_JUNK


# Chrome options
chrome_options = Options()
chrome_options.add_argument("--headless")
chrome_options.add_argument("--window-size=1280x800")
chrome_options.add_argument("--no-sandbox")
chrome_options.add_argument("--disable-dev-shm-usage")
chrome_options.add_argument("--disable-blink-features=AutomationControlled")
chrome_options.add_experimental_option(
    "excludeSwitches", ["enable-automation"])
chrome_options.add_experimental_option("useAutomationExtension", False)
chrome_options.add_argument("--ignore-certificate-errors")
chrome_options.add_argument("--incognito")
chrome_options.add_argument("--disable-features=VizDisplayCompositor")
# chrome_options.add_argument("--single-process")
chrome_options.add_argument("--renderer-process-limit=2")
chrome_options.add_argument("--disable-backgrounding-occluded-windows")
chrome_options.set_capability("goog:loggingPrefs", {"performance": "ALL"})

chrome_options.add_argument("--disable-extensions")
chrome_options.add_argument("--disable-background-networking")
chrome_options.add_argument("--metrics-recording-only")
chrome_options.add_argument("--disable-sync")
chrome_options.add_argument("--disable-gpu")
chrome_options.add_argument("--no-first-run")
chrome_options.add_argument("--disable-background-timer-throttling")
chrome_options.add_argument("--renderer-process-limit=1")


# Initialize DB

def init_results_db():
    os.makedirs(os.path.dirname(RESULTS_DB), exist_ok=True)

    conn = sqlite3.connect(RESULTS_DB)
    c = conn.cursor()

    c.execute(
        "CREATE TABLE IF NOT EXISTS leaks ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "url TEXT, "
        "status TEXT, "
        "matched_url TEXT, "
        "matched_html TEXT, "
        "screenshot_path TEXT, "
        "html_path TEXT"
        ")"
    )

    conn.commit()
    conn.close()



folder = "..."


all_urls = []


def load_urls_from_db(db_path, table_name, column_name):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(f"SELECT DISTINCT {column_name} FROM {table_name}")
    urls = [row[0] for row in cursor.fetchall()
            if row[0] and row[0].startswith("https://")]
    conn.close()
    return urls


PHOTO_DOMAINS = [d.lower() for d in PHOTO_DOMAINS]
PASTE_DOMAINS = [d.lower() for d in PASTE_DOMAINS]
E_SIGNATURE_DOMAINS = [d.lower() for d in E_SIGNATURE_DOMAINS]


def check_special_domain(url):

    domain = urllib.parse.urlparse(url).netloc.lower().split(":")[0]
    for d in PHOTO_DOMAINS:
        if domain == d or domain.endswith("." + d):
            return "photo"
    for d in E_SIGNATURE_DOMAINS:
        if domain == d or domain.endswith("." + d):
            return "e_signature"
    for d in PASTE_DOMAINS:
        if domain == d or domain.endswith("." + d):
            return "paste"
    return None

def filter_useful_urls(url_list):
    global screenshot_counter

    useful_urls = []
    skipped_reasons = {
        "static_file": 0,
        "no_signal": 0
    }
    bad_exts = {
        ".gif", ".css", ".svg", ".woff", ".ico", ".mp4", ".webp",
        ".jpg", ".jpeg", ".png", ".bmp", ".tif", ".tiff", ".heic", ".webm",
        ".zip", ".tar", ".gz", ".7z", ".rar"
    }
    for url in url_list:
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            url_path = parsed.path.lower()
            url_query = parsed.query.lower()
        except Exception as e:
            print(f" Error parsing URL: {url} — {e}")
            continue

        # === Skip static files first ===
        is_static = any(
            url_path.endswith(ext) and not (
                ".php" in url_path or ".asp" in url_path)
            for ext in bad_exts
        )
        if is_static:
            skipped_reasons["static_file"] += 1
            continue

        # === Auto-process domain-matched URLs ===
        domain_type = check_special_domain(url)
        if domain_type in {"photo", "e_signature", "paste"}:
            print(
                f"Matched special domain ({domain_type}) → deferring to worker...")
            useful_urls.append({
                "url": url,
                "matched_url": f"{domain_type} domain matched"
            })
            continue

        # === Fast suspicious param match ===
        query_params = urllib.parse.parse_qs(url_query)

        # --- keep single-param URLs if value looks random ---
        if len(query_params) == 1:
            k, vals = next(iter(query_params.items()))
            v = vals[0] if vals else ""
            if looks_random(v):
                useful_urls.append({
                    "url": url,
                    "matched_url": f"single_param_random:{k}={v}"
                })
                continue

        query_keys = set(norm_key(k) for k in query_params)
        matching_keys = SUSPICIOUS_URL_PARAMS_SET & query_keys

        url_leaks = []
        for key in matching_keys:
            val_list = query_params.get(key, [])
            val = val_list[0] if val_list else ''
            if 'link' in key:
                if (val.startswith('http') or
                        any(val.lower().endswith(ext) for ext in ['.pdf', '.html', '.docx', '.xlsx', '.zip', '.exe', '.php'])):
                    url_leaks.append({
                        "type": key,
                        "value": val,
                        "source": "url_param"
                    })
            else:
                url_leaks.append({
                    "type": key,
                    "value": val,
                    "source": "url_param"
                })

        # === Deduplicate values ===
        seen_values = set()
        deduped_leaks = []
        for leak in url_leaks:
            val = leak['value']
            if val not in seen_values:
                deduped_leaks.append(leak)
                seen_values.add(val)
        url_leaks = deduped_leaks

        # === Confirmed URL leak match ===
        if url_leaks:
            _, _, pairs = format_leaks(url_leaks)
            useful_urls.append({
                "url": url,
                "matched_url": pairs
            })
            continue

        # === High-signal heuristic match ===
        hint = is_high_signal_heuristic(url, query_params)
        if hint:
            print(f" Heuristic match → keeping: {url} ({hint})")
            useful_urls.append({
                "url": url,
                "matched_url": hint
            })
            continue

        # === Skip if nothing matched ===
        skipped_reasons["no_signal"] += 1

    return useful_urls


def is_high_signal_heuristic(url, query_params):
    parsed = urllib.parse.urlparse(url)
    url_path = parsed.path.lower()
    path_segments = url_path.strip("/").split("/")

    long_keys = any(len(k) >= 1600 for k in query_params.keys())
    many_params = len(query_params) >= 10

    if many_params and long_keys:
        return "heuristic: many long query params"

    if len(url) >= 220 and url.count("/") >= 6:
        return "heuristic: long URL with depth"

    if any(len(seg) > 30 for seg in path_segments):
        return "heuristic: long path segment"

    return None


def decode_pdf_file(pdf_path, dpi=200, max_pages=None):
    #Render PDF pages and decode barcodes. Returns list with page index.
    results = []
    try:
        doc = fitz.open(pdf_path)
        page_count = doc.page_count
        pages = range(page_count) if not max_pages else range(
            min(page_count, max_pages))
        for pi in pages:
            page = doc.load_page(pi)
            mat = fitz.Matrix(dpi/72, dpi/72)
            pix = page.get_pixmap(matrix=mat, alpha=False)
            img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)

        doc.close()
    except Exception as e:
        print(f" decode_pdf_file error: {e}")
    return results


def looks_random(val: str) -> bool:
    v = (val or "").strip()
    if len(v) < 12:
        return False
    # reject obvious junk like emails/urls
    if "@" in v or v.startswith(("http://", "https://")):
        return False
    # check character class diversity
    classes = sum([
        any(c.islower() for c in v),
        any(c.isupper() for c in v),
        any(c.isdigit() for c in v),
        any(c in "-_.~+/=" for c in v),
    ])
    if classes < 2:
        return False
    # normalized Shannon entropy
    probs = [v.count(c)/len(v) for c in set(v)]
    H = -sum(p*log2(p) for p in probs)
    Hnorm = H / log2(len(set(v))) if len(set(v)) > 1 else 0
    return Hnorm >= 0.85


def extract_dynamic_inputs(driver, suspicious_keywords, config):
    leaks = []
    inputs = driver.find_elements(By.TAG_NAME, "input")

    for inp in inputs:
        try:
            name = (inp.get_attribute("name")
                    or inp.get_attribute("id") or "").lower()
            value = inp.get_attribute("value") or ""

            if not value or value.lower() in JUNK_VALUES:
                continue

            matched_type = None
            for keyword in suspicious_keywords:
                if keyword in name:
                    matched_type = keyword
                    break

            if config.get("require_field_match") and not matched_type:
                continue

            if is_valid_leak_value(value, config):
                leaks.append({
                    "type": matched_type or "input_value",
                    "value": value.strip(),
                    "field": name,
                    "source": "input_dynamic"
                })
                print(
                    f"Extracted dynamic input: type={matched_type or 'input_value'}, field={name}, value={value.strip()}")
        except Exception as e:
            print(f" Error in dynamic input extraction: {e}")
            continue
    return leaks

def is_url_live(url):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }

        # === HEAD request — allow 200–399
        head_resp = requests.head(
            url, headers=headers, timeout=20, allow_redirects=False)
        if 200 <= head_resp.status_code < 400:
            return True, url

        # === Fallback to GET request — allow redirects now
        get_resp = requests.get(url, headers=headers,
                                timeout=25, allow_redirects=True)
        html = get_resp.text.strip().lower()

        # Accept 200–399
        if not (200 <= get_resp.status_code < 400):
            return False, url

        # Softer blocked keywords: log but don’t block
        blocked_keywords = [
            "not found", "access denied", "you need permission",
            "403 forbidden", "sign in", "login required",
            "unavailable", "you have been blocked",
            "error 404", "page doesn't exist", "404"
        ]
        if any(phrase in html for phrase in blocked_keywords):
            print(f" Warning: Blocked phrase detected  → {url}")

        return True, url

    except requests.exceptions.RequestException as e:
        print(f" Network error: {e}")
        return False, url

    except Exception as e:
        print(f" Unexpected error for {url}: {e}")
        return False, url


def take_screenshot(url, prefix="test", screenshot_dir=None, html_dir=None):
    global chrome_options, CHROMEDRIVER_PATH

    if screenshot_dir is None:
        screenshot_dir = SCREENSHOT_FOLDER
    if html_dir is None:
        html_dir = HTML_FOLDER
    try:
        os.makedirs(screenshot_dir, exist_ok=True)
        os.makedirs(html_dir, exist_ok=True)
    except Exception as e:
        print(f" Dir creation failed: {e}")
        return None, None, None

    timestamp = int(time.time() * 1000)
    ss_path = os.path.join(screenshot_dir, f"{prefix}_{timestamp}.png")
    html_path = os.path.join(html_dir, f"{prefix}_{timestamp}.html")

    driver = None
    try:
        driver = webdriver.Chrome(service=Service(), options=chrome_options)
        driver.set_page_load_timeout(20)

        try:
            driver.get(url)
        except TimeoutException:
            print(f" TimeoutException — skipping: {url}")
            with open("skipped_timeout_urls.txt", "a") as f:
                f.write(url + "\n")
            return None, None, None

        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.TAG_NAME, "body")))
        scroll_height = driver.execute_script(
            "return document.body.scrollHeight")
        driver.set_window_size(1280, min(scroll_height, 2500))
        time.sleep(0.2)

        driver.save_screenshot(ss_path)
        page_html = driver.page_source

        with open(html_path, "w", encoding="utf-8") as f:
            f.write(page_html)

        print(f" Screenshot + HTML saved: {url}")
        return ss_path, html_path, page_html

    except Exception as e:
        print(f" Screenshot failed for {url}: {type(e).__name__}: {e}")
        return None, None, None

    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
        time.sleep(0.1)
        
def safe_screenshot_with_timeout(url, prefix="test", timeout=30):
    def _take():
        return take_screenshot(url, prefix=prefix)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_take)
            ss, html, _ = future.result(timeout=timeout)
            return ss, html
    except concurrent.futures.TimeoutError:
        print(f" Timeout exceeded → screenshot failed for: {url}")
        return None, None
    except Exception as e:
        print(
            f" Screenshot thread crashed for {url}: {type(e).__name__}: {e}")
        return None, None

def translate_safe(text, target="en", retries=1, delay=0.3):
    if not text:
        return text
    try:
        return GoogleTranslator(source='auto', target=target).translate(text)
    except Exception:
        # one lite retry, then give up silently
        if retries > 0:
            time.sleep(delay)
            try:
                return GoogleTranslator(source='auto', target=target).translate(text)
            except Exception:
                return text
        return text

def extract_from_visible_text(text, suspicious_keywords, config):
    leaks = []

    for raw in text.splitlines():
        line = raw.strip()
        if not line or len(line) < 5:
            continue

        lower_line = line.lower()

        for keyword in suspicious_keywords:
            if keyword in lower_line:

                # Try :, =, - split
                parts = None
                for splitter in [":", "=", "-"]:
                    if splitter in line:
                        parts = line.split(splitter, 1)
                        break

                # Extract value
                if parts and len(parts) >= 2:
                    val = parts[1].strip(' \t\n\r;,.')
                else:
                    toks = line.split()
                    if len(toks) >= 2:
                        val = toks[-1].strip(' \t\n\r;,.')
                    else:
                        continue

                # Filters
                if val.startswith("//"):
                    break

                if val.startswith(("http://", "https://")) and not looks_secretish(val):
                    break

                if keyword in {"order", "link"} and len(val) < max(16, config.get("min_val_length", 10)):
                    break

                if is_valid_leak_value(val, config):
                    leaks.append({
                        "type": keyword,
                        "value": val,
                        "source": "visible_text"
                    })
                break
    return leaks

URL_RE = re.compile(r'^https?://', re.I)
EXT_RE = re.compile(
    r'\.(html?|css|js|png|jpe?g|gif|svg|pdf|txt)(?:\?|#|$)', re.I)
PATH_RE = re.compile(r'^(/[A-Za-z0-9._%~-]+){2,}$')
UUID_RE = re.compile(
    r'\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b', re.I)
HEX_RE = re.compile(r'\b[0-9a-f]{24,}\b', re.I)
B64_RE = re.compile(r'^[A-Za-z0-9+/_-]{32,}={0,2}$')
JWT_RE = re.compile(
    r'^[A-Za-z0-9-_]{20,}\.[A-Za-z0-9-_]{20,}\.[A-Za-z0-9-_]{20,}$')

DENY_FIELDS = {
    'shareurl', 'returnurl', 'redirect', 'return_url', 'url', 'href', 'lang', 'locale', 'sort', 'page',
    'search', 'query', 'filter', 'q', 's', 'ref', 'referrer', 'source', 'utm', 'gclid', 'fbclid', 'input'
}

def is_denied_field(name: str) -> bool:
    if not name:
        return False
    n = name.lower()
    if n in DENY_FIELDS:
        return True
    # treat these as prefixes too (utm_*, input_*, ref_…)
    for p in ('utm', 'input', 'ref', 'return_url', 'gclid', 'fbclid'):
        if n.startswith(p) or n.startswith(p+'_'):
            return True
    return False

def shannon_bpc(s: str) -> float:
    from math import log2
    if not s:
        return 0.0
    L = len(s)
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    H = -sum((n/L) * log2(n/L) for n in freq.values())
    return H  

def looks_secretish(v: str, min_len: int = 16) -> bool:
    v = (v or '').strip()
    if len(v) < min_len or ' ' in v:
        return False
    if '@' in v and '.' in v.split('@')[-1]:
        return False  # email-like
    if JWT_RE.match(v) or UUID_RE.search(v) or HEX_RE.search(v) or B64_RE.match(v):
        return True
    digits = sum(c.isdigit() for c in v)
    letters = sum(c.isalpha() for c in v)
    if digits >= 6 and letters >= 6:
        return True
    return shannon_bpc(v) >= 3.5


def is_valid_leak_value(val: str, config: dict) -> bool:
    if not val:
        return False
    v = val.strip()
    if v.lower() in BAD_VALUES:
        return False

    # URL values: first check query for suspicious key + secretish value
    if URL_RE.match(v):
        u = urlsplit(v)
        q = dict(parse_qsl(u.query))

        if any(norm_key(k) in SUSPICIOUS_URL_PARAMS_SET for k in q) and \
           any(len(q[k]) >= 16 and looks_secretish(q[k])
               for k in q if norm_key(k) in SUSPICIOUS_URL_PARAMS_SET):
            return True

        # then reject obvious static/resource URLs by path/extension
        if EXT_RE.search(u.path or "") or PATH_RE.match(u.path or ""):
            return False

        # no qualifying query secrets → reject URL values
        return False

    # Non-URL values: drop obvious paths/files
    if EXT_RE.search(v) or PATH_RE.match(v):
        return False

    # Config gates
    min_len = config.get("min_val_length", 10)
    if len(v) < min_len:
        return False
    if config.get("require_digit") and not any(c.isdigit() for c in v):
        return False

    # Strong accept for long tokens; else shape check
    if len(v) >= 30 and ' ' not in v:
        return True
    return looks_secretish(v, min_len=max(16, min_len))


def load_page_source_only(url):
    global chrome_options, CHROMEDRIVER_PATH
    driver = None
    try:
        driver = webdriver.Chrome(service=Service(), options=chrome_options)
        driver.set_page_load_timeout(30)
        driver.get(url)
        WebDriverWait(driver, 35).until(
            EC.presence_of_element_located((By.TAG_NAME, "body")))
        time.sleep(0.5)
        html = driver.page_source
        return html
    except Exception as e:
        print(f" Failed to load page source for {url}: {e}")
        return None
    finally:
        if driver:
            try:
                driver.quit()
            except:
                pass


def extract_from_inputs(soup, suspicious_keywords, config):
    leaks = []

    PLACEHOLDER_JUNK = {
        "username", "password", "email", "admin", "test", "user", "login",
        "name@host.com", "e-mail", "123456", "email or phone",
        "phone number", "enter your name", "sign in", "submit"
    }

    for inp in soup.find_all(["input", "textarea"]):
        input_type = inp.get("type", "text").lower()
        if input_type in {"submit", "button", "checkbox", "radio", "file", "reset"}:
            continue

        name = (inp.get("name") or inp.get("id") or "").lower()
        value = (inp.get("value") or inp.get("placeholder") or "").strip()
        if inp.name == "textarea":
            value = inp.text.strip() or value
        if not value or value.lower() in PLACEHOLDER_JUNK:
            continue

        # === Match on keyword in field name
        matched_type = None
        for keyword in suspicious_keywords:
            if keyword in name:
                matched_type = keyword
                break

        # === If no keyword match, skip in aggressive mode
        if config.get("require_field_match") and not matched_type:
            continue
        if not matched_type:
            continue  # Skip if no real keyword match (force strictness)
        # name is already lowercased
        if is_denied_field(name):
            continue
        if config.get("require_field_match", True) and not any(kw in name for kw in suspicious_keywords):
            # optionally allow hidden fields:
            if input_type != 'hidden':
                continue

        # === Check value quality
        if is_valid_leak_value(value, config):
            leaks.append({
                "type": matched_type or "input_value",
                "value": value,
                "field": name,
                "source": "input"
            })
    return leaks

def extract_from_meta_and_data_attrs(soup, suspicious_keywords, config):
    leaks = []
# === 1. Extract from <meta> tags
    for meta in soup.find_all("meta"):
        name = meta.get("name", "") or meta.get("property", "")
        content = meta.get("content", "")
        if not content or len(content.strip()) < config.get("min_val_length", 10):
            continue

    # Lowercase for comparison
        content_lower = content.strip().lower()

    # Skip junk values
        if content_lower in JUNK_VALUES:
            continue

        for keyword in suspicious_keywords:
            if keyword.lower() in name.lower():
                if is_valid_leak_value(content, config):
                    leaks.append({
                        "type": keyword,
                        "value": content.strip(),
                        "field": name,
                        "source": "meta"
                    })

    # === 2. Extract from data-* attributes
    for tag in soup.find_all(True):
        for attr, val in tag.attrs.items():
            if attr.startswith("data-") and isinstance(val, str):
                for keyword in suspicious_keywords:
                    if keyword.lower() in attr.lower():
                        if is_valid_leak_value(val, config):
                            leaks.append({
                                "type": keyword,
                                "value": val.strip(),
                                "field": attr,
                                "source": "data-attribute"
                            })

    return leaks


def extract_from_js_variables(soup, suspicious_keywords, config):
    leaks = []

    # Grab all <script> tags that are inline (no src)
    for script in soup.find_all("script"):
        if script.has_attr("src") or not script.string:
            continue

        js_code = script.string

        # Match patterns like: let/var/const keyword = "value";
        pattern = r"\b([a-zA-Z0-9_\-$]+)\s*[:=]\s*['\"]([^'\"]{4,})['\"]"
        matches = re.findall(pattern, js_code)

        for var_name, var_value in matches:
            var_name_lower = var_name.lower()
            var_value_clean = var_value.strip()

            # Match if var name OR value contains a suspicious keyword
            for keyword in suspicious_keywords:
                keyword_lower = keyword.lower()
                if (keyword_lower in var_name_lower):
                    if is_valid_leak_value(var_value_clean, config):
                        leaks.append({
                            "type": keyword,
                            "value": var_value_clean,
                            "field": var_name,
                            "source": "js-var"
                        })

    return leaks


def extract_from_screenshot_text(ss_path, suspicious_keywords, config):
    leaks = []

    try:
        image = Image.open(ss_path)
        text = pytesseract.image_to_string(image).lower()
        print(" OCR text extracted from screenshot.")

        leaks_ocr = extract_from_visible_text(
            text, suspicious_keywords, config)
        leaks.extend(leaks_ocr)

    except Exception as e:
        print(f" OCR failed for {ss_path}: {e}")

    return leaks


def deduplicate_leaks(leak_list):
    seen = set()
    unique_leaks = []
    for leak in leak_list:
        key = f"{leak['type']}:{leak['value']}"
        if key not in seen:
            seen.add(key)
            unique_leaks.append(leak)
    return unique_leaks


def _safe_json_loads(s):
    try:
        return json.loads(s)
    except Exception:
        return None

def normalize_request_index(events):
    reqs = {}
    for ev in events:
        m = ev["method"]
        p = ev["params"]
        if m == "Network.requestWillBeSent":
            r = p.get("request", {})
            rid = p.get("requestId")
            if not rid:
                continue
            reqs.setdefault(rid, {}).update({
                "url": r.get("url"),
                "method": r.get("method"),
                "headers": r.get("headers", {}),
                "postData": r.get("postData", None),  # may be absent
                "ts": p.get("timestamp"),
                "type": p.get("type"),  # ResourceType
            })
        elif m == "Network.responseReceived":
            rid = p.get("requestId")
            if not rid or rid not in reqs:
                continue
            resp = p.get("response", {})
            reqs[rid].update({
                "status": resp.get("status"),
                "resp_headers": resp.get("headers", {}),
                "mime": resp.get("mimeType"),
            })
    
    return [v for v in reqs.values() if v.get("url")]

def process_ocr_leaks(url, prefix, leak_type="ocr"):
    ss_path, html_path, _ = take_screenshot(
        url, prefix=prefix,
        screenshot_dir=OCR_SCREENSHOT_FOLDER,
        html_dir=OCR_HTML_FOLDER
    )
    if not ss_path:
        print(" No screenshot available for OCR.")
        return

    with stats_lock:
        stats["ocr_ss"] += 1

    # 1) OCR text → leaks
    leaks_ocr = extract_from_screenshot_text(
        ss_path, SUSPICIOUS_PARAMS_SET, INCLUSIVE_CONFIG
    )
    unique_ocr_leaks = deduplicate_leaks(leaks_ocr)

    if unique_ocr_leaks:
        with stats_lock:
            stats["ocr_leaks"] += 1
        print(" OCR-based leaks found:")
        for leak in unique_ocr_leaks:
            print(
                f"  - {leak['type']}: {leak['value']} (source: screenshot_ocr)")

        dest_ss = os.path.join(SCREENSHOT_FOLDER, os.path.basename(ss_path))
        dest_html = os.path.join(HTML_FOLDER, os.path.basename(html_path))
        if ss_path != dest_ss:
            shutil.copy(ss_path, dest_ss)
        if html_path != dest_html:
            shutil.copy(html_path, dest_html)

        _, _, matched_pairs = format_leaks(unique_ocr_leaks)
        print(" Saving OCR result to DB for:", url)
        save_result_to_db({
            "url": url,
            "status": "Live",
            "matched_url": matched_pairs,
            "matched_html": matched_pairs,
            "screenshot_path": dest_ss,
            "html_path": dest_html,
            "type": leak_type
        })
        print(" Saved to DB.")
    else:
        print(" No leaks found after OCR.")
        try:
            os.remove(ss_path)
            os.remove(html_path)
        except Exception as e:
            print(f" Cleanup error: {e}")
            
def save_result_to_db(res):
    try:
        conn = sqlite3.connect(RESULTS_DB)
        c = conn.cursor()

        c.execute(
            "INSERT INTO leaks (url, status, matched_url, matched_html, screenshot_path, html_path) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                res["url"],
                res["status"],
                res["matched_url"],
                res["matched_html"],
                res["screenshot_path"],
                res["html_path"],
            )
        )

        conn.commit()
        conn.close()
        print(f"Saved to DB: {res['url']}")

    except Exception as e:
        print(f"DB insert failed for {res['url']}: {e}")


def format_leaks(leak_list, max_len=200):
    def _clean(v):
        v = (v or "").replace("\n", " ").replace("\r", " ").strip()
        return (v[:max_len] + "…") if len(v) > max_len else v
    types = "; ".join(_clean(l["type"]) for l in leak_list)
    values = "; ".join(_clean(l["value"]) for l in leak_list)
    pairs = "; ".join(
        f"{_clean(l['type'])}:{_clean(l['value'])}" for l in leak_list)
    return types, values, pairs


def etld1(host):
    parts = (host or "").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


LEAK_PATTERNS = {
    "email": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
    "credit_card": re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"),
    "phone": re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b"),
    "id_like": re.compile(r"\b\d{9,}\b"),
    "api_secret": re.compile(r"\b(?:api[_-]?key|secret|password|pwd|token|bearer)\b[:=]?[ \t]*[A-Za-z0-9._\-]{8,}", re.I),
    "jwt": JWT_RE,
    "base64": B64_RE,
}


def worker_single_url(entry):
    try:
        url = entry["url"]
        matched_url = entry.get("matched_url", "")
        url_queue.put(entry)     # enqueue the single URL
        url_queue.put(None)      # enqueue sentinel so worker stops
        worker()                 # run worker loop once
    except Exception as e:
        print(f"worker_single_url error for {entry.get('url')}: {e}")

def worker():
    while True:
        entry = None
        try:
            entry = url_queue.get(timeout=35)
            if entry is None:
                # sentinel to stop the worker
                return

            url = entry["url"]
            matched_url = entry.get("matched_url", "")

            # --- Special domain fast-path: just screenshot + HTML, then save ---

            domain_type = check_special_domain(url)
            if domain_type:
                print(
                    f"Matched special domain ({domain_type}) → capture SS + HTML only.")
                try:
                    ss_path, html_path = safe_screenshot_with_timeout(
                        url, prefix=domain_type, timeout=35)
                    if ss_path and os.path.exists(ss_path):
                        with stats_lock:
                            stats["regular_ss"] += 1
                except Exception as e:
                    print(f" Failed SS/HTML capture for special domain: {e}")
                    ss_path, html_path = "N/A", "N/A"

                save_result_to_db({
                    "url": url,
                    "status": "Live",
                    "matched_url": f"{domain_type} domain matched",
                    "matched_html": "",         
                    "screenshot_path": ss_path or "N/A",
                    "html_path": html_path or "N/A",
                    "type": domain_type
                })
                with stats_lock:
                    stats[f"{domain_type}_live"] += 1
                continue 

            with stats_lock:
                stats["processed"] += 1

            print(f"\n Checking URL: {url}")
            try:
                with open("scanned_urls.log", "a") as logf:
                    logf.write(url + "\n")
            except Exception as e:
                print(f" Failed to write log: {e}")
            # --- PDFs: just screenshot + HTML, then save (no parsing) ---
            if url.lower().endswith(".pdf"):
                try:
                    print("Detected PDF URL — capture SS + HTML only.")

                    # 1) Download PDF
                    try:
                        os.makedirs(PDF_FOLDER, exist_ok=True)
                        pdf_path = os.path.join(
                            PDF_FOLDER, f"pdf_{int(time.time()*1000)}.pdf")
                        pdf_resp = requests.get(url, timeout=30)
                        ctype = pdf_resp.headers.get(
                            "content-type", "").lower()
                        if pdf_resp.status_code == 200 and ctype.startswith("application/pdf"):
                            with open(pdf_path, "wb") as f:
                                f.write(pdf_resp.content)
                            print(f"Saved PDF bytes: {pdf_path}")
                        else:
                            print(
                                f"PDF fetch failed (status {pdf_resp.status_code}); proceeding with SS/HTML.")
                            pdf_path = None
                    except Exception as e:
                        print(f"PDF download failed for {url}: {e}")
                        pdf_path = None

                    # 2) Screenshot + HTML
                    try:
                        ss_path, html_path = safe_screenshot_with_timeout(
                            url, prefix="pdf", timeout=35)
                        if ss_path and os.path.exists(ss_path):
                            with stats_lock:
                                stats["regular_ss"] += 1
                    except Exception as e:
                        print(f"PDF SS/HTML capture failed: {e}")
                        ss_path, html_path = "N/A", "N/A"

                    # 3) Always log the capture row
                    save_result_to_db({
                        "url": url,
                        "status": "Live",
                        "matched_url": (matched_url or ""),
                        "matched_html": "",   # no HTML parsing here
                        "screenshot_path": ss_path or "N/A",
                        "html_path": html_path or "N/A",
                        "type": "pdf_capture"
                    })
                except Exception as e:
                    print(f"Error while handling PDF: {e}")
                continue

            # === Live check ===
            try:
                live, _ = is_url_live(url)
            except Exception as e:
                print(f" Live check failed: {e}")
                continue

            if not live:
                print(" Dead or blocked page.")
                with stats_lock:
                    stats["dead"] += 1
                continue

            with stats_lock:
                stats["live"] += 1

            # === Render page with Selenium ===
            driver = None
            leaks_dynamic_inputs = [] 

            try:
                driver = webdriver.Chrome(
                    service=Service(), options=chrome_options)
                driver.set_page_load_timeout(45)

                try:
                    driver.execute_cdp_cmd("Network.enable", {
                        "maxTotalBufferSize": 10000000,
                        "maxResourceBufferSize": 5000000
                    })
                    driver.execute_cdp_cmd("Page.enable", {})
                except Exception:
                    pass

                driver.get(url)

                WebDriverWait(driver, 12).until(
                    lambda d: d.execute_script(
                        "return document.readyState") == "complete"
                )

                time.sleep(0.3)
                html = driver.page_source
                soup = BeautifulSoup(html, "html.parser")
                time.sleep(0.4)

                # === Extract dynamic input fields ===
                try:
                    leaks_dynamic_inputs = extract_dynamic_inputs(
                        driver, SUSPICIOUS_PARAMS_SET, INCLUSIVE_CONFIG
                    )
                except Exception as e:
                    print(f"Failed to extract dynamic inputs: {e}")
                    leaks_dynamic_inputs = []

            except Exception as e:
                print(f"Selenium rendering failed for {url}: {e}")

            # === Visible text extraction and translation ===
            try:
                visible_text = soup.get_text(separator="\n")
                if visible_text.strip():
                    short_text = visible_text[:INCLUSIVE_CONFIG["max_translate_chars"]]

                    try:
                        lang = detect(short_text)
                    except Exception:
                        lang = "en"  # default quietly

                    should_translate = (
                        INCLUSIVE_CONFIG.get("enable_translation", True)
                        and lang != "en"
                        and lang.lower() in INCLUSIVE_CONFIG.get("translate_langs", set())
                    )

                    if should_translate:
                        # no spammy prints; do it quietly
                        translated = translate_safe(short_text, target="en")
                        visible_text = translated if translated else short_text
                    else:
                        visible_text = short_text
                else:
                    visible_text = ""
            except Exception:
                visible_text = ""

            # === Leak extraction from multiple layers ===
            try:
                leaks_visible = extract_from_visible_text(
                    visible_text, SUSPICIOUS_PARAMS_SET, INCLUSIVE_CONFIG
                )
            except Exception as e:
                print(f" Error extracting visible leaks: {e}")
                leaks_visible = []

            try:
                leaks_input = extract_from_inputs(
                    soup, SUSPICIOUS_PARAMS_SET, INCLUSIVE_CONFIG
                )
            except Exception as e:
                print(f" Error extracting input leaks: {e}")
                leaks_input = []

            try:
                leaks_meta = extract_from_meta_and_data_attrs(
                    soup, SUSPICIOUS_PARAMS_SET, INCLUSIVE_CONFIG
                )
            except Exception as e:
                print(f" Error extracting meta leaks: {e}")
                leaks_meta = []

            try:
                leaks_js = extract_from_js_variables(
                    soup, SUSPICIOUS_PARAMS_SET, INCLUSIVE_CONFIG
                )
            except Exception as e:
                print(f" Error extracting JS leaks: {e}")
                leaks_js = []

            all_leaks = deduplicate_leaks(
                leaks_visible + leaks_input + leaks_meta +
                leaks_js + leaks_dynamic_inputs
            )

            if not all_leaks:
                print(" No leaks found in Layers 1–5. Applying OCR fallback...")
                try:
                    process_ocr_leaks(url, prefix="ocr", leak_type="ocr")
                except Exception as e:
                    print(f" OCR fallback failed: {e}")
                continue

            # === Final result logging ===
            print(" Leaks found:")
            for leak in all_leaks:
                print(
                    f"  - {leak['type']}: {leak['value']} (source: {leak['source']})")

            ss_path, html_path = safe_screenshot_with_timeout(
                url, prefix="leak", timeout=35)
            if ss_path and os.path.exists(ss_path):
                with stats_lock:
                    stats["regular_ss"] += 1
            else:
                print(" Screenshot path missing or invalid — skipping OCR.")

            matched_types, matched_values, matched_pairs = format_leaks(
                all_leaks)
            save_result_to_db({
                "url": url,
                "status": "Live",
                "matched_url": matched_pairs,
                "matched_html": matched_pairs,
                "screenshot_path": ss_path or "N/A",
                "html_path": html_path or "N/A",
                "type": "regular"
            })

        except Exception as e:
            # Optional top-level protection per URL
            print(f" Top-level worker error: {e}")

        finally:
            # Always mark the URL as done if we dequeued it
            if entry is not None:
                try:
                    url_queue.task_done()
                except Exception:
                    pass


def main():
    global url_queue
    init_results_db()
    start_time = time.time()

    folder = ""

    db_files = [
        os.path.join(folder, f)
        for f in os.listdir(folder)
        if f.endswith(".db")
    ]

    all_urls = []
    for db_path in db_files:
        print(f"Loading from: {db_path}")
        urls = load_urls_from_db(db_path, "urls", "urls")
        all_urls.extend(urls)

    test_urls = all_urls

    if not test_urls:
        print("No URLs loaded. Aborting.")
        return

    total_loaded = len(test_urls)
    print(f" Loaded {total_loaded} URLs from DB (before filtering)\n")

    # --- Print the first 100 URLs being scanned ---
    print(" First URLs being scanned:")
    for i, u in enumerate(test_urls[:100], 1):
        print(f"{i:03d}. {u}")
    print("------------------------------------------------------------")

    # random.shuffle(test_urls)  # disabled to keep DB order
    with stats_lock:
        stats["total_input_urls"] = total_loaded

    # === First filter ===
    filtered_urls = filter_useful_urls(test_urls)
    total_filtered = len(filtered_urls)
    print(f"\n URLs after 1st filter = {total_filtered}")

    if not filtered_urls:
        print(" No URLs passed the filter. Exiting early.")
        return

    with stats_lock:
        stats["passed_filtering"] = total_filtered

    # === Prepare the queue with filtered URLs ===
    for url in filtered_urls:
        url_queue.put(url)
    for _ in range(NUM_THREADS):
        url_queue.put(None)

    # === ThreadPoolExecutor for controlled parallelism ===
    print(f"\n Starting thread pool with {NUM_THREADS} threads...")
    with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
        for _ in range(NUM_THREADS):
            executor.submit(worker)

    duration = time.time() - start_time

    # === Final report ===
    print("\n Final Stats:")
    print(f"   URLs loaded initially: {total_loaded}")
    print(f"   URLs after filtering: {total_filtered}")
    print(f"   Total URLs processed: {stats['processed']}")
    print(f"   Live URLs: {stats['live']}")
    print(f"   Dead URLs: {stats['dead']}")
    print(f"   Regular screenshots taken: {stats['regular_ss']}")
    print(f"   OCR screenshots taken: {stats['ocr_ss']}")
    print(f"   OCR-based leaks found: {stats['ocr_leaks']}")
    print(f"   Photo domain URLs matched: {stats['photo_live']}")
    print(f"   E-sign domain URLs matched: {stats['esign_total']}")
    print(f"   Paste domain URLs matched: {stats['paste_total']}")
    print(f"   Non-English pages translated: {stats['non_english']}")
    print(f"   HTTP-layer leaks found: {stats['http_leaks']}")
    print(f"   Time taken: {round(duration, 2)} seconds")
    print("-----> All results written to DB.")


if __name__ == "__main__":
    main()
