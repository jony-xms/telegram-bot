"""
╔══════════════════════════════════════════════════════════════╗
║            MalwareGuard PRO v3.2 — Telegram Bot             ║
║                                                              ║
║  Barcha xususiyatlar bitta faylda:                           ║
║  ✅ Fayl tahlili  — Shannon entropiya, PE, YARA, API scan   ║
║  ✅ URL tahlili   — 7 qatlam (DNS, WHOIS, SSL, typosquat)   ║
║  ✅ Hash tekshir  — MD5 / SHA1 / SHA256                     ║
║  ✅ VirusTotal    — fayl, hash, URL                         ║
║  ✅ URLScan.io    — screenshot + verdict                    ║
║  ✅ Google Safe Browsing                                     ║
║  ✅ SQLite DB     — tahlil tarixi, foydalanuvchilar         ║
║  ✅ Rate limiter  — spam himoyasi                           ║
║  ✅ Admin panel   — statistika, ban/unban                   ║
║  ✅ Ko'p til      — O'zbek / Русский / English              ║
║  ✅ Ogohlantiruv  — zararli fayl banneri + kanal havolasi   ║
║  ✅ Double ext    — ikki kengaytma aniqlash                 ║
║  ✅ APK/mobil     — Android zararli fayl aniqlash           ║
║                                                              ║
║  O'rnatish:                                                  ║
║    pip install aiogram aiohttp python-dotenv                 ║
║               dnspython python-whois yara-python            ║
║                                                              ║
║  .env fayli:                                                 ║
║    BOT_TOKEN=...                                             ║
║    VT_API_KEY=...                                            ║
║    URLSCAN_API_KEY=...                                       ║
║    GSB_API_KEY=...                                           ║
║    ADMIN_IDS=123456,789012                                   ║
║    GUIDE_URL=https://t.me/Malwarebot_news/4                 ║
╚══════════════════════════════════════════════════════════════╝
"""

# ───────────────────────────────────────────────────────────
#  IMPORT
# ───────────────────────────────────────────────────────────
import asyncio
import logging
import math
import hashlib
import struct
import re
import os
import sqlite3
import time
import base64
import ssl
import socket
import ipaddress
import io
from collections import Counter, defaultdict
from datetime import datetime, timezone
from difflib import SequenceMatcher
from functools import wraps
from urllib.parse import urlparse, quote

import aiohttp
import dns.resolver
import dns.exception
import whois as whois_lib
from dotenv import load_dotenv

from aiogram import Bot, Dispatcher, Router, F
from aiogram.enums import ParseMode
from aiogram.client.default import DefaultBotProperties
from aiogram.filters import CommandStart, Command
from aiogram.types import (
    Message, CallbackQuery,
    InlineKeyboardMarkup, InlineKeyboardButton,
    ReplyKeyboardMarkup, KeyboardButton,
)
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.utils.keyboard import InlineKeyboardBuilder

try:
    import yara
    YARA_OK = True
except ImportError:
    YARA_OK = False

# ───────────────────────────────────────────────────────────
#  CONFIG
# ───────────────────────────────────────────────────────────
load_dotenv()

BOT_TOKEN    = os.getenv("BOT_TOKEN", "")
VT_API_KEY   = os.getenv("VT_API_KEY", "")
URLSCAN_KEY  = os.getenv("URLSCAN_API_KEY", "")
GSB_KEY      = os.getenv("GSB_API_KEY", "")
ADMIN_IDS    = [int(x) for x in os.getenv("ADMIN_IDS", "").split(",") if x.strip().isdigit()]
DB_PATH      = os.getenv("DB_PATH", "malwareguard.db")
GUIDE_URL    = os.getenv("GUIDE_URL", "https://t.me/Malwarebot_news/4")

MAX_FILE_MB    = 20
MAX_FILE_BYTES = MAX_FILE_MB * 1024 * 1024
RATE_LIMIT_MAX = 5
DNS_TIMEOUT    = 5.0
HTTP_TO        = aiohttp.ClientTimeout(total=15)
VT_TIMEOUT     = aiohttp.ClientTimeout(total=20)
VT_POLL_WAIT   = 5
VT_POLL_MAX    = 8

if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN .env faylida topilmadi!")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
log = logging.getLogger("MGPro")

# ───────────────────────────────────────────────────────────
#  TARJIMALAR
# ───────────────────────────────────────────────────────────
LANGS = {
    "uz": {
        # Knopkalar
        "btn_scanner":    "🦠 Virus Scanner",
        "btn_profile":    "📊 Profil",
        "btn_about":      "ℹ️ Haqida",
        "btn_file":       "📄 Fayl",
        "btn_hash":       "🔑 Hash",
        "btn_url":        "🔗 URL",
        "btn_back":       "🔙 Orqaga",
        # Umumiy
        "lang_changed":   "✅ Til o'zgartirildi: O'zbek 🇺🇿",
        "choose_lang":    "🌐 Tilni tanlang:",
        "scanner_menu":   "🦠 <b>Virus Scanner</b>\n\nNimani tekshirmoqchisiz?",
        "back_main":      "⬅️ Asosiy menyu",
        "banned":         "🚫 Siz bloklangansiz.",
        "rate_limit":     "⏳ Juda tez! <b>{wait} sek</b> kuting.\n(60 sek ichida max {max} so'rov)",
        "send_file":      "📄 Faylni yuboring (max {mb} MB):",
        "send_hash":      "🔑 MD5, SHA1 yoki SHA256 hash yuboring:",
        "send_url":       "🔗 URL yuboring (https:// bilan):",
        "hash_hex_err":   "❌ Hash faqat hex belgilar (0–9, a–f).",
        "hash_len_err":   "❌ Uzunlik: {n}. MD5=32, SHA1=40, SHA256=64.",
        "url_scheme_err": "❌ URL http:// yoki https:// bilan boshlanishi kerak.",
        "url_long_err":   "❌ URL juda uzun (max 2048).",
        "file_big_err":   "❌ Fayl juda katta! Max: {mb} MB, sizniki: {size}",
        "vt_searching":   "⏳ VT bazasida qidirilmoqda...",
        "url_analyzing":  "🔬 <b>URL tahlil boshlanmoqda...</b>\n\n⏳ DNS, WHOIS, SSL...\n🛡 VT, GSB, URLScan...\n<i>20–40 sekund davom etishi mumkin</i>",
        "file_analyzing": "🔬 <b>Tahlil boshlanmoqda...</b>\n\n⏳ Heshlar...\n🧬 Heuristik + YARA...\n🌐 VirusTotal...",
        "file_heuristic": "🔬 <b>Heuristik tugadi...</b>\n\n✅ YARA skaneri\n✅ Entropiya\n🌐 VirusTotal kutilmoqda...",
        "error":          "❌ Xato: <code>{err}</code>",
        "url_detected":   "🔗 URL aniqlandi...\n<code>{url}</code>",
        "admin_cmd":      "🚫 Admin buyrug'i.",
        "no_perm":        "Ruxsat yo'q!",
        "ban_ask":        "🚫 Ban qilinadigan foydalanuvchi ID:",
        "unban_ask":      "✅ Unban qilinadigan foydalanuvchi ID:",
        "banned_ok":      "🚫 <code>{uid}</code> bloklandi.",
        "unbanned_ok":    "✅ <code>{uid}</code> blokdan chiqarildi.",
        "id_err":         "❌ ID raqam bo'lishi kerak.",
        "no_scans":       "📋 Hali scan yo'q.",
        # Hisobot
        "verdict_malicious":  "ZARARLI",
        "verdict_suspicious": "SHUBHALI",
        "verdict_clean":      "XAVFSIZ",
        "file_report_title":  "FAYL TAHLILI",
        "url_report_title":   "URL TAHLILI",
        "hash_report_title":  "Hash Tekshiruvi",
        "warn_malicious":     "⛔️ <b>Ogoh bo'ling!</b> Bu fayl zararli fayl deb topildi!\n🗑 <b>Izoh:</b> Faylni darhol o'chirib tashlang!\n📖 <b>Qo'llanma:</b> {url}",
        "warn_suspicious":    "⚠️ <b>Ehtiyot bo'ling!</b> Bu fayl shubhali deb topildi!\n🗑 <b>Tavsiya:</b> Faylni o'chirib tashlang!\n📖 <b>Qo'llanma:</b> {url}",
        "warn_url_mal":       "⛔️ <b>Ogoh bo'ling!</b> Bu URL xavfli deb topildi!\n📖 <b>Qo'llanma:</b> {url}",
        "warn_url_sus":       "⚠️ <b>Ehtiyot bo'ling!</b> Bu URL shubhali!\n📖 <b>Qo'llanma:</b> {url}",
        "guide_btn":          "📖 Qo'llanma — Virusni o'chirish",
        "guide_url_btn":      "📖 Qo'llanma — Xavfsiz bo'lish",
        "vt_btn":             "🌐 VT da ko'rish",
        "no_problem":         "✅ Muammo topilmadi",
    },
    "ru": {
        "btn_scanner":    "🦠 Сканер вирусов",
        "btn_profile":    "📊 Профиль",
        "btn_about":      "ℹ️ О боте",
        "btn_file":       "📄 Файл",
        "btn_hash":       "🔑 Хэш",
        "btn_url":        "🔗 URL",
        "btn_back":       "🔙 Назад",
        "lang_changed":   "✅ Язык изменён: Русский 🇷🇺",
        "choose_lang":    "🌐 Выберите язык:",
        "scanner_menu":   "🦠 <b>Сканер вирусов</b>\n\nЧто хотите проверить?",
        "back_main":      "⬅️ Главное меню",
        "banned":         "🚫 Вы заблокированы.",
        "rate_limit":     "⏳ Слишком быстро! Подождите <b>{wait} сек</b>.\n(Макс {max} запросов за 60 сек)",
        "send_file":      "📄 Отправьте файл (макс {mb} МБ):",
        "send_hash":      "🔑 Отправьте MD5, SHA1 или SHA256 хэш:",
        "send_url":       "🔗 Отправьте URL (с https://):",
        "hash_hex_err":   "❌ Хэш должен содержать только hex символы (0–9, a–f).",
        "hash_len_err":   "❌ Длина: {n}. MD5=32, SHA1=40, SHA256=64.",
        "url_scheme_err": "❌ URL должен начинаться с http:// или https://",
        "url_long_err":   "❌ URL слишком длинный (макс 2048).",
        "file_big_err":   "❌ Файл слишком большой! Макс: {mb} МБ, ваш: {size}",
        "vt_searching":   "⏳ Поиск в базе VT...",
        "url_analyzing":  "🔬 <b>Анализ URL начинается...</b>\n\n⏳ DNS, WHOIS, SSL...\n🛡 VT, GSB, URLScan...\n<i>Может занять 20–40 секунд</i>",
        "file_analyzing": "🔬 <b>Анализ начинается...</b>\n\n⏳ Хэши...\n🧬 Эвристика + YARA...\n🌐 VirusTotal...",
        "file_heuristic": "🔬 <b>Эвристика завершена...</b>\n\n✅ YARA сканер\n✅ Энтропия\n🌐 Ожидание VirusTotal...",
        "error":          "❌ Ошибка: <code>{err}</code>",
        "url_detected":   "🔗 URL обнаружен...\n<code>{url}</code>",
        "admin_cmd":      "🚫 Команда администратора.",
        "no_perm":        "Нет доступа!",
        "ban_ask":        "🚫 ID пользователя для блокировки:",
        "unban_ask":      "✅ ID пользователя для разблокировки:",
        "banned_ok":      "🚫 <code>{uid}</code> заблокирован.",
        "unbanned_ok":    "✅ <code>{uid}</code> разблокирован.",
        "id_err":         "❌ ID должен быть числом.",
        "no_scans":       "📋 Сканирований ещё не было.",
        "verdict_malicious":  "ВРЕДОНОСНЫЙ",
        "verdict_suspicious": "ПОДОЗРИТЕЛЬНЫЙ",
        "verdict_clean":      "БЕЗОПАСНЫЙ",
        "file_report_title":  "АНАЛИЗ ФАЙЛА",
        "url_report_title":   "АНАЛИЗ URL",
        "hash_report_title":  "Проверка Хэша",
        "warn_malicious":     "⛔️ <b>Осторожно!</b> Файл признан вредоносным!\n🗑 <b>Примечание:</b> Немедленно удалите файл!\n📖 <b>Инструкция:</b> {url}",
        "warn_suspicious":    "⚠️ <b>Будьте осторожны!</b> Файл подозрительный!\n🗑 <b>Рекомендация:</b> Удалите файл!\n📖 <b>Инструкция:</b> {url}",
        "warn_url_mal":       "⛔️ <b>Осторожно!</b> Этот URL опасен!\n📖 <b>Инструкция:</b> {url}",
        "warn_url_sus":       "⚠️ <b>Будьте осторожны!</b> URL подозрительный!\n📖 <b>Инструкция:</b> {url}",
        "guide_btn":          "📖 Инструкция — Удаление вируса",
        "guide_url_btn":      "📖 Инструкция — Как защититься",
        "vt_btn":             "🌐 Смотреть на VT",
        "no_problem":         "✅ Проблем не обнаружено",
    },
    "en": {
        "btn_scanner":    "🦠 Virus Scanner",
        "btn_profile":    "📊 Profile",
        "btn_about":      "ℹ️ About",
        "btn_file":       "📄 File",
        "btn_hash":       "🔑 Hash",
        "btn_url":        "🔗 URL",
        "btn_back":       "🔙 Back",
        "lang_changed":   "✅ Language changed: English 🇬🇧",
        "choose_lang":    "🌐 Choose language:",
        "scanner_menu":   "🦠 <b>Virus Scanner</b>\n\nWhat would you like to check?",
        "back_main":      "⬅️ Main menu",
        "banned":         "🚫 You are banned.",
        "rate_limit":     "⏳ Too fast! Wait <b>{wait} sec</b>.\n(Max {max} requests per 60 sec)",
        "send_file":      "📄 Send a file (max {mb} MB):",
        "send_hash":      "🔑 Send MD5, SHA1 or SHA256 hash:",
        "send_url":       "🔗 Send URL (with https://):",
        "hash_hex_err":   "❌ Hash must contain only hex characters (0–9, a–f).",
        "hash_len_err":   "❌ Length: {n}. MD5=32, SHA1=40, SHA256=64.",
        "url_scheme_err": "❌ URL must start with http:// or https://",
        "url_long_err":   "❌ URL is too long (max 2048).",
        "file_big_err":   "❌ File too large! Max: {mb} MB, yours: {size}",
        "vt_searching":   "⏳ Searching in VT database...",
        "url_analyzing":  "🔬 <b>URL analysis starting...</b>\n\n⏳ DNS, WHOIS, SSL...\n🛡 VT, GSB, URLScan...\n<i>May take 20–40 seconds</i>",
        "file_analyzing": "🔬 <b>Analysis starting...</b>\n\n⏳ Hashes...\n🧬 Heuristic + YARA...\n🌐 VirusTotal...",
        "file_heuristic": "🔬 <b>Heuristic done...</b>\n\n✅ YARA scanner\n✅ Entropy\n🌐 Waiting for VirusTotal...",
        "error":          "❌ Error: <code>{err}</code>",
        "url_detected":   "🔗 URL detected...\n<code>{url}</code>",
        "admin_cmd":      "🚫 Admin command.",
        "no_perm":        "No permission!",
        "ban_ask":        "🚫 Enter user ID to ban:",
        "unban_ask":      "✅ Enter user ID to unban:",
        "banned_ok":      "🚫 <code>{uid}</code> has been banned.",
        "unbanned_ok":    "✅ <code>{uid}</code> has been unbanned.",
        "id_err":         "❌ ID must be a number.",
        "no_scans":       "📋 No scans yet.",
        "verdict_malicious":  "MALICIOUS",
        "verdict_suspicious": "SUSPICIOUS",
        "verdict_clean":      "CLEAN",
        "file_report_title":  "FILE ANALYSIS",
        "url_report_title":   "URL ANALYSIS",
        "hash_report_title":  "Hash Check",
        "warn_malicious":     "⛔️ <b>Warning!</b> This file is malicious!\n🗑 <b>Note:</b> Delete the file immediately!\n📖 <b>Guide:</b> {url}",
        "warn_suspicious":    "⚠️ <b>Be careful!</b> This file is suspicious!\n🗑 <b>Advice:</b> Delete the file!\n📖 <b>Guide:</b> {url}",
        "warn_url_mal":       "⛔️ <b>Warning!</b> This URL is dangerous!\n📖 <b>Guide:</b> {url}",
        "warn_url_sus":       "⚠️ <b>Be careful!</b> This URL is suspicious!\n📖 <b>Guide:</b> {url}",
        "guide_btn":          "📖 Guide — Remove Virus",
        "guide_url_btn":      "📖 Guide — Stay Safe",
        "vt_btn":             "🌐 View on VT",
        "no_problem":         "✅ No issues found",
    },
}

# Barcha knopka matnlari (filter uchun)
ALL_SCANNER_BTNS = {v["btn_scanner"] for v in LANGS.values()}
ALL_PROFILE_BTNS = {v["btn_profile"] for v in LANGS.values()}
ALL_ABOUT_BTNS   = {v["btn_about"]   for v in LANGS.values()}
ALL_FILE_BTNS    = {v["btn_file"]    for v in LANGS.values()}
ALL_HASH_BTNS    = {v["btn_hash"]    for v in LANGS.values()}
ALL_URL_BTNS     = {v["btn_url"]     for v in LANGS.values()}
ALL_BACK_BTNS    = {v["btn_back"]    for v in LANGS.values()}

def tr(uid: int, key: str, **kwargs) -> str:
    """Foydalanuvchi tiliga mos matnni qaytaradi."""
    lang = db_get_lang(uid)
    text = LANGS.get(lang, LANGS["uz"]).get(key, LANGS["uz"].get(key, key))
    if kwargs:
        try:
            text = text.format(**kwargs)
        except Exception:
            pass
    return text

# ───────────────────────────────────────────────────────────
#  DATABASE
# ───────────────────────────────────────────────────────────
def _db() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c

def db_init():
    c = _db()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY,
            username   TEXT,
            first_name TEXT,
            lang       TEXT DEFAULT 'uz',
            joined_at  TEXT DEFAULT (datetime('now')),
            is_banned  INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS scans (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL,
            scan_type    TEXT NOT NULL,
            target       TEXT,
            verdict      TEXT,
            score        INTEGER DEFAULT 0,
            entropy      REAL    DEFAULT 0,
            sha256       TEXT,
            vt_malicious INTEGER DEFAULT 0,
            vt_total     INTEGER DEFAULT 0,
            created_at   TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id);
    """)
    # Migration: eski DB da lang ustuni bo'lmasa qo'shamiz
    try:
        c.execute("ALTER TABLE users ADD COLUMN lang TEXT DEFAULT 'uz'")
        c.commit()
        log.info("✅ DB migration: lang ustuni qo'shildi")
    except Exception:
        pass  # Ustun allaqachon bor — e'tibor bermaylik
    c.commit()
    c.close()
    log.info("✅ DB: %s", DB_PATH)

def db_upsert_user(uid, username, first_name):
    c = _db()
    c.execute(
        "INSERT INTO users(id,username,first_name) VALUES(?,?,?) "
        "ON CONFLICT(id) DO UPDATE SET username=excluded.username,"
        "first_name=excluded.first_name",
        (uid, username or "", first_name or "")
    )
    c.commit()
    c.close()

def db_get_lang(uid: int) -> str:
    c = _db()
    row = c.execute("SELECT lang FROM users WHERE id=?", (uid,)).fetchone()
    c.close()
    return row["lang"] if row and row["lang"] else "uz"

def db_set_lang(uid: int, lang: str):
    c = _db()
    c.execute("UPDATE users SET lang=? WHERE id=?", (lang, uid))
    c.commit()
    c.close()

def db_save_scan(user_id, scan_type, target, verdict,
                 score=0, entropy=0.0, sha256="",
                 vt_malicious=0, vt_total=0):
    c = _db()
    c.execute(
        "INSERT INTO scans(user_id,scan_type,target,verdict,score,"
        "entropy,sha256,vt_malicious,vt_total) VALUES(?,?,?,?,?,?,?,?,?)",
        (user_id, scan_type, (target or "")[:200], verdict,
         score, round(entropy, 4), sha256, vt_malicious, vt_total)
    )
    c.commit()
    c.close()

def db_user_stats(uid) -> dict:
    c = _db()
    row = c.execute(
        "SELECT COUNT(*) total,"
        "SUM(CASE WHEN verdict='malicious'  THEN 1 ELSE 0 END) malicious,"
        "SUM(CASE WHEN verdict='suspicious' THEN 1 ELSE 0 END) suspicious,"
        "SUM(CASE WHEN verdict='clean'      THEN 1 ELSE 0 END) clean "
        "FROM scans WHERE user_id=?", (uid,)
    ).fetchone()
    c.close()
    return dict(row) if row else {}

def db_is_banned(uid) -> bool:
    c = _db()
    row = c.execute("SELECT is_banned FROM users WHERE id=?", (uid,)).fetchone()
    c.close()
    return bool(row and row["is_banned"])

def db_set_ban(uid, ban: bool):
    c = _db()
    c.execute("UPDATE users SET is_banned=? WHERE id=?", (1 if ban else 0, uid))
    c.commit()
    c.close()

def db_global_stats() -> dict:
    c = _db()
    row = c.execute(
        "SELECT COUNT(DISTINCT user_id) users, COUNT(*) scans,"
        "SUM(CASE WHEN verdict='malicious' THEN 1 ELSE 0 END) malicious "
        "FROM scans"
    ).fetchone()
    reg = c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]
    c.close()
    d = dict(row) if row else {}
    d["registered"] = reg
    return d

def db_recent_scans(n=8) -> list:
    c = _db()
    rows = c.execute(
        "SELECT s.id,s.user_id,u.username,s.scan_type,s.target,"
        "s.verdict,s.score,s.created_at "
        "FROM scans s LEFT JOIN users u ON s.user_id=u.id "
        "ORDER BY s.created_at DESC LIMIT ?", (n,)
    ).fetchall()
    c.close()
    return [dict(r) for r in rows]

# ───────────────────────────────────────────────────────────
#  RATE LIMITER
# ───────────────────────────────────────────────────────────
_rl: dict[int, list[float]] = defaultdict(list)

def rate_check(uid: int) -> tuple[bool, float]:
    now    = time.monotonic()
    window = now - 60
    times  = [t for t in _rl[uid] if t > window]
    _rl[uid] = times
    if len(times) >= RATE_LIMIT_MAX:
        return False, round(60 - (now - times[0]), 1)
    _rl[uid].append(now)
    return True, 0.0

# ───────────────────────────────────────────────────────────
#  YARA QOIDALARI  (tuzatilgan sintaksis)
# ───────────────────────────────────────────────────────────
_YARA_SRC = r"""
rule Suspicious_PowerShell {
    strings:
        $a = "powershell" nocase
        $b = "-EncodedCommand" nocase
        $c = "Invoke-Expression" nocase
        $d = "IEX(" nocase
        $e = "DownloadString" nocase
        $f = "Net.WebClient" nocase
    condition:
        2 of them
}
rule Process_Injection {
    strings:
        $a = "VirtualAllocEx"
        $b = "WriteProcessMemory"
        $c = "CreateRemoteThread"
        $d = "NtCreateThreadEx"
        $e = "OpenProcess"
    condition:
        3 of them
}
rule Anti_Analysis {
    strings:
        $a = "IsDebuggerPresent"
        $b = "CheckRemoteDebuggerPresent"
        $c = "NtQueryInformationProcess"
        $d = "FindWindowA"
        $e = "GetTickCount"
    condition:
        2 of them
}
rule Ransomware_Indicators {
    strings:
        $a = "CryptEncrypt"
        $b = "CryptGenKey"
        $c = "FindFirstFile"
        $d = "DeleteFile"
        $e = ".locked" nocase
        $f = "bitcoin" nocase
        $g = "YOUR FILES" nocase
    condition:
        3 of them
}
rule Network_Indicators {
    strings:
        $a = "WSAStartup"
        $b = "InternetOpen"
        $c = "URLDownloadToFile"
        $d = "WinHttpOpen"
    condition:
        2 of them
}
rule Persistence_Mechanisms {
    strings:
        $a = "RegSetValueEx"
        $b = "RegCreateKeyEx"
        $c = "CreateService"
        $d = "CurrentVersion\\Run"
    condition:
        2 of them
}
"""

_yara_rules = None
if YARA_OK:
    try:
        _yara_rules = yara.compile(source=_YARA_SRC)
        log.info("✅ YARA: 6 qoida yuklandi")
    except Exception as e:
        log.warning("YARA compile xatosi: %s", e)

# ───────────────────────────────────────────────────────────
#  FAYL ANALYZER
# ───────────────────────────────────────────────────────────
_APIS = {
    "process_injection": [
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtCreateThreadEx", "RtlCreateUserThread", "OpenProcess",
        "NtUnmapViewOfSection", "SetThreadContext", "ResumeThread",
    ],
    "anti_analysis": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "GetTickCount", "OutputDebugString",
        "FindWindowA", "FindWindowW", "QueryPerformanceCounter",
    ],
    "network": [
        "WSAStartup", "connect", "send", "recv",
        "InternetOpenA", "InternetOpenW", "URLDownloadToFile",
        "WinHttpOpen", "HttpSendRequest", "WinHttpConnect",
    ],
    "persistence": [
        "RegSetValueEx", "RegCreateKeyEx", "CreateServiceA", "CreateServiceW",
        "SHGetFolderPath", "SetFileAttributesA",
    ],
    "ransomware": [
        "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContext",
        "FindFirstFileA", "FindFirstFileW", "DeleteFileA", "DeleteFileW",
        "MoveFileExA", "SetEndOfFile",
    ],
}
_ALL_APIS = {api: cat for cat, apis in _APIS.items() for api in apis}

_DANGEROUS_EXTS = {
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".vbs", ".js", ".ps1",
    ".msi", ".com", ".hta", ".jar", ".pif", ".wsf", ".cpl", ".inf",
    ".apk", ".ipa", ".dex", ".xapk",
}

_SOCIAL_KEYWORDS = [
    "chaqiruv", "jarima", "soliq", "bank", "kredit", "tolov", "to'lov",
    "invoice", "payment", "urgent", "police", "court", "tax", "fine",
    "notice", "summon", "warning", "alert", "penalty", "debt", "loan",
    "iibb", "dtx", "sud", "prokuratura", "davlat",
]

_PS_PATTERNS = [
    (b"bypass",            "ExecutionPolicy Bypass",   15),
    (b"invoke-expression", "Invoke-Expression (IEX)",  15),
    (b"downloadstring",    "DownloadString",            15),
    (b"-encodedcommand",   "Base64 encoded buyruq",    15),
    (b"iex(",              "IEX qisqartmasi",           15),
    (b"net.webclient",     "Net.WebClient",             12),
    (b"downloadfile",      "DownloadFile",              12),
    (b"hidden",            "Yashirin oyna rejimi",       8),
    (b"-nop",              "NoProfile flagi",            8),
    (b"base64",            "Base64 kodlash",             8),
]

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return round(-sum((v / n) * math.log2(v / n) for v in c.values() if v), 4)

def _strings(data: bytes, ml=5) -> list[str]:
    return [
        m.group().decode("ascii", "ignore")
        for m in re.finditer(rb"[ -~]{" + str(ml).encode() + rb",}", data)
    ][:400]

def _is_pe(data: bytes) -> bool:
    if len(data) < 64 or data[:2] != b"MZ":
        return False
    try:
        off = struct.unpack_from("<I", data, 0x3C)[0]
        return off + 4 <= len(data) and data[off:off + 4] == b"PE\x00\x00"
    except Exception:
        return False

def compute_hashes(data: bytes) -> dict:
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

def analyze_file(data: bytes, filename: str = "") -> dict:
    score   = 0
    flags   = []
    details = {}

    # 1. Entropiya
    ent = _entropy(data)
    details["entropy"] = ent
    if ent > 7.5:
        score += 40
        flags.append(("high", f"Entropiya kritik ({ent}/8.0) — packer/obfuskatsiya/shifrlangan"))
    elif ent > 7.2:
        score += 25
        flags.append(("high", f"Entropiya juda yuqori ({ent}/8.0) — shifrlangan/qadoqlangan"))
    elif ent > 6.2:
        score += 10
        flags.append(("medium", f"Entropiya o'rtacha yuqori ({ent}/8.0)"))

    # 2. PE format
    details["is_pe"] = _is_pe(data)
    if details["is_pe"]:
        flags.append(("info", "PE bajariladigan fayl (EXE/DLL)"))

    # 3. API tekshiruvi
    strs     = _strings(data)
    details["strings_count"] = len(strs)
    strs_set = set(strs)
    found_apis: dict[str, list] = {}
    for api, cat in _ALL_APIS.items():
        if api in strs_set:
            found_apis.setdefault(cat, []).append(api)
    if found_apis:
        score += min(sum(len(v) for v in found_apis.values()) * 5, 35)
        details["apis"] = found_apis
        for cat, apis in found_apis.items():
            sev = "high" if cat in ("process_injection", "anti_analysis", "ransomware") else "medium"
            flags.append((sev, f"{cat.replace('_', ' ').title()}: {', '.join(apis[:4])}"))

    # 4. PowerShell
    dl = data.lower()
    for pat, desc, pts in _PS_PATTERNS:
        if pat in dl:
            score += pts
            flags.append(("high", f"PowerShell: {desc}"))

    # 5. IP / URL
    ip_re = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    ips = list({
        m.group().decode()
        for m in ip_re.finditer(data)
        if not m.group().decode().startswith(("127.", "0.", "192.168.", "10.", "172."))
    })[:8]
    urls = [s for s in strs if s.startswith(("http://", "https://", "ftp://"))][:8]
    if ips:
        score += min(len(ips) * 3, 12)
        details["ips"] = ips
        flags.append(("medium", f"Hardcoded IP ({len(ips)} ta)"))
    if urls:
        score += min(len(urls) * 4, 12)
        details["urls"] = urls
        flags.append(("medium", f"Ichki URL ({len(urls)} ta)"))

    # 6. Kengaytma + Double extension
    fname_lower = filename.lower()
    name_parts  = fname_lower.split(".")
    ext         = ("." + name_parts[-1]) if len(name_parts) > 1 else ""
    details["extension"] = ext

    if len(name_parts) >= 3:
        fake_ext = "." + name_parts[-2]
        real_ext = "." + name_parts[-1]
        if real_ext in _DANGEROUS_EXTS:
            score += 40
            flags.append(("high", f"Ikki kengaytma: '{fake_ext}' yashiringan, asl: '{real_ext}' — FISHING!"))
    elif ext in _DANGEROUS_EXTS:
        score += 10
        flags.append(("medium", f"Xavfli kengaytma: {ext}"))

    # 7. Ijtimoiy muhandislik
    sw = [k for k in _SOCIAL_KEYWORDS if k in fname_lower]
    if sw and ext in _DANGEROUS_EXTS:
        score += 30
        flags.append(("high", f"Ijtimoiy muhandislik: '{', '.join(sw[:3])}' + xavfli fayl"))

    # 8. APK maxsus
    if ext in (".apk", ".xapk", ".dex"):
        score += 15
        flags.append(("high", "Android bajariladigan fayl (APK/DEX) — mobil zararli dastur ehtimoli"))
        if b"AndroidManifest" in data:
            flags.append(("info", "AndroidManifest topildi — haqiqiy APK"))
        if b"classes.dex" in data:
            flags.append(("medium", "classes.dex topildi — DEX kodi mavjud"))

    # 9. YARA
    yara_hits = []
    if _yara_rules:
        try:
            yara_hits = [m.rule for m in _yara_rules.match(data=data)]
            if yara_hits:
                score += len(yara_hits) * 10
                flags.append(("high", f"YARA: {', '.join(yara_hits)}"))
        except Exception:
            pass
    details["yara"] = yara_hits

    score   = min(score, 100)
    verdict = "malicious" if score >= 60 else "suspicious" if score >= 25 else "clean"

    return {
        "score":   score,
        "verdict": verdict,
        "flags":   flags,
        "details": details,
        "entropy": ent,
    }

# ───────────────────────────────────────────────────────────
#  URL ANALYZER
# ───────────────────────────────────────────────────────────
_BRANDS = [
    "google", "gmail", "youtube", "facebook", "instagram", "twitter", "x",
    "linkedin", "microsoft", "office", "outlook", "apple", "icloud", "paypal",
    "amazon", "aws", "netflix", "spotify", "telegram", "whatsapp", "discord",
    "github", "gitlab", "dropbox", "binance", "coinbase", "metamask", "blockchain",
    "click", "payme", "uzcard", "humo", "uzum", "anorbank", "kapitalbank",
]

_SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw",
    ".buzz", ".click", ".download", ".loan", ".win", ".bid",
    ".stream", ".work", ".party", ".zip", ".mov",
}

_PHISHING_KW = [
    "login", "signin", "sign-in", "account", "verify", "secure", "update", "confirm",
    "password", "credential", "auth", "banking", "wallet", "support", "helpdesk",
    "suspended", "alert", "notice", "invoice", "payment", "billing", "refund",
    "free", "prize", "winner", "bonus", "reward", "claim",
]

_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "is.gd",
    "cli.gs", "short.link", "tiny.cc", "cutt.ly", "shorturl.at", "rb.gy",
}

_HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "ο": "o", "ρ": "p", "ν": "v", "α": "a", "β": "b",
}

def _norm_domain(d: str) -> str:
    return "".join(_HOMOGLYPHS.get(c, c) for c in d.lower())

def _parse_url(url: str) -> dict:
    flags = []
    score = 0
    try:
        parsed = urlparse(url)
    except Exception:
        return {"flags": [("high", "URL parse xatosi")], "score": 30, "info": {}}

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path   = parsed.path.lower()
    query  = parsed.query.lower()
    domain = netloc.split(":")[0]
    dn     = _norm_domain(domain)
    parts  = domain.split(".")
    tld    = ("." + parts[-1]) if parts else ""

    if scheme == "http":
        score += 8
        flags.append(("medium", "HTTP — shifrsiz ulanish"))
    elif scheme not in ("http", "https"):
        score += 20
        flags.append(("high", f"Noodatiy protokol: {scheme}"))

    if len(url) > 200:
        score += 10
        flags.append(("medium", f"URL juda uzun: {len(url)} belgi"))
    elif len(url) > 100:
        score += 5
        flags.append(("info", f"URL uzun: {len(url)} belgi"))

    if re.match(r"https?://\d{1,3}(\.\d{1,3}){3}", url):
        score += 25
        flags.append(("high", "IP manzil URL sifatida (fishing belgisi)"))

    subs = parts[:-2] if len(parts) > 2 else []
    if len(subs) >= 3:
        score += 15
        flags.append(("high", f"Ko'p subdomen ({len(subs)} ta)"))
    elif len(subs) == 2:
        score += 5
        flags.append(("medium", "Ikki qavatli subdomen"))

    if tld in _SUSPICIOUS_TLDS:
        score += 15
        flags.append(("high", f"Shubhali TLD: {tld}"))

    if domain in _URL_SHORTENERS:
        score += 12
        flags.append(("medium", f"URL qisqartuvchi: {domain}"))

    full = path + "?" + query
    kws  = [k for k in _PHISHING_KW if k in full]
    if kws:
        score += min(len(kws) * 5, 20)
        flags.append(("high", f"Fishing kalit so'z: {', '.join(kws[:5])}"))

    dkws = [k for k in _PHISHING_KW if k in dn]
    if dkws:
        score += 15
        flags.append(("high", f"Domenда fishing so'z: {', '.join(dkws[:3])}"))

    if "@" in netloc:
        score += 20
        flags.append(("high", "URL da '@' — foydalanuvchini aldash"))

    if url.count("//") > 1:
        score += 15
        flags.append(("high", "Ikki marta '//' — URL obfuskatsiyasi"))

    if re.search(r"[A-Za-z0-9+/]{30,}={0,2}", url):
        score += 10
        flags.append(("medium", "Base64 fragment topildi"))

    if dn != domain:
        score += 20
        flags.append(("high", f"Homoglyph/IDN hujum: {domain} → {dn}"))

    return {
        "flags": flags,
        "score": min(score, 40),
        "info":  {"scheme": scheme, "domain": domain, "domain_norm": dn, "tld": tld},
    }

def _typosquat(domain: str) -> list:
    clean = _norm_domain(domain.split(".")[0])
    res   = [(b, round(SequenceMatcher(None, clean, b).ratio(), 3)) for b in _BRANDS]
    return sorted([(b, r) for b, r in res if 0.75 <= r < 1.0], key=lambda x: -x[1])[:5]

async def _dns(domain: str) -> dict:
    r = {"a": [], "mx": [], "ns": [], "spf": None, "dmarc": None, "flags": [], "score": 0}
    res = dns.resolver.Resolver()
    res.lifetime = DNS_TIMEOUT
    try:
        r["a"] = [x.address for x in res.resolve(domain, "A")]
        for ip in r["a"]:
            try:
                if ipaddress.ip_address(ip).is_private:
                    r["score"] += 20
                    r["flags"].append(("high", f"DNS rebinding: → xususiy IP {ip}"))
            except Exception:
                pass
    except Exception:
        r["flags"].append(("info", "A record topilmadi"))
    try:
        r["mx"] = [str(x.exchange) for x in res.resolve(domain, "MX")]
    except Exception:
        pass
    try:
        r["ns"] = [str(x.target) for x in res.resolve(domain, "NS")]
    except Exception:
        pass
    try:
        for rd in res.resolve(domain, "TXT"):
            txt = " ".join(s.decode() for s in rd.strings)
            if len(txt) < 60:
                r["flags"].append(("info", f"TXT: {txt[:60]}"))
            if txt.startswith("v=spf1"):
                r["spf"] = txt[:80]
            if "v=DMARC1" in txt:
                r["dmarc"] = txt[:80]
    except Exception:
        pass
    if not r["dmarc"]:
        try:
            for rd in res.resolve(f"_dmarc.{domain}", "TXT"):
                txt = " ".join(s.decode() for s in rd.strings)
                if "v=DMARC1" in txt:
                    r["dmarc"] = txt[:80]
        except Exception:
            pass
    if not r["spf"] and r["mx"]:
        r["score"] += 8
        r["flags"].append(("medium", "SPF yozuvi yo'q"))
    if not r["dmarc"]:
        r["score"] += 5
        r["flags"].append(("info", "DMARC yozuvi yo'q"))
    if not r["a"] and not r["mx"]:
        r["score"] += 10
        r["flags"].append(("medium", "DNS yozuvlari topilmadi"))
    return r

def _whois(domain: str) -> dict:
    r = {
        "registrar": None, "created": None, "expires": None,
        "age_days": None, "country": None, "flags": [], "score": 0,
    }
    try:
        w   = whois_lib.whois(domain)
        r["registrar"] = str(w.registrar or "")[:60]
        r["country"]   = str(w.country   or "")[:10]
        now = datetime.now(timezone.utc)

        def _d(val):
            if not val:
                return None
            v = val[0] if isinstance(val, list) else val
            return v if isinstance(v, datetime) else None

        cr = _d(w.creation_date)
        ex = _d(w.expiration_date)
        if cr:
            if cr.tzinfo is None:
                cr = cr.replace(tzinfo=timezone.utc)
            age = (now - cr).days
            r["created"]  = cr.strftime("%Y-%m-%d")
            r["age_days"] = age
            if age < 7:
                r["score"] += 30
                r["flags"].append(("high", f"Domen juda yangi: {age} kun!"))
            elif age < 30:
                r["score"] += 20
                r["flags"].append(("high", f"Domen yangi: {age} kun"))
            elif age < 180:
                r["score"] += 10
                r["flags"].append(("medium", f"Domen nisbatan yangi: {age} kun"))
            else:
                r["flags"].append(("info", f"Domen yoshi: {age} kun (~{age // 365} yil)"))
        if ex:
            if ex.tzinfo is None:
                ex = ex.replace(tzinfo=timezone.utc)
            dl = (ex - now).days
            r["expires"] = ex.strftime("%Y-%m-%d")
            if dl < 0:
                r["score"] += 15
                r["flags"].append(("high", "Domen muddati tugagan!"))
            elif dl < 30:
                r["score"] += 5
                r["flags"].append(("medium", f"Muddat {dl} kun qoldi"))
    except Exception as e:
        r["flags"].append(("info", f"WHOIS: {str(e)[:50]}"))
    return r

async def _ssl_check(hostname: str) -> dict:
    r = {
        "valid": None, "issuer": None, "subject": None, "not_after": None,
        "days_left": None, "self_signed": False, "flags": [], "score": 0,
    }
    try:
        loop = asyncio.get_event_loop()

        def _get():
            ctx  = ssl.create_default_context()
            conn = ctx.wrap_socket(
                socket.create_connection((hostname, 443), timeout=8),
                server_hostname=hostname
            )
            cert = conn.getpeercert()
            conn.close()
            return cert

        cert    = await asyncio.wait_for(loop.run_in_executor(None, _get), timeout=10)
        issuer  = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        r["issuer"]  = issuer.get("organizationName", "")[:50]
        r["subject"] = subject.get("commonName", "")[:60]
        if issuer == subject:
            r["self_signed"] = True
            r["score"] += 20
            r["flags"].append(("high", "Self-signed sertifikat!"))

        na  = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        # DeprecationWarning tuzatildi: utcnow() o'rniga timezone-aware ishlatiladi
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        r["not_after"] = na.strftime("%Y-%m-%d")
        r["days_left"] = dl = (na - now).days
        r["valid"]     = dl > 0
        if dl < 0:
            r["score"] += 25
            r["flags"].append(("high", "SSL muddati tugagan!"))
        elif dl < 14:
            r["score"] += 10
            r["flags"].append(("high", f"SSL {dl} kun qoldi"))
        elif dl < 30:
            r["score"] += 5
            r["flags"].append(("medium", f"SSL {dl} kun qoldi"))
        else:
            r["flags"].append(("info", f"SSL yaroqli: {dl} kun"))
    except ssl.SSLCertVerificationError as e:
        r["valid"] = False
        r["score"] += 25
        r["flags"].append(("high", f"SSL xatosi: {str(e)[:60]}"))
    except Exception as e:
        r["flags"].append(("info", f"SSL: {str(e)[:50]}"))
    return r

async def _urlscan(url: str) -> dict:
    r = {"found": False, "verdict": None, "score": 0, "tags": [], "screenshot": None, "flags": []}
    if not URLSCAN_KEY:
        r["flags"].append(("info", "URLScan.io API key yo'q"))
        return r
    hdrs = {"API-Key": URLSCAN_KEY, "Content-Type": "application/json"}
    async with aiohttp.ClientSession() as s:
        try:
            async with s.post(
                "https://urlscan.io/api/v1/scan/",
                headers=hdrs,
                json={"url": url, "visibility": "private"},
                timeout=HTTP_TO
            ) as resp:
                if resp.status not in (200, 201):
                    r["flags"].append(("info", f"URLScan: HTTP {resp.status}"))
                    return r
                uuid = (await resp.json()).get("uuid", "")
                if not uuid:
                    return r
            for _ in range(6):
                await asyncio.sleep(5)
                async with s.get(
                    f"https://urlscan.io/api/v1/result/{uuid}/",
                    timeout=HTTP_TO
                ) as resp2:
                    if resp2.status == 200:
                        data = await resp2.json()
                        v    = data.get("verdicts", {}).get("overall", {})
                        r.update(
                            found=True,
                            verdict=v.get("malicious", False),
                            score=v.get("score", 0),
                            tags=v.get("tags", [])[:5],
                            screenshot=f"https://urlscan.io/screenshots/{uuid}.png"
                        )
                        if r["verdict"]:
                            r["flags"].append(("high", f"URLScan: ZARARLI (ball:{r['score']})"))
                        elif r["score"] > 50:
                            r["flags"].append(("medium", f"URLScan: Shubhali (ball:{r['score']})"))
                        return r
        except Exception as e:
            r["flags"].append(("info", f"URLScan: {str(e)[:40]}"))
    r["flags"].append(("info", "URLScan: Vaqt tugadi"))
    return r

async def _gsb(url: str) -> dict:
    r = {"safe": True, "threats": [], "flags": []}
    if not GSB_KEY:
        r["flags"].append(("info", "Google Safe Browsing API key yo'q"))
        return r
    payload = {
        "client": {"clientId": "malwareguard", "clientVersion": "3.2"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes":    ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries":    [{"url": url}],
        },
    }
    async with aiohttp.ClientSession() as s:
        try:
            async with s.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_KEY}",
                json=payload,
                timeout=HTTP_TO
            ) as resp:
                if resp.status == 200:
                    for m in (await resp.json()).get("matches", []):
                        t = m.get("threatType", "UNKNOWN")
                        r["safe"] = False
                        r["threats"].append(t)
                        r["flags"].append(("high", f"Google Safe Browsing: {t}"))
                    if r["safe"]:
                        r["flags"].append(("info", "Google Safe Browsing: Xavfsiz"))
        except Exception as e:
            r["flags"].append(("info", f"GSB: {str(e)[:40]}"))
    return r

# ───────────────────────────────────────────────────────────
#  VIRUSTOTAL
# ───────────────────────────────────────────────────────────
def _vt_ok() -> bool:
    return bool(VT_API_KEY)

def _vt_headers() -> dict:
    return {"x-apikey": VT_API_KEY} if VT_API_KEY else {}

def _vt_parse(data: dict) -> dict:
    a  = data.get("data", {}).get("attributes", {})
    st = a.get("last_analysis_stats", {})
    return {
        "found":      True,
        "malicious":  st.get("malicious",  0),
        "suspicious": st.get("suspicious", 0),
        "harmless":   st.get("harmless",   0),
        "undetected": st.get("undetected", 0),
        "total":      sum(st.values()),
        "name":       a.get("meaningful_name", ""),
        "file_type":  a.get("type_description", ""),
        "size":       a.get("size", 0),
        "categories": list(a.get("categories", {}).values())[:5],
        "engines":    {
            k: v.get("result", "")
            for k, v in a.get("last_analysis_results", {}).items()
            if v.get("category") in ("malicious", "suspicious")
        },
    }

async def vt_hash(h: str) -> dict:
    if not _vt_ok():
        return {"found": False, "message": "VT_API_KEY yo'q"}
    async with aiohttp.ClientSession() as s:
        try:
            async with s.get(
                f"https://www.virustotal.com/api/v3/files/{h}",
                headers=_vt_headers(), timeout=VT_TIMEOUT
            ) as r:
                if r.status == 200:
                    return _vt_parse(await r.json())
                if r.status == 404:
                    return {"found": False, "message": "VT bazasida topilmadi"}
                return {"found": False, "message": f"VT HTTP {r.status}"}
        except Exception as e:
            return {"found": False, "message": str(e)}

async def vt_file(data: bytes, fname: str) -> dict:
    if not _vt_ok():
        return {"found": False, "message": "VT_API_KEY yo'q"}
    sha = hashlib.sha256(data).hexdigest()
    res = await vt_hash(sha)
    if res.get("found"):
        return res
    async with aiohttp.ClientSession() as s:
        try:
            form = aiohttp.FormData()
            form.add_field("file", data, filename=fname)
            async with s.post(
                "https://www.virustotal.com/api/v3/files",
                headers=_vt_headers(), data=form,
                timeout=aiohttp.ClientTimeout(total=60)
            ) as r:
                j = await r.json()
                if r.status not in (200, 201):
                    return {"found": False, "message": "Upload xatosi"}
                aid = j.get("data", {}).get("id", "")
                if not aid:
                    return {"found": False, "message": "Analysis ID yo'q"}
            for _ in range(VT_POLL_MAX):
                await asyncio.sleep(VT_POLL_WAIT)
                async with s.get(
                    f"https://www.virustotal.com/api/v3/analyses/{aid}",
                    headers=_vt_headers(), timeout=VT_TIMEOUT
                ) as r2:
                    j2 = await r2.json()
                    at = j2.get("data", {}).get("attributes", {})
                    if at.get("status") == "completed":
                        st = at.get("stats", {})
                        return {
                            "found": True,
                            "malicious":  st.get("malicious",  0),
                            "suspicious": st.get("suspicious", 0),
                            "harmless":   st.get("harmless",   0),
                            "undetected": st.get("undetected", 0),
                            "total":      sum(st.values()),
                            "name":       fname,
                            "engines":    {},
                        }
        except Exception as e:
            return {"found": False, "message": str(e)}
    return {"found": False, "message": "VT vaqt tugadi"}

async def vt_url(url: str) -> dict:
    if not _vt_ok():
        return {"found": False, "message": "VT_API_KEY yo'q"}
    uid = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    async with aiohttp.ClientSession() as s:
        try:
            async with s.get(
                f"https://www.virustotal.com/api/v3/urls/{uid}",
                headers=_vt_headers(), timeout=VT_TIMEOUT
            ) as r:
                if r.status == 200:
                    return _vt_parse(await r.json())
            form = aiohttp.FormData()
            form.add_field("url", url)
            async with s.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=_vt_headers(), data=form, timeout=VT_TIMEOUT
            ) as r:
                aid = (await r.json()).get("data", {}).get("id", "")
                if not aid:
                    return {"found": False, "message": "Analysis ID yo'q"}
            for _ in range(6):
                await asyncio.sleep(5)
                async with s.get(
                    f"https://www.virustotal.com/api/v3/analyses/{aid}",
                    headers=_vt_headers(), timeout=VT_TIMEOUT
                ) as r2:
                    at = (await r2.json()).get("data", {}).get("attributes", {})
                    if at.get("status") == "completed":
                        st = at.get("stats", {})
                        return {
                            "found": True,
                            "malicious":  st.get("malicious",  0),
                            "suspicious": st.get("suspicious", 0),
                            "harmless":   st.get("harmless",   0),
                            "undetected": st.get("undetected", 0),
                            "total":      sum(st.values()),
                            "categories": [],
                        }
        except Exception as e:
            return {"found": False, "message": str(e)}
    return {"found": False, "message": "VT URL vaqt tugadi"}

async def full_url_analysis(url: str) -> dict:
    p      = urlparse(url)
    domain = p.netloc.lower().split(":")[0]
    uf     = _parse_url(url)
    typo   = _typosquat(domain)
    loop   = asyncio.get_event_loop()

    ssl_coro = _ssl_check(domain) if p.scheme == "https" else asyncio.sleep(0)

    dns_t, ssl_t, vt_t, gsb_t, scan_t, whois_t = await asyncio.gather(
        _dns(domain), ssl_coro, vt_url(url),
        _gsb(url), _urlscan(url),
        loop.run_in_executor(None, _whois, domain),
        return_exceptions=True
    )

    def _s(v, d):
        return v if isinstance(v, dict) else d

    dns_r   = _s(dns_t,   {"flags": [], "score": 0})
    ssl_r   = _s(ssl_t,   {"flags": [], "score": 0})
    vt_r    = _s(vt_t,    {"found": False})
    gsb_r   = _s(gsb_t,   {"flags": [], "safe": True})
    scan_r  = _s(scan_t,  {"flags": [], "found": False})
    whois_r = _s(whois_t, {"flags": [], "score": 0})

    if p.scheme != "https":
        ssl_r = {"flags": [("info", "HTTP — SSL tekshiruvi o'tkazilmadi")], "score": 0}

    score = (
        uf.get("score", 0) + dns_r.get("score", 0) +
        ssl_r.get("score", 0) + whois_r.get("score", 0)
    )
    if typo:
        _, ratio = typo[0]
        score += 25 if ratio >= 0.90 else 15 if ratio >= 0.80 else 8

    vt_mal = vt_r.get("malicious", 0) if vt_r.get("found") else 0
    vt_sus = vt_r.get("suspicious", 0) if vt_r.get("found") else 0
    if vt_mal > 0:  score += min(vt_mal * 5, 30)
    if vt_sus > 3:  score += 10
    if not gsb_r.get("safe", True): score += 35
    if scan_r.get("verdict"):        score += 20
    elif scan_r.get("score", 0) > 50: score += 10

    score   = min(score, 100)
    verdict = "malicious" if score >= 70 else "suspicious" if score >= 35 else "clean"

    return {
        "url": url, "domain": domain, "score": score, "verdict": verdict,
        "url_features": uf, "typosquat": typo,
        "dns": dns_r, "ssl": ssl_r, "whois": whois_r,
        "vt": vt_r, "gsb": gsb_r, "urlscan": scan_r,
    }

# ───────────────────────────────────────────────────────────
#  HISOBOT FORMATLASH
# ───────────────────────────────────────────────────────────
_VE = {"malicious": "⛔", "suspicious": "⚠️", "clean": "✅"}
_SE = {"high": "🔴", "medium": "🟡", "info": "🔵"}

def _bar(sc: int) -> str:
    f   = round(sc / 10)
    bar = "█" * f + "░" * (10 - f)
    c   = "🔴" if sc >= 70 else "🟡" if sc >= 35 else "🟢"
    return f"{c} <code>[{bar}]</code> {sc}/100"

def _fmt_flags(flags: list, uid: int, mx=5) -> str:
    if not flags:
        return f"  {tr(uid, 'no_problem')}"
    lines = [f"  {_SE.get(s, '⚪')} {m}" for s, m in flags[:mx]]
    if len(flags) > mx:
        lines.append(f"  ... +{len(flags) - mx} ta")
    return "\n".join(lines)

def _fmt_sz(b: int) -> str:
    if b < 1024:      return f"{b} B"
    if b < 1 << 20:   return f"{b / 1024:.1f} KB"
    return f"{b / (1 << 20):.2f} MB"

def _fmt_vt(vt: dict) -> str:
    if not vt or not vt.get("found"):
        return f"  {vt.get('message', 'Topilmadi') if vt else 'API key yoq'}"
    t = vt.get("total", 1) or 1
    lines = [
        f"  🔴 {vt.get('malicious', 0)} | 🟡 {vt.get('suspicious', 0)} | "
        f"🟢 {vt.get('harmless', 0)}  (/{t})",
    ]
    if vt.get("name"):       lines.append(f"  📛 Nom: <code>{vt['name'][:40]}</code>")
    if vt.get("file_type"):  lines.append(f"  📂 Tur: {vt['file_type']}")
    if vt.get("categories"): lines.append(f"  🏷 Kategoriya: {', '.join(vt['categories'][:3])}")
    if vt.get("engines"):
        eng = list(vt["engines"])[:5]
        lines.append(f"  🦠 {', '.join(f'<code>{e}</code>' for e in eng)}")
    return "\n".join(lines)

def _verdict_label(uid: int, verdict: str) -> str:
    return tr(uid, f"verdict_{verdict}")

def _build_banner(uid: int, verdict: str, is_url: bool = False) -> str:
    if verdict == "malicious":
        key = "warn_url_mal" if is_url else "warn_malicious"
    elif verdict == "suspicious":
        key = "warn_url_sus" if is_url else "warn_suspicious"
    else:
        return ""
    return "━━━━━━━━━━━━━━━━━━━━\n" + tr(uid, key, url=GUIDE_URL) + "\n━━━━━━━━━━━━━━━━━━━━\n\n"

# ── Fayl hisoboti ─────────────────────────────────────────
def report_file(filename, size, hashes, h, vt, uid: int) -> tuple[str, str]:
    verdict = h["verdict"]
    if vt and vt.get("found") and vt.get("malicious", 0) > 0:
        verdict = "malicious"
    elif vt and vt.get("found") and vt.get("suspicious", 0) > 3 and verdict == "clean":
        verdict = "suspicious"

    d      = h["details"]
    banner = _build_banner(uid, verdict)
    vl     = _verdict_label(uid, verdict)
    title  = tr(uid, "file_report_title")

    lines = [
        f"{banner}{_VE[verdict]} <b>{title}: {vl}</b>", "",
        f"📄 <b>Fayl:</b> <code>{filename}</code>",
        f"📦 <b>Hajm:</b> {_fmt_sz(size)}",
        f"🔬 <b>Xavf balli:</b> {_bar(h['score'])}", "",
        "🔐 <b>Heshlar:</b>",
        f"  MD5:    <code>{hashes['md5']}</code>",
        f"  SHA1:   <code>{hashes['sha1']}</code>",
        f"  SHA256: <code>{hashes['sha256']}</code>", "",
        f"📊 <b>Entropiya:</b> <code>{d['entropy']}/8.0</code>"
        + (" 🔴" if d["entropy"] > 7.0 else " 🟡" if d["entropy"] > 6.0 else " 🟢"),
        f"⚙️  <b>PE format:</b> {'✅ Ha' if d.get('is_pe') else '—'}",
        f"📝 <b>Satrlar:</b> {d.get('strings_count', 0)} ta",
        f"🧬 <b>YARA:</b> {', '.join(f'<code>{r}</code>' for r in d.get('yara', [])) or '✅ Toza'}",
        "", "🌐 <b>VirusTotal:</b>", _fmt_vt(vt),
    ]
    if h["flags"]:
        lines += ["", "🚩 <b>Ko'rsatkichlar:</b>", _fmt_flags(h["flags"], uid)]
    if d.get("ips"):
        lines += ["", "🌍 <b>Hardcoded IP:</b>",
                  " ".join(f"<code>{i}</code>" for i in d["ips"][:6])]
    if d.get("urls"):
        lines += ["", "🔗 <b>Ichki URL:</b>"] + \
                 [f"  <code>{u[:60]}</code>" for u in d["urls"][:4]]
    lines += ["", "━━━━━━━━━━━━━━━━━━━━", "🛡 <i>MalwareGuard PRO v3.2</i>"]
    return "\n".join(lines), verdict

# ── URL hisoboti ──────────────────────────────────────────
def report_url(r: dict, uid: int) -> str:
    verdict = r["verdict"]
    w       = r["whois"]
    d       = r["dns"]
    ss      = r["ssl"]
    vt      = r["vt"]
    gsb     = r["gsb"]
    sc      = r["urlscan"]
    typo    = r["typosquat"]
    uf      = r["url_features"]

    banner = _build_banner(uid, verdict, is_url=True)
    vl     = _verdict_label(uid, verdict)
    title  = tr(uid, "url_report_title")

    lines = [
        f"{banner}{_VE[verdict]} <b>{title}: {vl}</b>", "",
        f"🔗 <code>{r['url'][:70]}</code>",
        f"🌍 Domen: <b>{r['domain']}</b>",
        f"🔬 Xavf balli: {_bar(r['score'])}", "",
    ]
    if uf.get("flags"):
        lines += ["🔎 <b>URL tuzilmasi:</b>", _fmt_flags(uf["flags"], uid, 4), ""]

    if typo:
        lines.append("🎭 <b>Typosquatting:</b>")
        for brand, ratio in typo[:3]:
            pct  = int(ratio * 100)
            icon = "🔴" if ratio >= 0.90 else "🟡" if ratio >= 0.80 else "🟠"
            lines.append(f"  {icon} <code>{r['domain']}</code> ↔ <b>{brand}</b> ({pct}%)")
        lines.append("")

    lines.append("📋 <b>WHOIS:</b>")
    if w.get("registrar"): lines.append(f"  Registrar: {w['registrar']}")
    if w.get("created"):
        age = f" ({w['age_days']} kun)" if w.get("age_days") is not None else ""
        lines.append(f"  Yaratilgan: {w['created']}{age}")
    if w.get("expires"):  lines.append(f"  Muddat: {w['expires']}")
    if w.get("country"):  lines.append(f"  Mamlakat: {w['country']}")
    lines += [_fmt_flags(w.get("flags", []), uid, 3), ""]

    lines.append("🌐 <b>DNS:</b>")
    if d.get("a"):  lines.append(f"  A: {', '.join(d['a'][:3])}")
    if d.get("mx"): lines.append(f"  MX: {', '.join(str(m)[:30] for m in d['mx'][:2])}")
    spf_i = "✅" if d.get("spf") else "❌"
    dma_i = "✅" if d.get("dmarc") else "❌"
    lines += [f"  SPF: {spf_i}  DMARC: {dma_i}", _fmt_flags(d.get("flags", []), uid, 3), ""]

    if ss and (ss.get("flags") or ss.get("issuer")):
        lines.append("🔒 <b>SSL Sertifikat:</b>")
        if ss.get("issuer"):    lines.append(f"  Issuer: {ss['issuer']}")
        if ss.get("not_after"): lines.append(f"  Muddat: {ss['not_after']} ({ss.get('days_left', '?')} kun)")
        if ss.get("self_signed"): lines.append("  ⚠️ Self-signed!")
        lines += [_fmt_flags(ss.get("flags", []), uid, 3), ""]

    lines += ["🛡 <b>VirusTotal:</b>", _fmt_vt(vt), ""]

    lines.append("🔍 <b>Google Safe Browsing:</b>")
    if not gsb.get("safe", True):
        lines.append(f"  🔴 Tahdid: {', '.join(gsb.get('threats', []))}")
    else:
        lines.append("  ✅ Xavfsiz")
    lines.append("")

    lines.append("🖥 <b>URLScan.io:</b>")
    if not sc.get("found"):
        msg = sc["flags"][0][1] if sc.get("flags") else "Ma'lumot yo'q"
        lines.append(f"  {msg}")
    else:
        vi = "🔴 ZARARLI" if sc.get("verdict") else "✅ Xavfsiz"
        lines.append(f"  {vi}  (ball:{sc.get('score', 0)})")
        if sc.get("tags"):       lines.append(f"  Teglar: {', '.join(sc['tags'][:3])}")
        if sc.get("screenshot"): lines.append(f"  📸 {sc['screenshot']}")

    lines += ["", "━━━━━━━━━━━━━━━━━━━━", "🛡 <i>MalwareGuard PRO v3.2</i>"]
    return "\n".join(lines)

# ── Hash hisoboti ─────────────────────────────────────────
def report_hash(h_str: str, vt: dict, uid: int) -> str:
    title = tr(uid, "hash_report_title")
    lines = [f"🔑 <b>{title}</b>", f"<code>{h_str}</code>", ""]
    if not vt.get("found"):
        lines += ["🔍 VT bazasida topilmadi", vt.get("message", "")]
    else:
        mal = vt.get("malicious", 0)
        sus = vt.get("suspicious", 0)
        t   = vt.get("total", 1) or 1
        if mal > 0:
            lines.append(f"⛔ <b>{tr(uid, 'verdict_malicious')}</b> — {mal}/{t} engine aniqladi")
        elif sus > 3:
            lines.append(f"⚠️ <b>{tr(uid, 'verdict_suspicious')}</b> — {sus}/{t}")
        else:
            lines.append(f"✅ <b>{tr(uid, 'verdict_clean')}</b>")
        lines += ["", _fmt_vt(vt)]
    lines += ["", "━━━━━━━━━━━━━━━━━━━━", "🛡 <i>MalwareGuard PRO v3.2</i>"]
    return "\n".join(lines)

# ───────────────────────────────────────────────────────────
#  KLAVIATURALAR
# ───────────────────────────────────────────────────────────
def kb_main(uid: int):
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text=tr(uid, "btn_scanner")),
             KeyboardButton(text=tr(uid, "btn_profile"))],
            [KeyboardButton(text=tr(uid, "btn_about"))],
        ],
        resize_keyboard=True
    )

def kb_scanner(uid: int):
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text=tr(uid, "btn_file")),
             KeyboardButton(text=tr(uid, "btn_hash"))],
            [KeyboardButton(text=tr(uid, "btn_url")),
             KeyboardButton(text=tr(uid, "btn_back"))],
        ],
        resize_keyboard=True
    )

def kb_lang():
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="🇺🇿 O'zbek",  callback_data="lang_uz"),
        InlineKeyboardButton(text="🇷🇺 Русский", callback_data="lang_ru"),
        InlineKeyboardButton(text="🇬🇧 English", callback_data="lang_en"),
    ]])

def kb_vt_file(sha256: str, verdict: str, uid: int):
    buttons = [[InlineKeyboardButton(
        text=tr(uid, "vt_btn"),
        url=f"https://www.virustotal.com/gui/file/{sha256}"
    )]]
    if verdict in ("malicious", "suspicious"):
        buttons.append([InlineKeyboardButton(
            text=tr(uid, "guide_btn"), url=GUIDE_URL
        )])
    return InlineKeyboardMarkup(inline_keyboard=buttons)

def kb_vt_url(url: str, verdict: str, uid: int):
    uid_b64 = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    buttons = [[
        InlineKeyboardButton(
            text=tr(uid, "vt_btn"),
            url=f"https://www.virustotal.com/gui/url/{uid_b64}"
        ),
        InlineKeyboardButton(
            text="🔍 GSB",
            url=f"https://transparencyreport.google.com/safe-browsing/search?url={quote(url)}"
        ),
    ]]
    if verdict in ("malicious", "suspicious"):
        buttons.append([InlineKeyboardButton(
            text=tr(uid, "guide_url_btn"), url=GUIDE_URL
        )])
    return InlineKeyboardMarkup(inline_keyboard=buttons)

def kb_admin():
    b = InlineKeyboardBuilder()
    b.button(text="📊 Statistika",      callback_data="adm_stats")
    b.button(text="📋 So'nggi scanlar", callback_data="adm_recent")
    b.button(text="🚫 Ban",             callback_data="adm_ban")
    b.button(text="✅ Unban",           callback_data="adm_unban")
    b.adjust(2)
    return b.as_markup()

# ───────────────────────────────────────────────────────────
#  FSM
# ───────────────────────────────────────────────────────────
class S(StatesGroup):
    file      = State()
    hash_     = State()
    url       = State()
    adm_ban   = State()
    adm_unban = State()

# ───────────────────────────────────────────────────────────
#  ROUTER
# ───────────────────────────────────────────────────────────
router  = Router()
_URL_RE = re.compile(r"https?://[^\s]{8,}", re.I)

async def _guard(msg: Message) -> bool:
    uid = msg.from_user.id
    if db_is_banned(uid):
        await msg.answer(tr(uid, "banned"))
        return False
    ok, wait = rate_check(uid)
    if not ok:
        await msg.answer(tr(uid, "rate_limit", wait=wait, max=RATE_LIMIT_MAX))
        return False
    return True

# ── /start ───────────────────────────────────────────────
@router.message(CommandStart())
async def cmd_start(msg: Message, state: FSMContext):
    await state.clear()
    uid = msg.from_user.id
    db_upsert_user(uid, msg.from_user.username, msg.from_user.first_name)
    await msg.answer(
        "🛡 <b>MalwareGuard PRO v3.2</b>\n\n"
        "Zararli dasturlarni aniqlash tizimi.\n\n"
        "<b>Imkoniyatlar:</b>\n"
        "📄 Fayl → heuristik + YARA + VirusTotal\n"
        "🔗 URL  → 7 qatlam tahlil\n"
        "🔑 Hash → MD5 / SHA1 / SHA256\n\n"
        "<b>Buyruqlar:</b> /hash  /url  /profil  /lang  /help",
        reply_markup=kb_main(uid)
    )

# ── /lang ────────────────────────────────────────────────
@router.message(Command("lang"))
async def cmd_lang(msg: Message):
    uid = msg.from_user.id
    await msg.answer(tr(uid, "choose_lang"), reply_markup=kb_lang())

@router.callback_query(F.data.startswith("lang_"))
async def set_lang(call: CallbackQuery):
    lang = call.data.split("_")[1]
    uid  = call.from_user.id
    db_set_lang(uid, lang)
    await call.message.answer(tr(uid, "lang_changed"), reply_markup=kb_main(uid))
    await call.answer()

# ── /help ────────────────────────────────────────────────
@router.message(Command("help"))
async def cmd_help(msg: Message):
    await msg.answer(
        "❓ <b>Yordam</b>\n\n"
        "<b>Fayl:</b> To'g'ridan yuboring yoki Scanner → Fayl\n"
        "<b>Hash:</b> <code>/hash d41d8cd98f...</code>\n"
        "<b>URL:</b>  <code>/url https://example.com</code>\n"
        "<b>Til:</b>  <code>/lang</code>\n\n"
        "<b>URL tahlil qatlamlari:</b>\n"
        "  🔎 URL tuzilmasi\n"
        "  🎭 Typosquatting (30+ brend)\n"
        "  📋 WHOIS (domen yoshi)\n"
        "  🌐 DNS (SPF, DMARC, rebinding)\n"
        "  🔒 SSL (muddati, self-signed)\n"
        "  🛡 VirusTotal (70+ AV)\n"
        "  🔍 Google Safe Browsing\n"
        "  🖥 URLScan.io\n\n"
        "<b>Fayl tahlil qatlamlari:</b>\n"
        "  📊 Shannon entropiya\n"
        "  ⚙️ PE tuzilmasi\n"
        "  🧬 YARA (6 qoida)\n"
        "  🔍 30+ Windows API\n"
        "  📱 APK/mobil fayl\n"
        "  🎭 Double extension\n"
        "  🌐 VirusTotal"
    )

# ── /about ───────────────────────────────────────────────
@router.message(Command("about"))
@router.message(F.text.in_(ALL_ABOUT_BTNS))
async def cmd_about(msg: Message):
    uid   = msg.from_user.id
    vt_s  = "✅ Faol" if VT_API_KEY  else "⚠️ Sozlanmagan"
    gsb_s = "✅ Faol" if GSB_KEY     else "⚠️ Sozlanmagan"
    usc_s = "✅ Faol" if URLSCAN_KEY else "⚠️ Sozlanmagan"
    yar_s = "✅ Faol" if YARA_OK     else "⚠️ O'rnatilmagan"
    await msg.answer(
        "ℹ️ <b>MalwareGuard PRO v3.2</b>\n\n"
        "<b>Stack:</b> Python 3.11+ • aiogram 3.x • aiohttp\n"
        "         dnspython • python-whois • YARA\n\n"
        "<b>Integratsiyalar:</b>\n"
        f"  VirusTotal:           {vt_s}\n"
        f"  Google Safe Browsing: {gsb_s}\n"
        f"  URLScan.io:           {usc_s}\n"
        f"  YARA:                 {yar_s}\n\n"
        "<b>Tillar:</b> 🇺🇿 O'zbek • 🇷🇺 Русский • 🇬🇧 English\n"
        "<b>DB:</b> SQLite — tahlil tarixi\n"
        "<b>Kurs ishi:</b> Axborot xavfsizligi"
    )

# ── Menyu ────────────────────────────────────────────────
@router.message(F.text.in_(ALL_SCANNER_BTNS))
async def menu_scanner(msg: Message, state: FSMContext):
    await state.clear()
    uid = msg.from_user.id
    await msg.answer(tr(uid, "scanner_menu"), reply_markup=kb_scanner(uid))

@router.message(F.text.in_(ALL_BACK_BTNS))
async def menu_back(msg: Message, state: FSMContext):
    await state.clear()
    uid = msg.from_user.id
    await msg.answer(tr(uid, "back_main"), reply_markup=kb_main(uid))

# ── Profil ───────────────────────────────────────────────
@router.message(Command("profil"))
@router.message(F.text.in_(ALL_PROFILE_BTNS))
async def cmd_profil(msg: Message):
    uid = msg.from_user.id
    st  = db_user_stats(uid)
    await msg.answer(
        f"👤 <b>Profil</b>\n\n"
        f"🆔 ID: <code>{uid}</code>\n"
        f"📛 Ism: {msg.from_user.first_name}\n"
        f"🌐 Til: {db_get_lang(uid).upper()}\n\n"
        f"📊 Jami scanlar: <b>{st.get('total') or 0}</b>\n"
        f"  ⛔ Zararli:   <b>{st.get('malicious') or 0}</b>\n"
        f"  ⚠️ Shubhali: <b>{st.get('suspicious') or 0}</b>\n"
        f"  ✅ Xavfsiz:  <b>{st.get('clean') or 0}</b>"
    )

# ── Rejim tanlash ─────────────────────────────────────────
@router.message(F.text.in_(ALL_FILE_BTNS))
async def mode_file(msg: Message, state: FSMContext):
    uid = msg.from_user.id
    await state.set_state(S.file)
    await msg.answer(tr(uid, "send_file", mb=MAX_FILE_MB))

@router.message(F.text.in_(ALL_HASH_BTNS))
async def mode_hash(msg: Message, state: FSMContext):
    uid = msg.from_user.id
    await state.set_state(S.hash_)
    await msg.answer(tr(uid, "send_hash"))

@router.message(F.text.in_(ALL_URL_BTNS))
async def mode_url(msg: Message, state: FSMContext):
    uid = msg.from_user.id
    await state.set_state(S.url)
    await msg.answer(tr(uid, "send_url"))

# ── /hash buyrug'i ────────────────────────────────────────
@router.message(Command("hash"))
async def cmd_hash_direct(msg: Message, state: FSMContext):
    if not await _guard(msg): return
    uid   = msg.from_user.id
    parts = (msg.text or "").split(maxsplit=1)
    if len(parts) < 2:
        await state.set_state(S.hash_)
        await msg.answer(tr(uid, "send_hash"))
        return
    await _do_hash(msg, parts[1].strip().lower(), state)

@router.message(S.hash_)
async def input_hash(msg: Message, state: FSMContext):
    if not await _guard(msg): return
    await _do_hash(msg, (msg.text or "").strip().lower(), state)

async def _do_hash(msg: Message, h: str, state: FSMContext):
    uid = msg.from_user.id
    if not all(c in "0123456789abcdef" for c in h):
        await msg.answer(tr(uid, "hash_hex_err"))
        return
    if len(h) not in (32, 40, 64):
        await msg.answer(tr(uid, "hash_len_err", n=len(h)))
        return
    st = await msg.answer(tr(uid, "vt_searching"))
    vt = await vt_hash(h)
    await st.edit_text(report_hash(h, vt, uid))
    verdict = (
        "malicious"  if vt.get("malicious",  0) > 0 else
        "suspicious" if vt.get("suspicious", 0) > 3 else
        "clean"
    )
    db_save_scan(uid, "hash", h, verdict,
                 vt_malicious=vt.get("malicious", 0),
                 vt_total=vt.get("total", 0))
    await state.clear()

# ── /url buyrug'i ─────────────────────────────────────────
@router.message(Command("url"))
async def cmd_url_direct(msg: Message, state: FSMContext):
    if not await _guard(msg): return
    uid   = msg.from_user.id
    parts = (msg.text or "").split(maxsplit=1)
    if len(parts) < 2:
        await state.set_state(S.url)
        await msg.answer(tr(uid, "send_url"))
        return
    await _do_url(msg, parts[1].strip(), state)

@router.message(S.url)
async def input_url(msg: Message, state: FSMContext):
    if not await _guard(msg): return
    await _do_url(msg, (msg.text or "").strip(), state)

async def _do_url(msg: Message, url: str, state: FSMContext):
    uid = msg.from_user.id
    if not re.match(r"https?://", url, re.I):
        await msg.answer(tr(uid, "url_scheme_err"))
        return
    if len(url) > 2048:
        await msg.answer(tr(uid, "url_long_err"))
        return
    st = await msg.answer(tr(uid, "url_analyzing"))
    try:
        res     = await full_url_analysis(url)
        text    = report_url(res, uid)
        verdict = res["verdict"]
        await st.edit_text(text, reply_markup=kb_vt_url(url, verdict, uid))
        db_save_scan(uid, "url", url, verdict, res["score"],
                     vt_malicious=res["vt"].get("malicious", 0),
                     vt_total=res["vt"].get("total", 0))
    except Exception as e:
        log.exception("URL tahlil xatosi")
        await st.edit_text(tr(uid, "error", err=str(e)[:100]))
    await state.clear()

# ── Fayl handler ──────────────────────────────────────────
@router.message(F.document)
async def handle_file(msg: Message, bot: Bot, state: FSMContext):
    if not await _guard(msg): return
    uid = msg.from_user.id
    doc = msg.document
    if doc.file_size and doc.file_size > MAX_FILE_BYTES:
        await msg.answer(tr(uid, "file_big_err", mb=MAX_FILE_MB, size=_fmt_sz(doc.file_size)))
        return
    st = await msg.answer(tr(uid, "file_analyzing"))
    try:
        fo     = await bot.get_file(doc.file_id)
        buf    = io.BytesIO()
        await bot.download_file(fo.file_path, destination=buf)
        data   = buf.getvalue()
        fname  = doc.file_name or "unknown"
        hashes = compute_hashes(data)
        h_res  = analyze_file(data, fname)

        await st.edit_text(tr(uid, "file_heuristic"))

        vt_res        = await vt_file(data, fname)
        text, verdict = report_file(fname, doc.file_size or len(data), hashes, h_res, vt_res, uid)

        await st.edit_text(text, reply_markup=kb_vt_file(hashes["sha256"], verdict, uid))
        db_save_scan(uid, "file", fname, verdict,
                     h_res["score"], h_res["entropy"], hashes["sha256"],
                     vt_res.get("malicious", 0) if vt_res else 0,
                     vt_res.get("total",     0) if vt_res else 0)
    except Exception as e:
        log.exception("Fayl tahlil xatosi")
        await st.edit_text(tr(uid, "error", err=str(e)[:100]))
    await state.clear()

# ── Matnda URL avtoaniq ───────────────────────────────────
@router.message(F.text & ~F.text.startswith("/"))
async def catch_text(msg: Message, state: FSMContext):
    if await state.get_state(): return
    m = _URL_RE.search(msg.text or "")
    if not m: return
    if not await _guard(msg): return
    uid = msg.from_user.id
    url = m.group()
    st  = await msg.answer(tr(uid, "url_detected", url=url[:60]))
    try:
        res     = await full_url_analysis(url)
        text    = report_url(res, uid)
        verdict = res["verdict"]
        await st.edit_text(text, reply_markup=kb_vt_url(url, verdict, uid))
        db_save_scan(uid, "url", url, verdict, res["score"],
                     vt_malicious=res["vt"].get("malicious", 0),
                     vt_total=res["vt"].get("total", 0))
    except Exception as e:
        log.exception("Auto URL xatosi")
        await st.edit_text(tr(uid, "error", err=str(e)[:100]))

# ───────────────────────────────────────────────────────────
#  ADMIN PANEL
# ───────────────────────────────────────────────────────────
def _admin(func):
    @wraps(func)
    async def wrapper(msg: Message, *a, **kw):
        if msg.from_user.id not in ADMIN_IDS:
            await msg.answer(tr(msg.from_user.id, "admin_cmd"))
            return
        return await func(msg, *a, **kw)
    return wrapper

@router.message(Command("admin"))
@_admin
async def cmd_admin(msg: Message):
    await msg.answer("🔧 <b>Admin Panel</b>", reply_markup=kb_admin())

@router.callback_query(F.data == "adm_stats")
async def adm_stats(call: CallbackQuery):
    if call.from_user.id not in ADMIN_IDS:
        await call.answer(tr(call.from_user.id, "no_perm"), show_alert=True)
        return
    st   = db_global_stats()
    text = (
        f"📊 <b>Statistika</b>\n\n"
        f"👤 Ro'yxatdagi foydalanuvchilar: <b>{st.get('registered', 0)}</b>\n"
        f"🔬 Jami scanlar:                 <b>{st.get('scans', 0)}</b>\n"
        f"⛔ Zararli topilgan:             <b>{st.get('malicious', 0)}</b>"
    )
    # TelegramBadRequest tuzatildi: try/except qo'shildi
    try:
        await call.message.edit_text(text, reply_markup=kb_admin())
    except Exception:
        pass
    await call.answer()

@router.callback_query(F.data == "adm_recent")
async def adm_recent(call: CallbackQuery):
    if call.from_user.id not in ADMIN_IDS:
        await call.answer(tr(call.from_user.id, "no_perm"), show_alert=True)
        return
    rows = db_recent_scans(8)
    if not rows:
        text = "📋 Hali scan yo'q."
    else:
        lines = ["📋 <b>So'nggi 8 scan:</b>\n"]
        for r in rows:
            em  = _VE.get(r["verdict"], "❓")
            tg  = f"@{r['username']}" if r.get("username") else f"id:{r['user_id']}"
            lines.append(
                f"{em} <code>{(r['target'] or '')[:25]}</code>\n"
                f"   {tg} • {r['scan_type']} • {r['created_at'][:16]}"
            )
        text = "\n".join(lines)
    # TelegramBadRequest tuzatildi: try/except qo'shildi
    try:
        await call.message.edit_text(text, reply_markup=kb_admin())
    except Exception:
        pass
    await call.answer()

@router.callback_query(F.data == "adm_ban")
async def adm_ban_ask(call: CallbackQuery, state: FSMContext):
    if call.from_user.id not in ADMIN_IDS:
        await call.answer(tr(call.from_user.id, "no_perm"), show_alert=True)
        return
    await state.set_state(S.adm_ban)
    await call.message.answer(tr(call.from_user.id, "ban_ask"))
    await call.answer()

@router.callback_query(F.data == "adm_unban")
async def adm_unban_ask(call: CallbackQuery, state: FSMContext):
    if call.from_user.id not in ADMIN_IDS:
        await call.answer(tr(call.from_user.id, "no_perm"), show_alert=True)
        return
    await state.set_state(S.adm_unban)
    await call.message.answer(tr(call.from_user.id, "unban_ask"))
    await call.answer()

@router.message(S.adm_ban)
async def adm_do_ban(msg: Message, state: FSMContext):
    if msg.from_user.id not in ADMIN_IDS: return
    uid = msg.from_user.id
    try:
        target = int(msg.text.strip())
        db_set_ban(target, True)
        await msg.answer(tr(uid, "banned_ok", uid=target))
    except ValueError:
        await msg.answer(tr(uid, "id_err"))
    await state.clear()

@router.message(S.adm_unban)
async def adm_do_unban(msg: Message, state: FSMContext):
    if msg.from_user.id not in ADMIN_IDS: return
    uid = msg.from_user.id
    try:
        target = int(msg.text.strip())
        db_set_ban(target, False)
        await msg.answer(tr(uid, "unbanned_ok", uid=target))
    except ValueError:
        await msg.answer(tr(uid, "id_err"))
    await state.clear()

# ───────────────────────────────────────────────────────────
#  MAIN
# ───────────────────────────────────────────────────────────
async def main():
    db_init()
    bot = Bot(
        token=BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML)
    )
    dp = Dispatcher(storage=MemoryStorage())
    dp.include_router(router)

    log.info("🛡  MalwareGuard PRO v3.2 ishga tushdi")
    log.info("🧬  YARA:                 %s", "✅ 6 qoida" if YARA_OK    else "⚠️  o'rnatilmagan")
    log.info("🌐  VirusTotal:           %s", "✅ Faol"    if VT_API_KEY  else "⚠️  sozlanmagan")
    log.info("🔍  Google Safe Browsing: %s", "✅ Faol"    if GSB_KEY     else "⚠️  sozlanmagan")
    log.info("🖥   URLScan.io:          %s", "✅ Faol"    if URLSCAN_KEY else "⚠️  sozlanmagan")
    log.info("🌍  Tillar:               O'zbek • Русский • English")
    log.info("📖  Guide URL:            %s", GUIDE_URL)
    log.info("👮  Admin ID lar:         %s", ADMIN_IDS or "—")

    await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())

if __name__ == "__main__":
    asyncio.run(main())
