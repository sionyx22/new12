# -*- coding: utf-8 -*-
"""
PC Cleaner - ניקוי חכם של מחשבים (Windows)

סורק, ממליץ (🟢 מומלץ למחוק / 🟡 לבדיקה / 🔴 מומלץ לשמור) ומבצע רק את מה שנשאר מסומן.
שום דבר לא נעול: הכל ניתן לשינוי. מילות הגנה, פרויקטים וקבצים עדכניים רק מסומנים 🔴 ולא נבחרים מראש.
"""
import ctypes
import glob
import json
import math
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import threading
import time
import traceback
import tkinter as tk
from tkinter import messagebox, ttk

try:
    import winreg
except ImportError:  # לא Windows
    winreg = None

APP_NAME = "PC Cleaner"
VERSION = "8.3"
MAX_ITEMS_PER_CATEGORY = 3000
SYSTEM_DRIVE = os.environ.get("SystemDrive", "C:") + "\\"
WINDIR = os.environ.get("SystemRoot", r"C:\Windows")
PROGRAMDATA = os.environ.get("ProgramData", r"C:\ProgramData")
USERS = os.path.join(SYSTEM_DRIVE, "Users")
RECYCLE = "__recycle__"
UNINSTALL = "UNINSTALL::"

# ---------- צבעים ----------
BG, HEADER, ACCENT = "#f1f5f9", "#0f172a", "#2563eb"
RED, GREEN, AMBER = "#dc2626", "#16a34a", "#d97706"
ROW_DEL, ROW_KEEP, ROW_WARN = "#fff1f2", "#f0fdf4", "#fde68a"
REC_ICON = {"green": "🟢", "yellow": "🟡", "red": "🔴"}
REC_ORDER = {"red": 0, "yellow": 1, "green": 2}
FILTERS = ["הכל", "🟢 מומלץ למחוק", "🟡 לבדיקה", "🔴 מומלץ לשמור", "מסומנים בלבד", "לא מסומנים"]

# ---------- הגדרות הגנה ----------
DEFAULT_KEYWORDS = [
    "קסיוק", "קיסיוק", "kasyuk", "kasiuk", "kasiok", "casiok", "kasyok",
    "וידאוף", "videoff", "videooff", "video off", "video-off",
    "sionyx", "kiosk", "קיוסק", "contentblocker", "content blocker",
]
CONFIG_FILES = [
    os.path.join(PROGRAMDATA, "PCCleaner", "protect.txt"),
    os.path.join(os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__)),
                 "protect.txt"),
]
GENERIC_TOKENS = {"microsoft", "windows", "corporation", "software", "program", "programs",
                  "application", "common", "files", "systems", "technologies", "intel", "nvidia",
                  "amd", "realtek", "driver", "drivers"}
MS_ONLY_WORDS = ["microsoft", "windows", "visual c++", ".net", "webview2"]
SYSTEM_WORDS = ["driver", "intel", "nvidia", "amd ", "realtek", "synaptics", "bluetooth", "chipset",
                "audio", "wifi", "wi-fi", "touchpad", "firmware", "pc cleaner", "pccleaner",
                "laserjet", "deskjet", "officejet", "brother", "mfl-pro", "printer", "epson", "canon",
                "lexmark", "ricoh", "kyocera", "xerox", "מדפסת", "התקן בסיסי",
                "wireless adapter", "broadband", "npcap", "openal"]
ALL_SYSTEM_WORDS = SYSTEM_WORDS + MS_ONLY_WORDS
REMOTE_WORDS = ["teamviewer", "anydesk", "vnc", "mesh agent", "meshagent", "rustdesk", "ultraviewer",
                "radmin", "supremo", "ammyy", "remote", "rdp", "no-ip", "noip", "splashtop", "chrome remote",
                "parsec", "getscreen", "tailscale", "zerotier", "hamachi", "logmein", "anydesk", "iperius", "mesh"]


def norm_tok(s):
    """נרמול להשוואה: אותיות קטנות, בלי רווחים/קווים/סלאשים."""
    return re.sub(r"[\s_\-\.\\/:]+", "", str(s).lower())


_OUT_DIR = None


def out_dir():
    """תיקיית הפלט (לוגים ודוחות): C:\\Users\\Public\\Documents\\PCCleaner - נגישה לכל משתמש. גיבוי: ProgramData."""
    global _OUT_DIR
    if _OUT_DIR:
        return _OUT_DIR
    for d in (os.path.join(USERS, "Public", "Documents", "PCCleaner"), os.path.join(PROGRAMDATA, "PCCleaner")):
        try:
            os.makedirs(os.path.join(d, "Logs"), exist_ok=True)
            os.makedirs(os.path.join(d, "Reports"), exist_ok=True)
            probe = os.path.join(d, "Logs", ".write-test")
            with open(probe, "w"):
                pass
            os.remove(probe)
            _OUT_DIR = d
            return d
        except OSError:
            continue
    _OUT_DIR = os.path.join(PROGRAMDATA, "PCCleaner")
    return _OUT_DIR


def log_dir():
    return os.path.join(out_dir(), "Logs")


def log(msg):
    """יומן פעולות: כל סריקה, מחיקה, העברה, הסרה והשבתה (והצלחה/כשלון)."""
    try:
        with open(os.path.join(log_dir(), time.strftime("pccleaner-%Y%m%d.log")), "a", encoding="utf-8") as f:
            f.write(time.strftime("%H:%M:%S  ") + str(msg) + "\n")
    except OSError:
        pass


def log_exc(where):
    log(f"ERROR ({where}):\n" + traceback.format_exc())


def _excepthook(et, ev, tb):
    log("UNCAUGHT:\n" + "".join(traceback.format_exception(et, ev, tb)))


sys.excepthook = _excepthook
threading.excepthook = lambda a: _excepthook(a.exc_type, a.exc_value, a.exc_traceback)


def redact(s):
    """מסתיר טוקנים וסודות מפקודות לפני שהן מוצגות או נכנסות לדוח."""
    s = re.sub(r"(--?token[=\s]+)\S+", r"\1<redacted>", str(s), flags=re.I)
    return re.sub(r"[A-Za-z0-9_\-+/=]{40,}", "<redacted>", s)


def load_keywords():
    for f in CONFIG_FILES:
        try:
            with open(f, encoding="utf-8") as fh:
                words = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
                if words:
                    return words
        except OSError:
            pass
    return []


def save_keywords(words):
    text = "# מילות הגנה - שורה לכל מילה. כל תוכנה/תיקייה/קובץ שהשם שלהם מכיל אחת מהמילים לא יימחקו.\n"
    text += "\n".join(words) + "\n"
    for f in CONFIG_FILES:
        try:
            os.makedirs(os.path.dirname(f), exist_ok=True)
            with open(f, "w", encoding="utf-8") as fh:
                fh.write(text)
            return True
        except OSError:
            continue
    return False


KEYWORDS = load_keywords()


def keyword_tokens():
    allw = list(DEFAULT_KEYWORDS) + list(KEYWORDS) + list(PROFILE["keywords"])   # מובנות + אישיות + פרופיל
    return {norm_tok(w) for w in allw if len(norm_tok(w)) >= 3}


def path_protected(path, tokens):
    n = norm_tok(path)
    return any(t in n for t in tokens)


# ---------- קטגוריות ----------
def U(*parts):
    return os.path.join(USERS, "*", *parts)


# שם, תיאור, תבניות, expand, גיל מינימלי בימים, ברירת מחדל מסומן
CATEGORIES = [
    ("קבצים זמניים של משתמשים", "Temp של כל המשתמשים",
     [U("AppData", "Local", "Temp")], True, 0, True),
    ("קבצים זמניים של Windows", "Windows\\Temp",
     [os.path.join(WINDIR, "Temp")], True, 0, True),
    ("מטמון עדכוני Windows", "קבצי עדכון שהורדו",
     [os.path.join(WINDIR, "SoftwareDistribution", "Download")], True, 0, True),
    ("מטמון Chrome / Edge", "מטמון דפדפנים",
     [U("AppData", "Local", "Google", "Chrome", "User Data", "*", "Cache", "Cache_Data"),
      U("AppData", "Local", "Google", "Chrome", "User Data", "*", "Code Cache"),
      U("AppData", "Local", "Google", "Chrome", "User Data", "*", "GPUCache"),
      U("AppData", "Local", "Microsoft", "Edge", "User Data", "*", "Cache", "Cache_Data"),
      U("AppData", "Local", "Microsoft", "Edge", "User Data", "*", "Code Cache"),
      U("AppData", "Local", "Microsoft", "Edge", "User Data", "*", "GPUCache")], False, 0, True),
    ("מטמון Firefox", "מטמון Firefox",
     [U("AppData", "Local", "Mozilla", "Firefox", "Profiles", "*", "cache2")], False, 0, True),
    ("תמונות ממוזערות", "מטמון תצוגה מקדימה",
     [U("AppData", "Local", "Microsoft", "Windows", "Explorer", "thumbcache_*.db")], False, 0, True),
    ("דוחות שגיאה ו-Dump", "דוחות קריסה ולוגי מערכת",
     [os.path.join(PROGRAMDATA, "Microsoft", "Windows", "WER", "ReportQueue"),
      os.path.join(PROGRAMDATA, "Microsoft", "Windows", "WER", "ReportArchive"),
      os.path.join(WINDIR, "Minidump"), os.path.join(WINDIR, "MEMORY.DMP"),
      os.path.join(WINDIR, "Logs", "CBS", "*.log")], True, 0, True),
    ("Prefetch", "האצת הפעלה (נבנה מחדש לבד)",
     [os.path.join(WINDIR, "Prefetch")], True, 0, False),
    ("שולחן עבודה", "קבצים אישיים - Desktop",
     [U("Desktop")], True, 0, True),
    ("מסמכים (כולל ציבוריים)", "קבצים אישיים - Documents",
     [U("Documents")], True, 0, True),
    ("הורדות", "קבצים אישיים - Downloads",
     [U("Downloads")], True, 0, True),
    ("תמונות / סרטים / מוזיקה", "Pictures, Videos, Music",
     [U("Pictures"), U("Videos"), U("Music")], True, 0, True),
    ("נתוני דפדפנים", "סימניות, היסטוריה, סיסמאות ופרופילים",
     [U("AppData", "Local", "Google", "Chrome", "User Data"),
      U("AppData", "Local", "Microsoft", "Edge", "User Data"),
      U("AppData", "Roaming", "Mozilla", "Firefox", "Profiles")], True, 0, True),
]
PROG_CI = len(CATEGORIES)
RECYCLE_CI = PROG_CI + 1
PROG_INFO = {}


# ---------- עזר ----------
def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def is_reparse(path):
    try:
        st = os.lstat(path)
        return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & 0x400)
    except OSError:
        return False


def fmt_size(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def ltr(s):
    return "\u202a" + s + "\u202c"


def path_size(path):
    try:
        if is_reparse(path):
            return 0
        if os.path.isfile(path):
            return os.path.getsize(path)
        total, stack = 0, [path]
        while stack:
            cur = stack.pop()
            try:
                with os.scandir(cur) as it:
                    for e in it:
                        try:
                            if e.is_symlink() or is_reparse(e.path):
                                continue
                            if e.is_dir(follow_symlinks=False):
                                stack.append(e.path)
                            else:
                                total += e.stat(follow_symlinks=False).st_size
                        except OSError:
                            pass
            except OSError:
                pass
        return total
    except OSError:
        return 0


def recycle_bin_size():
    class Q(ctypes.Structure):
        _fields_ = [("cbSize", ctypes.c_ulong), ("i64Size", ctypes.c_longlong),
                    ("i64NumItems", ctypes.c_longlong)]
    try:
        q = Q()
        q.cbSize = ctypes.sizeof(q)
        ctypes.windll.shell32.SHQueryRecycleBinW(None, ctypes.byref(q))
        return q.i64Size
    except Exception:
        return 0


def empty_recycle_bin():
    try:
        ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 0x7)
        return True
    except Exception:
        return False


def _norm_path(p):
    return os.path.normcase(os.path.abspath(p))


SELF_PATHS = [_norm_path(x) for x in (sys.executable if getattr(sys, "frozen", False) else __file__,
                                      getattr(sys, "_MEIPASS", None)) if x]


def contains_self(p):
    pn = _norm_path(p)
    return any(s == pn or s.startswith(pn + os.sep) or pn.startswith(s + os.sep) for s in SELF_PATHS)


def is_own_data(path):
    p = _norm_path(path)
    own = _norm_path(os.path.join(USERS, "Public", "Documents", "PCCleaner"))
    return p == own or p.startswith(own + os.sep)


def is_safe_to_delete(path):
    if is_own_data(path):
        return False
    p = _norm_path(path)
    if len(p) <= 3 or p.rstrip("\\") == _norm_path(WINDIR).rstrip("\\"):
        return False
    allowed = [_norm_path(USERS), _norm_path(WINDIR), _norm_path(PROGRAMDATA)]
    return any(p.startswith(a + os.sep) for a in allowed)


def _on_rm_error(func, path, exc_info):
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


def delete_path(path):
    if not is_safe_to_delete(path) or contains_self(path):
        return False
    try:
        if is_reparse(path):
            os.rmdir(path) if os.path.isdir(path) else os.unlink(path)
        elif os.path.isdir(path):
            shutil.rmtree(path, onerror=_on_rm_error)
        else:
            try:
                os.chmod(path, stat.S_IWRITE)
            except OSError:
                pass
            os.unlink(path)
    except OSError:
        pass
    return not os.path.exists(path)


# ---------- תוכנות מותקנות ----------
def _val(k, name):
    try:
        return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


def clean_publisher(p):
    p = re.sub(r"\b(inc|ltd|llc|corp|corporation|co|gmbh|ltd\.|inc\.)\b\.?", "", str(p or ""), flags=re.I)
    return norm_tok(p)


def prog_tokens(info):
    """מילים שמייצגות תוכנה, כדי להגן על התיקיות והלוגים שלה."""
    toks = set()
    n = norm_tok(info["name"])
    if len(n) >= 4:
        toks.add(n)
    loc = info.get("loc") or ""
    if loc:
        parts = [x for x in re.split(r"[\\/]+", loc) if x]
        base = None
        for i, pt in enumerate(parts):
            if pt.lower().startswith("program files") and i + 1 < len(parts):
                base = parts[i + 1]
                break
        if base is None and parts:
            base = parts[-1]
        b = norm_tok(base or "")
        if len(b) >= 4 and b not in GENERIC_TOKENS and b not in ("application", "bin", "app", "x64", "x86"):
            toks.add(b)
    pub = clean_publisher(info.get("publisher"))
    if len(pub) >= 4 and pub not in GENERIC_TOKENS:
        toks.add(pub)
    return toks


PROG_RULES = [
    (("deep freeze", "faronics"), "red", "הקפאת מחשב - אסור להסיר בלי תכנון"),
    (("smart identification", "כרטיס חכם", "smart card"), "yellow", "זיהוי ממשלתי / כרטיס חכם - ייתכן שנדרש לאתרי ממשלה"),
    (("ravkavonline", "rav-kav", "pcentra"), "yellow", "טעינת רב-קו - בדוק אם משתמשים"),
    (("papercut", "print logger"), "yellow", "רישום הדפסות - ייתכן שנדרש לחיוב או בקרה"),
    (("netiq",), "yellow", "NetIQ - בדוק אם קשור לניהול החדר"),
    (("python", "visual studio code", "node.js", "notepad++", "pycharm", "git for windows"), "yellow",
     "כלי פיתוח - ודא שאינך צריך אותו במחשב הזה"),
    (("google chrome", "mozilla firefox", "brave", "opera"), "yellow", "דפדפן - ודא שנשאר דפדפן אחר"),
    (("7-zip", "winrar", "vlc media player"), "yellow", "כלי עזר נפוץ - בדוק אם משתמשים בו"),
]


def is_system_program(name, publisher):
    """מערכת/דרייבר. מילים כמו Windows נחשבות רק אם התוכנה של Microsoft (Windows Movie Maker אינה)."""
    low, pub = (name or "").lower(), (publisher or "").lower()
    if any(w in low for w in SYSTEM_WORDS):
        return True
    if "microsoft" in pub or "microsoft" in low:
        return True
    return any(w in low for w in (".net", "visual c++", "webview2"))


def classify_program(info):
    """מחזיר (רמת המלצה, סיבה, מסומן כברירת מחדל) לתוכנה מותקנת."""
    low = (info["name"] + " " + info["publisher"]).lower()
    if info["guard"]:
        return "red", f"מילת הגנה: {info['why']}", False
    for words, rec, reason in PROG_RULES:
        if any(w in low for w in words):
            return rec, reason, rec == "green"
    if info["remote"]:
        return "red", "כלי ניהול מרחוק", False
    if info["system"]:
        return "red", "מערכת / דרייבר", False
    if "repack" in low:
        return "green", "גרסת Repack לא רשמית - מומלץ להסיר", True
    return "green", "תוכנה רגילה של צד שלישי", True


def list_programs():
    progs = {}
    if winreg is None:
        return progs
    sub = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    roots = [(winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY),
             (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY),
             (winreg.HKEY_CURRENT_USER, 0)]
    seen, kw = set(), keyword_tokens()
    for hive, flag in roots:
        try:
            key = winreg.OpenKey(hive, sub, 0, winreg.KEY_READ | flag)
        except OSError:
            continue
        i = 0
        while True:
            try:
                name = winreg.EnumKey(key, i)
            except OSError:
                break
            i += 1
            try:
                k = winreg.OpenKey(key, name)
            except OSError:
                continue
            dn = _val(k, "DisplayName")
            cmd = _val(k, "QuietUninstallString") or _val(k, "UninstallString")
            if not dn or not cmd or _val(k, "SystemComponent") == 1 or _val(k, "ParentKeyName"):
                continue
            if str(_val(k, "ReleaseType") or "") in ("Update", "Hotfix", "Security Update"):
                continue
            ident = (dn, str(_val(k, "DisplayVersion")))
            if ident in seen:
                continue
            seen.add(ident)
            info = {"name": dn, "publisher": _val(k, "Publisher") or "", "cmd": cmd,
                    "ver": str(_val(k, "DisplayVersion") or ""),
                    "loc": _val(k, "InstallLocation") or "",
                    "quiet": bool(_val(k, "QuietUninstallString")),
                    "size": int(_val(k, "EstimatedSize") or 0) * 1024}
            blob = norm_tok(dn + info["publisher"] + info["loc"])
            info["guard"] = any(t in blob for t in kw)           # מילת הגנה
            info["why"] = next((t for t in kw if t in blob), "")
            low = dn.lower()
            info["system"] = is_system_program(dn, info["publisher"])   # מערכת/דרייבר
            info["remote"] = any(w in low for w in REMOTE_WORDS)        # כלי ניהול מרחוק
            info["rec"], info["reason"], info["default"] = classify_program(info)
            progs[str(len(progs))] = info
    return progs


def uninstall_program(info):
    cmd, low = info["cmd"], info["cmd"].lower()
    if "msiexec" in low:
        cmd = re.sub(r"/I", "/X", cmd, flags=re.I)
        if "/qn" not in low and "/quiet" not in low:
            cmd += " /qn /norestart"
    elif not info["quiet"] and "unins" in low:
        cmd += " /VERYSILENT /NORESTART"
    try:
        r = subprocess.run(cmd, shell=True, timeout=900, stdin=subprocess.DEVNULL)
        return r.returncode in (0, 1641, 3010)
    except Exception:
        return False


# ---------- ביצועים: הפעלה אוטומטית, משימות מתוזמנות ושירותים ----------
STARTUP_CI = RECYCLE_CI + 1
TASK_CI = RECYCLE_CI + 2
SERVICE_CI = RECYCLE_CI + 3
PERF_CIS = (STARTUP_CI, TASK_CI, SERVICE_CI)
PERF_INFO = {}
PERF_PREFIX = {"startup": "STARTUP::", "startupfile": "STARTUP::", "task": "TASK::", "service": "SERVICE::"}
CHANGES_FILE = os.path.join(PROGRAMDATA, "PCCleaner", "changes.json")
UPDATER_WORDS = ["update", "updater", "telemetry", "feedback", "crashreport", "crash report",
                 "customer experience", "helper"]
NO_WINDOW = 0x08000000
DISABLED_BYTES = bytes([3, 0, 0, 0]) + bytes(8)
ENABLED_BYTES = bytes([2, 0, 0, 0]) + bytes(8)
APPROVED_BASE = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"
RUN_SUB = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"


KIND_ORDER = {"junk": 0, "personal": 1, "prog": 2, "perf": 3}


def cat_title(ci):
    return {
        RECYCLE_CI: "סל המחזור",
        PROG_CI: "תוכנות מותקנות",
        STARTUP_CI: "הפעלה אוטומטית עם Windows",
        TASK_CI: "משימות מתוזמנות של צד שלישי",
        SERVICE_CI: "שירותים של צד שלישי",
    }.get(ci) or CATEGORIES[ci][0]


def cat_kind(ci):
    """junk = נמחק ישירות, personal = קבצים אישיים (כספת), prog = הסרת תוכנה, perf = השבתה הפיכה."""
    if ci == PROG_CI:
        return "prog"
    if ci in PERF_CIS:
        return "perf"
    if ci == RECYCLE_CI:
        return "junk"
    n = CATEGORIES[ci][0]
    return "personal" if (n in PERSONAL_CATS or n == "נתוני דפדפנים") else "junk"


def cat_section_label(ci, vault=True):
    tag = {"junk": "🧹 נמחק ישירות",
           "personal": "👤 עובר לכספת" if vault else "👤 נמחק לצמיתות",
           "prog": "📦 הסרת תוכנה (בלתי הפיך)",
           "perf": "⚡ השבתה (הפיך)"}[cat_kind(ci)]
    return f"{tag}  |  {cat_title(ci)}"


def run_ps(cmd, timeout=60):
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
             "[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + cmd],
            capture_output=True, timeout=timeout, creationflags=NO_WINDOW, stdin=subprocess.DEVNULL)
        return r.returncode, r.stdout.decode("utf-8", "replace")
    except Exception:
        return 1, ""


def parse_ps_json(text):
    text = (text or "").strip().lstrip("\ufeff")
    if not text:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if isinstance(data, dict):
        return [data]
    return [d for d in data if isinstance(d, dict)] if isinstance(data, list) else []


PERF_RULES = [
    (("dfserv", "faronics", "deep freeze"), "red", "הקפאת מחשב (Deep Freeze)"),
    (("papercut", "pcprintlogger", "pcpl.exe"), "yellow", "רישום הדפסות - ייתכן שנדרש לחיוב או בקרה"),
    (("netiq", "deviceservice"), "yellow", "NetIQ - בדוק אם קשור לניהול החדר"),
    (("wifree", "netfree"), "yellow", "סינון NetFree - בדוק לפני השבתה"),
]


def classify_perf(info, low, updater):
    """מחזיר (רמת המלצה, סיבה, מסומן כברירת מחדל) לפריט הפעלה / משימה / שירות."""
    if info["guard"]:
        return "red", f"מילת הגנה: {info['why']}", False
    for words, rec, reason in PERF_RULES:
        if any(w in low for w in words):
            return rec, reason, False
    if info["remote"]:
        return "red", "כלי ניהול מרחוק", False
    if info["system"]:
        return "red", "מערכת / דרייבר", False
    if info["kind"] in ("startup", "startupfile"):
        return "green", "תוכנית שעולה עם Windows - השבתה הפיכה", True
    if updater:
        return "green", "עדכון / טלמטריה - השבתה הפיכה", True
    return "yellow", "צד שלישי - בדוק לפני השבתה", False


def perf_finalize(info):
    """מסווג פריט ביצועים: המלצה, סיבה וברירת מחדל."""
    # קובץ בתיקיית Startup: מסווגים לפי שם הקובץ בלבד (הנתיב תמיד מכיל Microsoft\Windows)
    raw = info["name"] if info["kind"] == "startupfile" else f"{info['name']} {info['cmd']}"
    low, nb, kw = raw.lower(), norm_tok(raw), keyword_tokens()
    info["blob"] = raw
    info["guard"] = any(t in nb for t in kw)
    info["why"] = next((t for t in kw if t in nb), "")
    info["system"] = any(w in low for w in ALL_SYSTEM_WORDS)
    info["remote"] = any(w in low for w in REMOTE_WORDS)
    updater = any(w in low for w in UPDATER_WORDS)
    info["rec"], info["reason"], info["default"] = classify_perf(info, low, updater)
    info["label"] = redact(info.get("label", ""))
    info["cmd_safe"] = redact(info["cmd"])
    return info


def _sid_list():
    sids, i = [], 0
    if winreg is None:
        return sids
    while True:
        try:
            sid = winreg.EnumKey(winreg.HKEY_USERS, i)
        except OSError:
            break
        i += 1
        if sid.startswith("S-1-5-21") and not sid.endswith("_Classes"):
            sids.append(sid)
    return sids


def list_startup():
    out = []
    if winreg is None:
        return out
    sources = [
        (winreg.HKEY_LOCAL_MACHINE, "HKLM", RUN_SUB, winreg.KEY_WOW64_64KEY, APPROVED_BASE + "\\Run", "כל המשתמשים"),
        (winreg.HKEY_LOCAL_MACHINE, "HKLM", RUN_SUB, winreg.KEY_WOW64_32KEY, APPROVED_BASE + "\\Run32", "כל המשתמשים"),
    ]
    for sid in _sid_list():
        sources.append((winreg.HKEY_USERS, "HKU", sid + "\\" + RUN_SUB, 0,
                        sid + "\\" + APPROVED_BASE + "\\Run", "משתמש"))
    for hive, hname, sub, flag, approved, scope in sources:
        try:
            key = winreg.OpenKey(hive, sub, 0, winreg.KEY_READ | flag)
        except OSError:
            continue
        try:
            akey = winreg.OpenKey(hive, approved, 0, winreg.KEY_READ)
        except OSError:
            akey = None
        i = 0
        while True:
            try:
                name, data, _t = winreg.EnumValue(key, i)
            except OSError:
                break
            i += 1
            if not name:
                continue
            if akey:
                try:
                    b = winreg.QueryValueEx(akey, name)[0]
                    if b and (b[0] & 1):          # כבר מושבת
                        continue
                except OSError:
                    pass
            cmd = str(data)
            out.append(perf_finalize({"kind": "startup", "name": name, "cmd": cmd, "hive": hname,
                                      "approved": approved,
                                      "label": f"{name}  ({scope})   →   {cmd[:100]}"}))
    return out


def list_startup_folders():
    out = []
    pats = [os.path.join(USERS, "*", "AppData", "Roaming", "Microsoft", "Windows", "Start Menu",
                         "Programs", "Startup", "*"),
            os.path.join(PROGRAMDATA, "Microsoft", "Windows", "Start Menu", "Programs", "StartUp", "*")]
    for pat in pats:
        for f in glob.glob(pat):
            if os.path.basename(f).lower() == "desktop.ini":
                continue
            out.append(perf_finalize({"kind": "startupfile", "name": os.path.basename(f), "cmd": f,
                                      "label": f"{os.path.basename(f)}  (תיקיית Startup)   →   {f}"}))
    return out


_TASK_SUFFIX = re.compile(r"[-\s]+S-1-5-21-[\d-]+.*$|\s*\{[0-9A-Fa-f-]{36}\}.*$")


def list_tasks():
    ps = (r"Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' } | "
          r"ForEach-Object { $a = $_.Actions | Select-Object -First 1; "
          r"[pscustomobject]@{P=$_.TaskPath;N=$_.TaskName;E=$a.Execute;A=$a.Arguments} } | ConvertTo-Json -Compress")
    rc, out = run_ps(ps, 90)
    groups = {}
    for d in parse_ps_json(out):
        name, path = str(d.get("N") or ""), str(d.get("P") or "\\")
        if not name:
            continue
        cmd = f"{d.get('E') or ''} {d.get('A') or ''}".strip()
        base = _TASK_SUFFIX.sub("", name).strip() or name
        g = groups.setdefault((path, base), {"cmd": cmd, "members": []})
        g["members"].append((path, name))
    res = []
    for (path, base), g in groups.items():
        n = len(g["members"])
        label = f"{path}{base}" + (f"  (×{n})" if n > 1 else "") + f"   →   {g['cmd'][:100]}"
        res.append(perf_finalize({"kind": "task", "name": base, "task_path": path, "cmd": g["cmd"],
                                  "members": g["members"], "label": label}))
    return res


def list_services():
    out = []
    if winreg is None:
        return out
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
    except OSError:
        return out
    i = 0
    while True:
        try:
            name = winreg.EnumKey(root, i)
        except OSError:
            break
        i += 1
        try:
            k = winreg.OpenKey(root, name)
        except OSError:
            continue
        start, typ, img = _val(k, "Start"), _val(k, "Type"), str(_val(k, "ImagePath") or "")
        if start != 2 or not typ or not (typ & 0x30):
            continue
        low = img.lower()
        if "\\windows\\" in low or "system32" in low or "%systemroot%" in low:
            continue
        disp = str(_val(k, "DisplayName") or name)
        if disp.startswith("@"):
            disp = name
        out.append(perf_finalize({"kind": "service", "name": name, "cmd": img,
                                  "label": f"{disp}  ({name})   →   {img[:100]}"}))
    return out


def load_changes():
    try:
        with open(CHANGES_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return []


def save_changes(lst):
    try:
        os.makedirs(os.path.dirname(CHANGES_FILE), exist_ok=True)
        with open(CHANGES_FILE, "w", encoding="utf-8") as f:
            json.dump(lst, f, ensure_ascii=False, indent=1)
    except OSError:
        pass


def _log_change(entry):
    lst = load_changes()
    lst.append(entry)
    save_changes(lst)


def _hive(name):
    return winreg.HKEY_LOCAL_MACHINE if name == "HKLM" else winreg.HKEY_USERS


def _q(s):
    return str(s).replace("'", "''")


def apply_perf(info):
    """משבית פריט ביצועים (בלי למחוק) ורושם כדי שאפשר לשחזר."""
    kind = info["kind"]
    try:
        if kind == "startup":
            key = winreg.CreateKeyEx(_hive(info["hive"]), info["approved"], 0,
                                     winreg.KEY_READ | winreg.KEY_WRITE)
            old = None
            try:
                old = winreg.QueryValueEx(key, info["name"])[0].hex()
            except OSError:
                pass
            winreg.SetValueEx(key, info["name"], 0, winreg.REG_BINARY, DISABLED_BYTES)
            _log_change({"t": "startup", "hive": info["hive"], "approved": info["approved"],
                         "name": info["name"], "old": old})
            return True
        if kind == "startupfile":
            dest_dir = os.path.join(PROGRAMDATA, "PCCleaner", "disabled-startup")
            os.makedirs(dest_dir, exist_ok=True)
            dest = os.path.join(dest_dir, f"{int(time.time())}_{os.path.basename(info['cmd'])}")
            shutil.move(info["cmd"], dest)
            _log_change({"t": "startupfile", "from": info["cmd"], "to": dest})
            return True
        if kind == "task":
            all_ok = True
            for p, n in info.get("members") or [(info["task_path"], info["name"])]:
                rc, _ = run_ps(f"Disable-ScheduledTask -TaskPath '{_q(p)}' -TaskName '{_q(n)}' | Out-Null")
                if rc == 0:
                    _log_change({"t": "task", "path": p, "name": n})
                else:
                    all_ok = False
            return all_ok
        if kind == "service":
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r"SYSTEM\CurrentControlSet\Services" + "\\" + info["name"],
                                 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, 3)
            _log_change({"t": "service", "name": info["name"], "old": 2})
            return True
    except Exception:
        return False
    return False


def undo_changes():
    ok = bad = 0
    remaining = []
    for e in load_changes():
        try:
            t = e["t"]
            if t == "startup":
                key = winreg.CreateKeyEx(_hive(e["hive"]), e["approved"], 0, winreg.KEY_WRITE)
                data = bytes.fromhex(e["old"]) if e.get("old") else ENABLED_BYTES
                winreg.SetValueEx(key, e["name"], 0, winreg.REG_BINARY, data)
            elif t == "startupfile":
                os.makedirs(os.path.dirname(e["from"]), exist_ok=True)
                shutil.move(e["to"], e["from"])
            elif t == "task":
                rc, _ = run_ps(f"Enable-ScheduledTask -TaskPath '{_q(e['path'])}' -TaskName '{_q(e['name'])}' | Out-Null")
                if rc != 0:
                    raise OSError("task")
            elif t == "service":
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                     r"SYSTEM\CurrentControlSet\Services" + "\\" + e["name"],
                                     0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, int(e.get("old", 2)))
            ok += 1
        except Exception:
            bad += 1
            remaining.append(e)
    save_changes(remaining)
    return ok, bad


def system_info():
    parts = []
    try:
        du = shutil.disk_usage(SYSTEM_DRIVE)
        parts.append(f"{SYSTEM_DRIVE[:2]} פנוי {fmt_size(du.free)} מתוך {fmt_size(du.total)}")
    except OSError:
        pass
    try:
        class MS(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
        m = MS()
        m.dwLength = ctypes.sizeof(m)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
        parts.append(f"RAM {fmt_size(m.ullTotalPhys)}")
    except Exception:
        pass
    rc, out = run_ps("Get-PhysicalDisk | Select-Object MediaType | ConvertTo-Json -Compress", 25)
    kinds = sorted({str(d.get("MediaType")) for d in parse_ps_json(out) if d.get("MediaType")})
    if kinds:
        parts.append("דיסק: " + "/".join(kinds))
    parts.append(f"{os.cpu_count()} ליבות")
    return "   |   ".join(parts)


# ---------- כספת: קבצים אישיים עוברים לכספת במקום להימחק, עם שחזור ----------
VAULT_ROOT = os.path.join(PROGRAMDATA, "PCCleaner", "Vault")
VAULT_DAYS = 7
VAULT_CATS = {"שולחן עבודה", "מסמכים (כולל ציבוריים)", "הורדות", "תמונות / סרטים / מוזיקה", "נתוני דפדפנים"}


def goes_to_vault(it):
    """קבצים אישיים/פרופילים -> כספת. זבל שנוצר מחדש (Temp, מטמון, לוגים) נמחק ישירות."""
    return (not it["prog"] and not it["perf"] and it["path"] != RECYCLE and it["ci"] < len(CATEGORIES)
            and CATEGORIES[it["ci"]][0] in VAULT_CATS)


def vault_new_batch():
    bid = time.strftime("%Y%m%d-%H%M%S")
    path = os.path.join(VAULT_ROOT, bid)
    os.makedirs(path, exist_ok=True)
    return {"id": bid, "path": path, "items": [], "n": 0, "time": time.time()}


def vault_save(batch):
    try:
        with open(os.path.join(batch["path"], "manifest.json"), "w", encoding="utf-8") as f:
            json.dump({"time": batch["time"], "items": batch["items"]}, f, ensure_ascii=False, indent=1)
    except OSError:
        pass


def vault_move(batch, src, size):
    """מעביר פריט לכספת (באותו כונן - מיידי) ורושם במניפסט. מחזיר True אם הצליח."""
    if not is_safe_to_delete(src) or contains_self(src):
        return False
    batch["n"] += 1
    dest_dir = os.path.join(batch["path"], str(batch["n"]))
    dest = os.path.join(dest_dir, os.path.basename(src))
    try:
        os.makedirs(dest_dir, exist_ok=True)
        shutil.move(src, dest)
    except Exception:
        return False
    if os.path.exists(src):                 # העברה חלקית - לא נרשום כהצלחה
        return False
    batch["items"].append({"from": src, "to": dest, "size": size})
    vault_save(batch)                       # נשמר אחרי כל פריט, כדי שקריסה לא תאבד את הרישום
    return True


def vault_list():
    out = []
    try:
        names = sorted(os.listdir(VAULT_ROOT), reverse=True)
    except OSError:
        return out
    for n in names:
        try:
            with open(os.path.join(VAULT_ROOT, n, "manifest.json"), encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, ValueError):
            continue
        items = d.get("items", [])
        out.append({"id": n, "time": d.get("time", 0), "count": len(items), "items": items,
                    "size": sum(i.get("size", 0) for i in items)})
    return out


def vault_purge(bid):
    if not bid or os.sep in bid or ".." in bid:
        return
    shutil.rmtree(os.path.join(VAULT_ROOT, bid), onerror=_on_rm_error)


def vault_restore(bid):
    batch = next((b for b in vault_list() if b["id"] == bid), None)
    if not batch:
        return 0, 0
    ok = bad = 0
    remaining = []
    for it in reversed(batch["items"]):
        src, dest = it["to"], it["from"]
        try:
            if not os.path.exists(src):
                raise OSError("missing")
            if os.path.exists(dest):
                dest += " (שוחזר)"
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.move(src, dest)
            ok += 1
        except Exception:
            bad += 1
            remaining.append(it)
    if remaining:
        vault_save({"path": os.path.join(VAULT_ROOT, bid), "time": batch["time"], "items": list(reversed(remaining))})
    else:
        vault_purge(bid)
    return ok, bad


def vault_auto_purge():
    for b in vault_list():
        if time.time() - b["time"] > VAULT_DAYS * 86400:
            vault_purge(b["id"])


# ---------- זיהוי פרויקטים / קבצים עדכניים ----------
ITEM_FLAGS = {}
PERSONAL_CATS = {"שולחן עבודה", "מסמכים (כולל ציבוריים)", "הורדות", "תמונות / סרטים / מוזיקה"}
RECENT_DAYS = 14
PROJECT_MARKERS = {".git", "package.json", "pyproject.toml", "requirements.txt", "setup.py", "pom.xml",
                   "build.gradle", "cargo.toml", "go.mod", "makefile", "cmakelists.txt", ".idea", ".vscode",
                   "composer.json", "dockerfile", "docker-compose.yml"}
PROJECT_EXT = (".sln", ".csproj", ".vcxproj", ".pyproj", ".xcodeproj")


def _has_marker(path, limit):
    n = 0
    try:
        with os.scandir(path) as it:
            for e in it:
                n += 1
                nm = e.name.lower()
                if nm in PROJECT_MARKERS or nm.endswith(PROJECT_EXT):
                    return True
                if n >= limit:
                    break
    except OSError:
        pass
    return False


def looks_like_project(path):
    """תיקייה עם .git / package.json / קובץ פרויקט (ברמה הראשונה או השנייה)."""
    if not os.path.isdir(path):
        return False
    if _has_marker(path, 400):
        return True
    subs = []
    try:
        with os.scandir(path) as it:
            for e in it:
                if e.is_dir(follow_symlinks=False):
                    subs.append(e.path)
                if len(subs) >= 40:
                    break
    except OSError:
        return False
    return any(_has_marker(sp, 150) for sp in subs)


def newest_touch(path):
    try:
        t = os.path.getmtime(path)
    except OSError:
        return 0
    if os.path.isdir(path):
        try:
            with os.scandir(path) as it:
                for i, e in enumerate(it):
                    if i >= 200:
                        break
                    try:
                        t = max(t, e.stat(follow_symlinks=False).st_mtime)
                    except OSError:
                        pass
        except OSError:
            pass
    return t


# ---------- פרופיל החרגות (אותו קובץ לכל המחשבים) ----------
PROFILE = {"name": "", "keywords": [], "programs": set(), "perf": set(), "paths": set()}
PROFILE_FILE = os.path.join(PROGRAMDATA, "PCCleaner", "profile.json")


def path_key(p):
    return re.sub(r"^([a-z]:\\users\\)[^\\]+", r"\1*", os.path.normpath(str(p)).lower())


def profile_keeps(name, kind):
    return norm_tok(name) in PROFILE[kind]


def profile_keeps_path(p):
    return path_key(p) in PROFILE["paths"]


def profile_clear():
    PROFILE.update({"name": "", "keywords": [], "programs": set(), "perf": set(), "paths": set()})


def profile_load(path):
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    PROFILE["name"] = d.get("name") or os.path.basename(path)
    PROFILE["keywords"] = [str(x) for x in d.get("keywords", [])]
    PROFILE["programs"] = {norm_tok(x) for x in d.get("programs", [])}
    PROFILE["perf"] = {norm_tok(x) for x in d.get("perf", [])}
    PROFILE["paths"] = {path_key(x) for x in d.get("paths", [])}
    log(f"profile loaded: {PROFILE['name']} ({len(PROFILE['programs'])} programs, "
        f"{len(PROFILE['perf'])} perf, {len(PROFILE['paths'])} paths)")


def profile_build(app, name):
    """הפריטים שהיו אמורים להימחק ואתה הסרת מהם V = החרגות מפורשות לפרופיל."""
    programs, perf, paths = [], [], []
    for iid, it in app.items.items():
        if app.checked.get(iid) or not it.get("default"):
            continue
        if it["prog"]:
            programs.append(PROG_INFO[it["path"]]["name"])
        elif it["perf"]:
            perf.append(PERF_INFO[it["path"]]["name"])
        elif it["path"] != RECYCLE:
            paths.append(it["path"])
    return {"version": 1, "name": name, "created": time.strftime("%Y-%m-%d %H:%M"),
            "keywords": list(KEYWORDS), "programs": sorted(set(programs)),
            "perf": sorted(set(perf)), "paths": sorted(set(paths))}


# ---------- סיווג קבצים ותוכנות ----------

JUNK_REASON = {
    "קבצים זמניים של משתמשים": "קבצים זמניים - נבנים מחדש",
    "קבצים זמניים של Windows": "קבצים זמניים של המערכת - נבנים מחדש",
    "מטמון Chrome / Edge": "מטמון דפדפן - נבנה מחדש",
    "מטמון Firefox": "מטמון דפדפן - נבנה מחדש",
    "תמונות ממוזערות": "מטמון תצוגה מקדימה - נבנה מחדש",
    "דוחות שגיאה ו-Dump": "דוחות קריסה ולוגים של המערכת",
}
BROWSER_PROFILE_RE = re.compile(r"^(default|profile \d+|guest profile|system profile)$", re.I)
DISPOSABLE_EXT = (".lnk", ".url", ".ini", ".tmp")
INSTALLER_EXT = (".msi", ".exe", ".zip", ".rar", ".7z", ".iso")
TEMPLATE_RE = re.compile(r"^[a-z]:\\users\\(default|default user)\\", re.I)


def classify_file(ci, p, size, kw):
    """מחזיר (רמת המלצה, סיבה, מסומן כברירת מחדל) לקובץ או תיקייה."""
    name = CATEGORIES[ci][0] if ci < len(CATEGORIES) else ""
    if p == RECYCLE:
        return "green", "סל המחזור - ריקון", True
    hit = next((t for t in kw if t in norm_tok(p)), "")
    if hit:
        return "red", f"מילת הגנה: {hit}", False
    if profile_keeps_path(p):
        return "red", f"נשמר בפרופיל: {PROFILE['name']}", False
    base = os.path.basename(p)
    low = base.lower()
    if name == "Prefetch":
        return "yellow", "לא מאיץ בפועל, והמחיקה מאטה את ההפעלה הראשונה", False
    if name == "מטמון עדכוני Windows":
        why = "הורדת עדכון שמורה - תורד שוב בעדכון הבא"
        if size >= 2 * 1024 ** 3:
            why += " (גדולה - ייתכן עדכון תקוע)"
        return "green", why, True
    if name == "נתוני דפדפנים":
        if BROWSER_PROFILE_RE.match(base) or ("firefox" in p.lower() and "profiles" in p.lower()):
            return "yellow", "פרופיל דפדפן: סיסמאות, סימניות והיסטוריה", True
        return "green", "נתוני עזר של הדפדפן - נבנים מחדש", True
    if name in PERSONAL_CATS:
        fl = ITEM_FLAGS.get(p) or {}
        if low == "desktop.ini" or low.endswith(DISPOSABLE_EXT) or low.startswith(("~$", "~wrl")):
            return "green", "קיצור / קובץ מערכת / קובץ נעילה של Office", True
        if fl.get("project"):
            return "red", "נראה כפרויקט קוד - מומלץ לשמור", False
        if fl.get("recent"):
            return "red", f"שונה ב-{RECENT_DAYS} הימים האחרונים - מומלץ לשמור", False
        if TEMPLATE_RE.match(p):
            return "yellow", "תבנית למשתמשים חדשים (Default) - ייתכן שהושארה בכוונה", False
        if name == "הורדות" and low.endswith(INSTALLER_EXT):
            return "green", "מתקין או ארכיון בהורדות - אפשר להוריד שוב", True
        return "yellow", "קובץ אישי - בדוק לפני מחיקה", True
    return "green", JUNK_REASON.get(name, "קבצים זמניים"), True


LINK_STOP = {"commonfiles", "programfiles", "programfilesx86", "shared", "windowsapps", "application",
             "appdata", "programdata"}


def link_service_programs(items):
    """תוכנה שהשירות שלה נשאר פעיל: הסרתה תשבור את השירות, ולכן היא מסומנת לבדיקה."""
    svcs = [PERF_INFO[it["path"]] for it in items.values()
            if it["perf"] and PERF_INFO[it["path"]]["kind"] == "service" and it["rec"] == "yellow"]
    if not svcs:
        return
    for it in items.values():
        if not it["prog"] or it["rec"] != "green":
            continue
        inf = PROG_INFO[it["path"]]
        toks = {t for t in prog_tokens(inf) if len(t) >= 5 and t not in LINK_STOP}
        if not inf.get("loc"):
            first = norm_tok(re.split(r"[\s\-_]+", inf["name"].strip())[0])
            if len(first) >= 5 and first not in GENERIC_TOKENS:
                toks.add(first)
        for sv in svcs:
            blob = norm_tok(sv["name"] + " " + sv["cmd"])
            if any(t in blob for t in toks):
                it["rec"], it["default"] = "yellow", False
                it["reason"] = f"השירות {sv['name']} נשאר פעיל - הסרת התוכנה תשבור אותו"
                break


def deepfreeze_present():
    """Deep Freeze (Faronics): במצב Frozen כל שינוי, כולל לוגים, נמחק באתחול."""
    try:
        if winreg is not None:
            winreg.CloseKey(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                           r"SYSTEM\CurrentControlSet\Services\DFServ"))
            return True
    except OSError:
        pass
    return os.path.isdir(os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "Faronics"))


def prune_old(folder, pattern, keep):
    try:
        files = sorted(glob.glob(os.path.join(folder, pattern)), key=os.path.getmtime, reverse=True)
        for f in files[keep:]:
            os.remove(f)
    except OSError:
        pass


def housekeeping():
    """ניקוי עצמי: כספת ישנה, דוחות ולוגים ישנים."""
    vault_auto_purge()
    rep_dir = os.path.join(out_dir(), "Reports")
    prune_old(rep_dir, "report-*.txt", 20)
    prune_old(rep_dir, "inventory-*.txt", 10)
    prune_old(log_dir(), "pccleaner-*.log", 60)


def scan(progress_cb, cancel):
    """progress_cb(msg, frac, ceiling, force). מחזיר (results, sysinfo)."""
    results, claimed = [], []
    ITEM_FLAGS.clear()
    TOTAL = len(CATEGORIES) + 1 + 1 + 4 + 1 + 1 + 2     # קטגוריות+תוכנות+הפעלה+משימות+שירותים+סל+חומרה
    st = [0.0]

    def rep(msg, extra=0.0, weight=1.0, force=True):
        progress_cb(msg, (st[0] + extra) / TOTAL, (st[0] + weight * 0.92) / TOTAL, force)

    for ci, (name, _d, patterns, expand, min_age, _c) in enumerate(CATEGORIES):
        if cancel.is_set():
            break
        rep(f"סורק: {name}")
        cutoff = time.time() - min_age * 86400
        found = []
        for pat in patterns:
            for match in glob.glob(pat):
                if is_reparse(match):
                    continue
                if expand and os.path.isdir(match):
                    try:
                        found.extend(c.path for c in os.scandir(match))
                    except OSError:
                        pass
                else:
                    found.append(match)
        n_found = max(len(found), 1)
        for k, p in enumerate(found):
            if cancel.is_set():
                break
            if k % 3 == 0:
                rep(f"סורק: {name}  ({k}/{len(found)})", k / n_found, force=False)
            if contains_self(p) or is_own_data(p):
                continue
            try:
                if min_age and os.path.getmtime(p) > cutoff:
                    continue
            except OSError:
                pass
            sz = path_size(p)
            pn = _norm_path(p)
            if name in ("מטמון Chrome / Edge", "מטמון Firefox"):
                claimed.append((pn, sz))
            elif name == "נתוני דפדפנים":                # בלי ספירה כפולה של המטמון שכבר נספר
                sz -= sum(c for cp, c in claimed if cp.startswith(pn + os.sep))
            if sz > 0:
                results.append((ci, p, sz))
                if name in PERSONAL_CATS:
                    ITEM_FLAGS[p] = {"project": looks_like_project(p),
                                     "recent": time.time() - newest_touch(p) < RECENT_DAYS * 86400}
        st[0] += 1

    rep("סורק: תוכנות מותקנות")
    PROG_INFO.clear()
    for key, info in list_programs().items():
        PROG_INFO[UNINSTALL + key] = info
        results.append((PROG_CI, UNINSTALL + key, max(info["size"], 1)))
    st[0] += 1

    PERF_INFO.clear()
    counter = [0]

    def add_perf(ci, infos):
        for info in infos:
            counter[0] += 1
            key = PERF_PREFIX[info["kind"]] + str(counter[0])
            PERF_INFO[key] = info
            results.append((ci, key, 1))

    rep("סורק: תוכנות שעולות עם Windows")
    add_perf(STARTUP_CI, list_startup() + list_startup_folders())
    st[0] += 1
    rep("סורק: משימות מתוזמנות (לוקח כמה שניות)", weight=4)
    add_perf(TASK_CI, list_tasks())
    st[0] += 4
    rep("סורק: שירותים")
    add_perf(SERVICE_CI, list_services())
    st[0] += 1

    rep("סורק: סל מחזור")
    rb = recycle_bin_size()
    if rb > 0:
        results.append((RECYCLE_CI, RECYCLE, rb))
    st[0] += 1
    rep("בודק חומרה ודיסק", weight=2)
    info = system_info()
    progress_cb("מסיים...", 1.0, 1.0, True)
    return results, info


# ---------- ממשק ----------
def _lerp_color(a, b, t):
    ca = [int(a[i:i + 2], 16) for i in (1, 3, 5)]
    cb = [int(b[i:i + 2], 16) for i in (1, 3, 5)]
    return "#%02x%02x%02x" % tuple(int(x + (y - x) * t) for x, y in zip(ca, cb))


class ProgressRing(tk.Canvas):
    """טבעת התקדמות עם גרדיינט, אחוזים, נקודה מובילה, קומטה מסתובבת וטבעת מקווקוות נעה."""
    N = 120

    def __init__(self, master, size=280, bg="white"):
        super().__init__(master, width=size, height=size, highlightthickness=0, bg=bg)
        self.size, self.pad, self.w = size, 34, 18
        self.seg = 360.0 / self.N
        c = size / 2
        self.c, self.R = c, c - self.pad
        box = (self.pad, self.pad, size - self.pad, size - self.pad)
        self.create_oval(*box, outline="#e5eaf2", width=self.w)
        self.dash = self.create_oval(10, 10, size - 10, size - 10, outline="#cbd5e1", width=2, dash=(3, 9))
        self.comet = self.create_arc(20, 20, size - 20, size - 20, start=0, extent=50, style="arc",
                                     outline="#93c5fd", width=3)
        self.segs = [self.create_arc(*box, start=90 - i * self.seg, extent=-(self.seg + 0.8), style="arc",
                                     width=self.w, state="hidden") for i in range(self.N)]
        self.dot = self.create_oval(0, 0, 0, 0, fill="white", outline=ACCENT, width=3, state="hidden")
        self.txt = self.create_text(c, c - 10, text="0%", font=("Segoe UI", 46, "bold"), fill=HEADER)
        self.subtxt = self.create_text(c, c + 40, text="", font=("Segoe UI", 12), fill="#64748b")
        self.colors, self.angle, self.dashoff, self.running = [], 0, 0, False
        self.palette(("#93c5fd", ACCENT))
        self.reset()

    def palette(self, pair):
        a, b = pair
        self.colors = [_lerp_color(a, b, i / (self.N - 1)) for i in range(self.N)]
        for i, sgm in enumerate(self.segs):
            self.itemconfigure(sgm, outline=self.colors[i])
        self.itemconfigure(self.comet, outline=a)

    def reset(self):
        self.shown = self.target = self.ceil = 0.0
        self._vis = 0
        for sgm in self.segs:
            self.itemconfigure(sgm, state="hidden")
        self.itemconfigure(self.dot, state="hidden")
        self.itemconfigure(self.txt, text="0%")

    def set(self, target, ceiling, sub=None):
        self.target = max(0.0, min(1.0, target))
        self.ceil = max(self.target, min(1.0, ceiling))
        if sub is not None:
            self.itemconfigure(self.subtxt, text=sub)

    def finish(self):
        self.shown = self.target = self.ceil = 1.0
        self._draw()

    def _draw(self):
        p = min(max(self.shown, 0.0), 1.0)
        deg = p * 360.0
        full = min(int(deg // self.seg), self.N)
        part = deg - full * self.seg
        if full > self._vis:
            for i in range(self._vis, full):
                self.itemconfigure(self.segs[i], state="normal", extent=-(self.seg + 0.8))
        elif full < self._vis:
            for i in range(full, self._vis):
                self.itemconfigure(self.segs[i], state="hidden")
        self._vis = full
        if full < self.N:
            self.itemconfigure(self.segs[full], state="normal" if part > 0.4 else "hidden",
                               extent=-max(part, 0.01))
        ang = math.radians(90 - deg)
        x, y = self.c + self.R * math.cos(ang), self.c - self.R * math.sin(ang)
        self.coords(self.dot, x - 11, y - 11, x + 11, y + 11)
        self.itemconfigure(self.dot, state="normal" if p > 0.004 else "hidden",
                           outline=self.colors[min(full, self.N - 1)])
        self.itemconfigure(self.txt, text=f"{int(p * 100)}%")

    def _step(self):
        if self.shown < self.target:                      # הקלה חלקה אל היעד
            self.shown = min(self.shown + max((self.target - self.shown) * 0.12, 0.0015), self.target)
        elif self.shown < self.ceil:                      # זחילה איטית בזמן שלב ארוך
            self.shown = min(self.shown + 0.00035, self.ceil)
        self._draw()
        self.angle = (self.angle - 7) % 360
        self.itemconfigure(self.comet, start=self.angle)
        self.dashoff = (self.dashoff + 1) % 12
        self.itemconfigure(self.dash, dashoffset=self.dashoff)

    def start(self):
        if not self.running:
            self.running = True
            self._loop()

    def stop(self):
        self.running = False

    def _loop(self):
        if self.running:
            self._step()
            self.after(16, self._loop)


class Spinner(tk.Canvas):
    def __init__(self, master, size=54, bg=HEADER):
        super().__init__(master, width=size, height=size, highlightthickness=0, bg=bg)
        self.angle, self.running, pad = 0, False, 7
        self.create_oval(pad, pad, size - pad, size - pad, outline="#334155", width=6)
        self.arc = self.create_arc(pad, pad, size - pad, size - pad, start=0, extent=100,
                                   style="arc", outline="#60a5fa", width=6)

    def start(self):
        self.running = True
        self._tick()

    def stop(self):
        self.running = False

    def _tick(self):
        if self.running:
            self.angle = (self.angle - 10) % 360
            self.itemconfigure(self.arc, start=self.angle)
            self.after(20, self._tick)


class App(tk.Tk):
    CHK, UNCHK, PART = "☑", "☐", "◪"

    def __init__(self):
        super().__init__()
        self.title(f"PC Cleaner v{VERSION} - ניקוי חכם")
        self.geometry("1120x740")
        self.minsize(860, 600)
        self.configure(bg=BG)
        self.cancel = threading.Event()
        self.items, self.checked, self.busy = {}, {}, False
        self.cat_items, self.open_cats, self._rt, self.deepfreeze = {}, None, None, False
        self.filter_var = tk.StringVar(value=FILTERS[0])
        self.search_var = tk.StringVar()
        self._style()
        self._build()
        threading.Thread(target=housekeeping, daemon=True).start()
        exe_dir = os.path.dirname(CONFIG_FILES[1])
        for pf in (os.path.join(exe_dir, "profile.json"), PROFILE_FILE):
            if os.path.exists(pf):
                try:
                    profile_load(pf)
                    self.status.config(text=f"נטען פרופיל: {PROFILE['name']}")
                    break
                except (OSError, ValueError):
                    log_exc("profile autoload")

    # --- עיצוב ---
    def _style(self):
        s = ttk.Style(self)
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        s.configure("Treeview", rowheight=28, font=("Segoe UI", 10), background="white",
                    fieldbackground="white", borderwidth=0)
        s.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"), background="#e2e8f0",
                    relief="flat", padding=6)
        s.map("Treeview", background=[("selected", "#bfdbfe")], foreground=[("selected", "black")])
        s.configure("TNotebook", background=BG, borderwidth=0)
        s.configure("TNotebook.Tab", font=("Segoe UI", 10, "bold"), padding=(18, 8))
        s.configure("Accent.TButton", font=("Segoe UI", 10, "bold"), padding=8,
                    background=ACCENT, foreground="white")
        s.map("Accent.TButton", background=[("active", "#1d4ed8"), ("disabled", "#94a3b8")])
        s.configure("Danger.TButton", font=("Segoe UI", 11, "bold"), padding=10,
                    background=RED, foreground="white")
        s.map("Danger.TButton", background=[("active", "#b91c1c"), ("disabled", "#fca5a5")])
        s.configure("Plain.TButton", font=("Segoe UI", 10), padding=7)
        s.configure("Horizontal.TProgressbar", troughcolor="#e2e8f0", background=ACCENT, thickness=10)

    def _card(self, parent, title, color):
        f = tk.Frame(parent, bg="white", highlightbackground="#e2e8f0", highlightthickness=1)
        tk.Frame(f, bg=color, height=4).pack(fill="x")
        tk.Label(f, text=title, bg="white", fg="#475569", font=("Segoe UI", 10)).pack(pady=(8, 0))
        val = tk.Label(f, text="-", bg="white", fg=color, font=("Segoe UI", 20, "bold"))
        val.pack()
        sub = tk.Label(f, text=" ", bg="white", fg="#64748b", font=("Segoe UI", 9))
        sub.pack(pady=(0, 8))
        return f, val, sub

    def _build(self):
        head = tk.Frame(self, bg=HEADER)
        head.pack(fill="x")
        self.spinner = Spinner(head)
        self.spinner.pack(side="left", padx=(16, 10), pady=12)
        t = tk.Frame(head, bg=HEADER)
        t.pack(side="left", fill="x", expand=True)
        tk.Label(t, text="PC Cleaner", bg=HEADER, fg="white", font=("Segoe UI", 16, "bold")).pack(anchor="w")
        self.status = tk.Label(t, text="לחץ 'סרוק' כדי להתחיל", bg=HEADER, fg="#cbd5e1", font=("Segoe UI", 10))
        self.status.pack(anchor="w")
        self.sysinfo = tk.Label(t, text="", bg=HEADER, fg="#94a3b8", font=("Segoe UI", 9))
        self.sysinfo.pack(anchor="w")
        if not is_admin():
            tk.Label(t, text="⚠ לא רץ כמנהל - חלק מהקבצים לא ייסרקו", bg=HEADER, fg="#fbbf24",
                     font=("Segoe UI", 9)).pack(anchor="w")
        bt = tk.Frame(head, bg=HEADER)
        bt.pack(side="right", padx=16)
        self.btn_scan = ttk.Button(bt, text="🔍  סרוק", style="Accent.TButton", command=self.start_scan)
        self.btn_scan.pack(side="right")
        ttk.Button(bt, text="🛡  הגדרות הגנה", style="Plain.TButton",
                   command=self.protect_dialog).pack(side="right", padx=8)
        self.btn_report = ttk.Button(bt, text="📋  העתק דוח", style="Plain.TButton",
                                     command=self.copy_report, state="disabled")
        self.btn_report.pack(side="right")
        ttk.Button(bt, text="↩  שחזור וכספת", style="Plain.TButton",
                   command=self.undo).pack(side="right", padx=8)
        ttk.Button(bt, text="📦  פרופיל", style="Plain.TButton",
                   command=self.profile_dialog).pack(side="right", padx=8)
        ttk.Button(bt, text="📜  לוגים", style="Plain.TButton",
                   command=self.logs_dialog).pack(side="right", padx=8)

        cards = tk.Frame(self, bg=BG)
        cards.pack(fill="x", padx=14, pady=(8, 4))
        for i in range(4):
            cards.columnconfigure(i, weight=1, uniform="c")
        c1, self.v_del, self.s_del = self._card(cards, "יימחק", RED)
        c2, self.v_prog, self.s_prog = self._card(cards, "תוכנות שיוסרו", AMBER)
        c3, self.v_keep, self.s_keep = self._card(cards, "יישמר", GREEN)
        c4, self.v_perf, self.s_perf = self._card(cards, "⚡ יושבתו (ביצועים)", ACCENT)
        for i, c in enumerate((c1, c2, c4, c3)):
            c.grid(row=0, column=i, sticky="nsew", padx=5)

        tk.Label(self, bg=BG, fg="#334155", font=("Segoe UI", 9), anchor="e", justify="right", wraplength=1060,
                 text="🟢 מומלץ למחוק (מסומן מראש)     🟡 לבדיקה (לא מסומן; קבצים אישיים מסומנים כי הם עוברים לכספת)     "
                      "🔴 מומלץ לשמור (לא מסומן)     -     אפשר לשנות כל פריט, שום דבר לא נעול"
                 ).pack(fill="x", padx=16)
        bar = tk.Frame(self, bg=BG)
        bar.pack(fill="x", padx=14, pady=(4, 6))
        tk.Label(bar, text="סינון:", bg=BG).pack(side="right", padx=(0, 4))
        fc = ttk.Combobox(bar, state="readonly", width=18, values=FILTERS, textvariable=self.filter_var)
        fc.pack(side="right", padx=(0, 14))
        fc.bind("<<ComboboxSelected>>", lambda e: self.render())
        tk.Label(bar, text="חיפוש:", bg=BG).pack(side="right", padx=(0, 4))
        ttk.Entry(bar, width=30, textvariable=self.search_var).pack(side="right")
        self.search_var.trace_add("write", lambda *a: self._schedule_render())

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=14)
        f1 = tk.Frame(self.nb, bg="white")
        f2 = tk.Frame(self.nb, bg="white")
        self.nb.add(f1, text="🗑  מה יקרה (לחץ על שורה לסימון / ביטול)")
        self.nb.add(f2, text="✅  מה נשאר")
        self.nb.bind("<<NotebookTabChanged>>", lambda e: self.refresh_kept())

        self.tree = ttk.Treeview(f1, columns=("action", "reason", "size"), selectmode="browse")
        self.tree.heading("#0", text="פריט  (☑ = ייעשה)")
        self.tree.heading("action", text="פעולה")
        self.tree.heading("reason", text="המלצה / סיבה")
        self.tree.heading("size", text="גודל")
        self.tree.column("#0", width=470)
        self.tree.column("action", width=110, anchor="center")
        self.tree.column("reason", width=330)
        self.tree.column("size", width=90, anchor="e")
        sb = ttk.Scrollbar(f1, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.tag_configure("cat", background="#e2e8f0", font=("Segoe UI", 10, "bold"))
        self.tree.tag_configure("on", background=ROW_DEL)
        self.tree.tag_configure("off", background=ROW_KEEP)
        self.tree.tag_configure("warn", background=ROW_WARN)
        self.tree.bind("<Button-1>", self.on_click)
        self.tree.bind("<space>", lambda e: self.toggle(self.tree.selection()[0]) if self.tree.selection() else None)
        self.tree.bind("<<TreeviewOpen>>", lambda e: self._track_open(True))
        self.tree.bind("<<TreeviewClose>>", lambda e: self._track_open(False))

        self.kept = ttk.Treeview(f2, columns=("why", "size"), selectmode="browse")
        self.kept.heading("#0", text="פריט")
        self.kept.heading("why", text="סיבה")
        self.kept.heading("size", text="גודל")
        self.kept.column("#0", width=560)
        self.kept.column("why", width=300)
        self.kept.column("size", width=100, anchor="e")
        sb2 = ttk.Scrollbar(f2, orient="vertical", command=self.kept.yview)
        self.kept.configure(yscrollcommand=sb2.set)
        self.kept.pack(side="left", fill="both", expand=True)
        sb2.pack(side="right", fill="y")
        self.kept.tag_configure("keep", background=ROW_KEEP)

        foot = tk.Frame(self, bg=BG)
        foot.pack(fill="x", padx=14, pady=10)
        self.btn_clean = ttk.Button(foot, text="🗑  בצע ניקוי", style="Danger.TButton",
                                    command=self.confirm_clean, state="disabled")
        self.btn_clean.pack(side="right")
        ttk.Button(foot, text="↺ חזור להמלצות", style="Plain.TButton",
                   command=self.reset_defaults).pack(side="right", padx=8)
        ttk.Button(foot, text="בטל הכל", style="Plain.TButton",
                   command=lambda: self.set_all(False)).pack(side="right")
        ttk.Button(foot, text="סמן הכל (בלי 🔴)", style="Plain.TButton",
                   command=lambda: self.set_all(True)).pack(side="right", padx=8)
        self.use_vault = tk.BooleanVar(value=True)
        self.use_vault.trace_add("write", lambda *a: self.render())
        ttk.Checkbutton(foot, text=f"🛡 קבצים אישיים → כספת (שחזור עד {VAULT_DAYS} ימים)",
                        variable=self.use_vault).pack(side="left", padx=(0, 14))
        self.dry_run = tk.BooleanVar(value=False)
        ttk.Checkbutton(foot, text="🧪 הדמיה (לא נוגע בכלום)",
                        variable=self.dry_run).pack(side="left", padx=(0, 14))
        self.pbar = ttk.Progressbar(foot, mode="determinate")
        self.pbar.pack(side="left", fill="x", expand=True, padx=(0, 14))
        self._build_overlay()

    def report_callback_exception(self, exc, val, tb):
        log("UI error:\n" + "".join(traceback.format_exception(exc, val, tb)))
        try:
            self.hide_overlay()
            self.spinner.stop()
            self.busy = False
            self.btn_scan.config(state="normal")
            messagebox.showerror("שגיאה", f"אירעה שגיאה בלתי צפויה.\nהפירוט נשמר ב:\n{log_dir()}")
        except Exception:
            pass

    def _fail(self, msg):
        self.spinner.stop()
        self.hide_overlay()
        self.busy = False
        self.btn_scan.config(state="normal")
        self.status.config(text=msg)
        messagebox.showerror("שגיאה", f"{msg}\nהפירוט נשמר ב:\n{log_dir()}")

    def logs_dialog(self):
        d = tk.Toplevel(self)
        d.title("יומן פעולות")
        d.geometry("940x620")
        d.configure(bg=BG)
        d.transient(self)
        top = tk.Frame(d, bg=BG)
        top.pack(fill="x", padx=12, pady=(10, 4))
        tk.Label(top, text=f"📁 {log_dir()}", bg=BG, fg="#475569", font=("Segoe UI", 9)).pack(side="right")
        files = []
        cb = ttk.Combobox(top, state="readonly", width=32)
        cb.pack(side="left")
        box = tk.Frame(d)
        box.pack(fill="both", expand=True, padx=12, pady=4)
        txt = tk.Text(box, wrap="none", font=("Consolas", 10), bg="white")
        sb = ttk.Scrollbar(box, command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        txt.pack(side="left", fill="both", expand=True)
        txt.tag_configure("bad", foreground="#b91c1c")
        txt.tag_configure("ok", foreground="#15803d")
        txt.tag_configure("dry", foreground="#b45309")

        def current_path():
            return os.path.join(log_dir(), cb.get()) if cb.get() else None

        def show(*_):
            txt.config(state="normal")
            txt.delete("1.0", "end")
            path = current_path()
            if not path or not os.path.exists(path):
                txt.insert("end", "אין עדיין לוגים. הם נוצרים בסריקה ובניקוי.")
            else:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    lines = fh.readlines()[-3000:]
                for line in lines:
                    tag = ("bad" if ("FAIL" in line or "ERROR" in line or "UNCAUGHT" in line)
                           else "dry" if " DRY " in line else "ok" if " OK:" in line else "")
                    txt.insert("end", line, tag)
            txt.see("end")
            txt.config(state="disabled")

        def load():
            files[:] = sorted(glob.glob(os.path.join(log_dir(), "pccleaner-*.log")), reverse=True)
            cb["values"] = [os.path.basename(f) for f in files]
            if files and not cb.get():
                cb.current(0)
            show()
        cb.bind("<<ComboboxSelected>>", show)

        def open_folder():
            try:
                os.startfile(log_dir())
            except Exception:
                messagebox.showinfo("תיקיית לוגים", log_dir(), parent=d)

        def open_file():
            p = current_path()
            try:
                os.startfile(p)
            except Exception:
                messagebox.showinfo("קובץ", str(p), parent=d)

        def copy_all():
            self.clipboard_clear()
            self.clipboard_append(txt.get("1.0", "end"))
            self.update()
            messagebox.showinfo("הועתק", "הלוג הועתק ללוח.", parent=d)

        row = tk.Frame(d, bg=BG)
        row.pack(pady=8)
        ttk.Button(row, text="🔄 רענן", style="Plain.TButton", command=load).pack(side="left", padx=4)
        ttk.Button(row, text="📁 פתח תיקייה", style="Plain.TButton", command=open_folder).pack(side="left", padx=4)
        ttk.Button(row, text="📝 פתח בפנקס רשימות", style="Plain.TButton", command=open_file).pack(side="left", padx=4)
        ttk.Button(row, text="📋 העתק הכל", style="Accent.TButton", command=copy_all).pack(side="left", padx=4)
        load()

    def profile_dialog(self):
        from tkinter import filedialog
        d = tk.Toplevel(self)
        d.title("פרופיל החרגות")
        d.geometry("520x330")
        d.configure(bg=BG)
        d.transient(self)
        cur = tk.Label(d, bg=BG, fg=HEADER, font=("Segoe UI", 11, "bold"))
        cur.pack(pady=(14, 4))
        tk.Label(d, bg=BG, fg="#475569", font=("Segoe UI", 10), wraplength=470, justify="right",
                 text="פרופיל = רשימת החרגות שאתה בונה פעם אחת על מחשב ייחוס (מסירים V ממה שרוצים לשמור), "
                      "ושומרים לקובץ. אחר כך טוענים את אותו קובץ בכל מחשב, והפריטים האלה מוגנים שם. "
                      "קובץ בשם profile.json ליד ה-EXE נטען אוטומטית.").pack(padx=14)

        def refresh():
            cur.config(text=f"פרופיל נוכחי: {PROFILE['name'] or 'אין'}")
        refresh()

        def save():
            if not self.items:
                messagebox.showinfo("פרופיל", "קודם סרוק והסר V ממה שרוצים לשמור.", parent=d)
                return
            f = filedialog.asksaveasfilename(parent=d, defaultextension=".json", initialfile="lab-profile.json",
                                             filetypes=[("Profile", "*.json")])
            if not f:
                return
            prof = profile_build(self, os.path.splitext(os.path.basename(f))[0])
            with open(f, "w", encoding="utf-8") as fh:
                json.dump(prof, fh, ensure_ascii=False, indent=1)
            messagebox.showinfo("פרופיל", f"נשמר: {len(prof['programs'])} תוכנות, {len(prof['perf'])} פריטי הפעלה/"
                                          f"שירותים, {len(prof['paths'])} נתיבים.", parent=d)

        def load():
            f = filedialog.askopenfilename(parent=d, filetypes=[("Profile", "*.json")])
            if not f:
                return
            try:
                profile_load(f)
            except (OSError, ValueError):
                messagebox.showerror("פרופיל", "הקובץ לא תקין.", parent=d)
                return
            refresh()
            messagebox.showinfo("פרופיל", "נטען. לחץ 'סרוק' כדי להחיל.", parent=d)

        def clear():
            profile_clear()
            refresh()
        row = tk.Frame(d, bg=BG)
        row.pack(pady=14)
        ttk.Button(row, text="💾 שמור פרופיל מהמצב הנוכחי", style="Accent.TButton", command=save).pack(pady=4)
        ttk.Button(row, text="📂 טען פרופיל", style="Plain.TButton", command=load).pack(pady=4)
        ttk.Button(row, text="✖ נקה פרופיל", style="Plain.TButton", command=clear).pack(pady=4)

    # --- מסך התקדמות ---
    def _build_overlay(self):
        self.overlay = tk.Frame(self, bg="white")
        inner = tk.Frame(self.overlay, bg="white")
        inner.place(relx=0.5, rely=0.5, anchor="center")
        self.ring = ProgressRing(inner)
        self.ring.pack()
        self.ov_title = tk.Label(inner, text="", bg="white", fg=HEADER, font=("Segoe UI", 16, "bold"))
        self.ov_title.pack(pady=(8, 2))
        self.ov_detail = tk.Label(inner, text="", bg="white", fg="#64748b", font=("Segoe UI", 10), wraplength=560)
        self.ov_detail.pack()
        self.ov_time = tk.Label(inner, text="", bg="white", fg="#94a3b8", font=("Segoe UI", 10))
        self.ov_time.pack(pady=(6, 0))
        self._ov_on = False

    def show_overlay(self, mode, title):
        self.ring.reset()
        self.ring.palette(("#fdba74", RED) if mode == "clean" else ("#93c5fd", ACCENT))
        self.ring.itemconfigure(self.ring.subtxt, text="מנקה" if mode == "clean" else "סורק")
        self.ov_title.config(text=title)
        self.ov_detail.config(text="")
        self.ov_t0 = time.time()
        self._ov_on = True
        self.overlay.place(in_=self.nb, x=0, y=0, relwidth=1, relheight=1)
        self.overlay.lift()
        self.ring.start()
        self._tick_time()

    def hide_overlay(self):
        self._ov_on = False
        self.ring.stop()
        self.overlay.place_forget()

    def _tick_time(self):
        if self._ov_on:
            sec = int(time.time() - self.ov_t0)
            self.ov_time.config(text=f"⏱  {sec // 60:02d}:{sec % 60:02d}")
            self.after(500, self._tick_time)

    def on_progress(self, msg, frac, ceil, sub=None):
        self.ring.set(frac, ceil, sub)
        self.ov_detail.config(text=msg)
        self.status.config(text=msg)
        self.pbar.config(maximum=100, value=frac * 100)

    def undo(self):
        d = tk.Toplevel(self)
        d.title("שחזור וכספת")
        d.geometry("680x560")
        d.configure(bg=BG)
        d.transient(self)
        tk.Label(d, text=f"🛡 כספת קבצים - נמחקת אוטומטית אחרי {VAULT_DAYS} ימים", bg=BG, fg=HEADER,
                 font=("Segoe UI", 12, "bold")).pack(pady=(12, 4))
        tk.Label(d, text="כל קבצי המשתמש שנוקו הועברו לכאן ואפשר להחזיר אותם למקום המקורי.",
                 bg=BG, fg="#475569", font=("Segoe UI", 10)).pack()
        lb = tk.Listbox(d, height=9, font=("Segoe UI", 11), activestyle="none")
        lb.pack(fill="both", expand=True, padx=14, pady=8)
        batches = []

        def refresh():
            batches[:] = vault_list()
            lb.delete(0, "end")
            for b in batches:
                lb.insert("end", f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(b['time']))}   |   "
                                 f"{b['count']} פריטים   |   {ltr(fmt_size(b['size']))}")

        def chosen():
            sel = lb.curselection()
            return batches[sel[0]] if sel else None

        def do_restore():
            b = chosen()
            if not b:
                messagebox.showinfo("שחזור", "בחר אצווה מהרשימה.", parent=d)
                return
            ok, bad = vault_restore(b["id"])
            messagebox.showinfo("שחזור", f"שוחזרו {ok} פריטים, נכשלו {bad}.", parent=d)
            refresh()

        def do_purge():
            b = chosen()
            if b and messagebox.askyesno("מחיקה", "למחוק את האצווה לצמיתות? לא ניתן יהיה לשחזר.", parent=d):
                vault_purge(b["id"])
                refresh()

        def do_empty():
            if batches and messagebox.askyesno("רוקן כספת", "למחוק את כל הכספת לצמיתות?", parent=d):
                for b in list(batches):
                    vault_purge(b["id"])
                refresh()

        row = tk.Frame(d, bg=BG)
        row.pack(pady=4)
        ttk.Button(row, text="↩ שחזר את הנבחרת", style="Accent.TButton", command=do_restore).pack(side="left", padx=4)
        ttk.Button(row, text="מחק נבחרת לצמיתות", style="Plain.TButton", command=do_purge).pack(side="left", padx=4)
        ttk.Button(row, text="רוקן כספת", style="Plain.TButton", command=do_empty).pack(side="left", padx=4)
        refresh()

        n = len(load_changes())
        tk.Label(d, text=f"⚡ שינויי הפעלה / משימות / שירותים שנשמרו: {n}", bg=BG, fg=HEADER,
                 font=("Segoe UI", 11, "bold")).pack(pady=(14, 2))

        def do_undo_perf():
            if not load_changes():
                messagebox.showinfo("שחזור", "אין שינויים לשחזר.", parent=d)
                return
            ok, bad = undo_changes()
            messagebox.showinfo("שחזור", f"שוחזרו {ok}, נכשלו {bad}.\nייתכן שצריך הפעלה מחדש.", parent=d)
            d.destroy()
        ttk.Button(d, text="↩ שחזר הפעלה / משימות / שירותים", style="Plain.TButton",
                   command=do_undo_perf).pack(pady=(0, 14))

    # --- דוח ---
    def build_report(self, per_cat=30):
        L = []
        add = L.append
        vault = self.use_vault.get()
        letter = {"green": "G", "yellow": "Y", "red": "R"}
        state = lambda iid: "DELETE" if self.checked.get(iid) else "KEEP"
        cnt = {"files": [0, 0], "vault": [0, 0], "prog": [0, 0], "perf": [0, 0]}
        red_on = 0
        for iid, it in self.items.items():
            if not self.checked.get(iid):
                continue
            if it["rec"] == "red":
                red_on += 1
            k = ("prog" if it["prog"] else "perf" if it["perf"]
                 else "vault" if (vault and goes_to_vault(it)) else "files")
            cnt[k][0] += 1
            if k in ("files", "vault"):
                cnt[k][1] += it["size"]
        add(f"=== PC Cleaner - דוח סריקה (v{VERSION}) ===")
        add(f"תאריך: {time.strftime('%Y-%m-%d %H:%M')} | משך סריקה: {self.meta['secs']:.0f} שניות")
        add(f"מחשב: {os.environ.get('COMPUTERNAME', '?')} | {platform.platform()} | מנהל: {'כן' if is_admin() else 'לא'}")
        add("חומרה: " + getattr(self, "sysinfo_text", ""))
        add("מילות הגנה מובנות: " + ", ".join(DEFAULT_KEYWORDS))
        add("מילות הגנה אישיות: " + (", ".join(KEYWORDS) or "-"))
        add("פרופיל: " + (PROFILE["name"] or "-"))
        if self.deepfreeze:
            add("Deep Freeze: זוהה (ודא מצב Thawed לפני ניקוי, אחרת הכל מתבטל באתחול)")
        add("מקרא: G=מומלץ למחוק | Y=לבדיקה | R=מומלץ לשמור | DELETE=מסומן לביצוע | KEEP=יישאר")
        add(f"סיכום: מחיקה ישירה {cnt['files'][0]} ({fmt_size(cnt['files'][1])}) | "
            f"כספת {cnt['vault'][0]} ({fmt_size(cnt['vault'][1])}) | הסרת תוכנות {cnt['prog'][0]} | "
            f"השבתות {cnt['perf'][0]} | R שסומנו למחיקה: {red_on}")
        add("")
        progs = sorted((i for i in self.items.items() if i[1]["prog"]),
                       key=lambda x: (REC_ORDER[x[1]["rec"]], x[1]["label"].lower()))
        add(f"--- תוכנות מותקנות ({len(progs)}) ---")
        for iid, it in progs:
            inf = PROG_INFO[it["path"]]
            add(f"[{state(iid)}][{letter[it['rec']]}] {inf['name']} | {inf['publisher']} | v{inf['ver']} | "
                f"{fmt_size(inf['size']) if inf['size'] else '?'} | {inf['loc'] or '-'} | {it['reason']}")
        add("")
        for ci in sorted(self.cat_items, key=lambda c: (KIND_ORDER[cat_kind(c)], c)):
            if ci == PROG_CI:
                continue
            n, total = self.meta["cats"].get(ci, (0, 0))
            lim = 300 if ci in PERF_CIS else per_cat
            add(f"--- {cat_section_label(ci, vault)}: {n} פריטים"
                + ("" if ci in PERF_CIS else f", {fmt_size(total)}") + " ---")
            for iid in self.cat_items[ci][:lim]:
                it = self.items[iid]
                tag = f"[{state(iid)}][{letter[it['rec']]}]"
                if it["perf"]:
                    pi = PERF_INFO[it["path"]]
                    add(f"{tag} {pi['kind']} | {pi['name']} | {pi['cmd_safe'][:160]} | {it['reason']}")
                else:
                    add(f"{tag} {fmt_size(it['size'])} | {it['path'] if it['path'] != RECYCLE else 'RecycleBin'}"
                        f" | {it['reason']}")
            if n > lim:
                add(f"... ועוד {n - lim} פריטים")
            add("")
        empty = [c[0] for i, c in enumerate(CATEGORIES) if i not in self.cat_items]
        if empty:
            add("קטגוריות שלא נמצא בהן כלום: " + ", ".join(empty))
        reds = [(it["size"], it["path"], it["reason"], iid) for iid, it in self.items.items()
                if it["rec"] == "red" and not it["prog"] and not it["perf"]]
        add("")
        add(f"--- קבצים/תיקיות שמומלץ לשמור - R ({len(reds)}) ---")
        for sz, p, why, iid in sorted(reds, reverse=True)[:60]:
            add(f"[{state(iid)}][R] {fmt_size(sz)} | {p} | {why}")
        return "\n".join(L)

    def copy_report(self):
        text = self.build_report()
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()
        saved = ""
        for f in (os.path.join(out_dir(), "Reports", time.strftime("report-%Y%m%d-%H%M%S.txt")),
                  os.path.join(os.path.dirname(CONFIG_FILES[1]), "report.txt")):
            try:
                os.makedirs(os.path.dirname(f), exist_ok=True)
                with open(f, "w", encoding="utf-8") as fh:
                    fh.write(text)
                saved = f
                break
            except OSError:
                continue
        messagebox.showinfo("הדוח מוכן",
                            "הדוח הועתק ללוח. הדבק אותו (Ctrl+V) בצ'אט.\n"
                            "השאר את התוכנה פתוחה עד שהדבקת.\n\n"
                            + (f"נשמר גם בקובץ:\n{saved}" if saved else ""))

    # --- הגדרות הגנה ---
    def protect_dialog(self):
        d = tk.Toplevel(self)
        d.title("הגדרות הגנה")
        d.geometry("540x540")
        d.configure(bg=BG)
        d.transient(self)
        tk.Label(d, bg=BG, justify="right", wraplength=500, font=("Segoe UI", 10),
                 text="מילות הגנה (שורה לכל מילה): כל תוכנה, תיקייה, קובץ, שירות או משימה ששמם מכיל אחת "
                      "מהמילים יסומנו 🔴 'מומלץ לשמור' ולא יסומנו מראש.\n"
                      "שום דבר לא נעול - אפשר לסמן אותם ידנית אם צריך.\n\n"
                      "מובנות (תמיד פעילות): " + ", ".join(DEFAULT_KEYWORDS)).pack(padx=14, pady=10)
        txt = tk.Text(d, height=12, font=("Segoe UI", 11))
        txt.pack(fill="both", expand=True, padx=14)
        txt.insert("1.0", "\n".join(KEYWORDS))

        def save():
            global KEYWORDS
            KEYWORDS = [l.strip() for l in txt.get("1.0", "end").splitlines() if l.strip()]
            ok = save_keywords(KEYWORDS)
            messagebox.showinfo("נשמר" if ok else "שגיאה",
                                "ההגדרות נשמרו. לחץ 'סרוק' כדי להחיל." if ok else "לא ניתן לשמור.")
            d.destroy()
        ttk.Button(d, text="שמור", style="Accent.TButton", command=save).pack(pady=10)

    # --- סריקה ---
    def start_scan(self):
        if self.busy:
            return
        self.busy = True
        self.t0 = time.time()
        self.cancel.clear()
        self.tree.delete(*self.tree.get_children())
        self.items.clear()
        self.checked.clear()
        self.cat_items = {}
        self.btn_scan.config(state="disabled")
        self.btn_clean.config(state="disabled")
        self.spinner.start()
        self.btn_report.config(state="disabled")
        self.show_overlay("scan", "סורק את המחשב")
        threading.Thread(target=self._scan_thread, daemon=True).start()

    def _scan_thread(self):
        last = [0.0]

        def cb(msg, frac, ceil, force=False):
            now = time.time()
            if not force and now - last[0] < 0.04:
                return
            last[0] = now
            self.after(0, lambda: self.on_progress(msg, frac, ceil))
        try:
            log("scan: start")
            res, info = scan(cb, self.cancel)
        except Exception:
            log_exc("scan")
            self.after(0, lambda: self._fail("הסריקה נכשלה"))
            return
        log(f"scan: done, {len(res)} items")
        self.after(0, lambda: self._scan_done(res, info))

    def _scan_done(self, results, sysinfo=""):
        self.sysinfo_text = sysinfo
        self.sysinfo.config(text=sysinfo)
        self.spinner.stop()
        self.ring.finish()
        self.update_idletasks()
        kw = keyword_tokens()
        by_cat = {}
        for ci, p, sz in results:
            by_cat.setdefault(ci, []).append((p, sz))
        self.meta = {"secs": time.time() - getattr(self, "t0", time.time()),
                     "cats": {c: (len(l), sum(z for _, z in l)) for c, l in by_cat.items()}}
        self.items.clear()
        self.checked.clear()
        self.cat_items = {}
        self.deepfreeze = deepfreeze_present()
        n = 0
        for ci in sorted(by_cat):
            lst = sorted(by_cat[ci], key=lambda x: -x[1])[:MAX_ITEMS_PER_CATEGORY]
            kids = []
            for p, sz in lst:
                n += 1
                iid = f"i{n}"
                it = {"ci": ci, "path": p, "size": sz, "prog": p in PROG_INFO, "perf": p in PERF_INFO,
                      "label": p, "guard": False}
                if p == RECYCLE:
                    it["label"] = "(כל תוכן סל המחזור)"
                    rec, reason, default = classify_file(ci, p, sz, kw)
                elif it["prog"]:
                    inf = PROG_INFO[p]
                    it["label"] = inf["name"] + (f"   [{inf['publisher']}]" if inf["publisher"] else "")
                    it["guard"] = inf["guard"]
                    rec, reason, default = inf["rec"], inf["reason"], inf["default"]
                    if profile_keeps(inf["name"], "programs"):
                        rec, reason, default = "red", f"נשמר בפרופיל: {PROFILE['name']}", False
                elif it["perf"]:
                    inf = PERF_INFO[p]
                    it["label"] = inf["label"]
                    it["guard"] = inf["guard"]
                    rec, reason, default = inf["rec"], inf["reason"], inf["default"]
                    if profile_keeps(inf["name"], "perf"):
                        rec, reason, default = "red", f"נשמר בפרופיל: {PROFILE['name']}", False
                else:
                    it["guard"] = path_protected(p, kw)
                    rec, reason, default = classify_file(ci, p, sz, kw)
                it.update(rec=rec, reason=reason, default=default)
                self.items[iid] = it
                kids.append(iid)
            self.cat_items[ci] = kids
        link_service_programs(self.items)
        for iid, it in self.items.items():
            self.checked[iid] = it["default"]
        self.open_cats = None
        self.render()
        self.busy = False
        self.btn_scan.config(state="normal")
        self.btn_report.config(state="normal")
        self.pbar.config(value=0)
        self.after(250, self.hide_overlay)
        msg = "הסריקה הסתיימה - 🟢 מסומן מראש, 🟡 ו-🔴 להחלטה שלך"
        if self.deepfreeze:
            msg += "   |   ❄ זוהה Deep Freeze"
        self.status.config(text=msg)
        self.update_total()

    # --- תצוגה ---
    def _schedule_render(self):
        if self._rt:
            self.after_cancel(self._rt)
        self._rt = self.after(250, self.render)

    def _track_open(self, state):
        iid = self.tree.focus()
        if iid.startswith("c") and self.open_cats is not None:
            (self.open_cats.add if state else self.open_cats.discard)(iid)

    def _visible(self, iid, flt, q):
        it, on = self.items[iid], self.checked.get(iid)
        if flt == FILTERS[1] and it["rec"] != "green":
            return False
        if flt == FILTERS[2] and it["rec"] != "yellow":
            return False
        if flt == FILTERS[3] and it["rec"] != "red":
            return False
        if flt == FILTERS[4] and not on:
            return False
        if flt == FILTERS[5] and on:
            return False
        return not q or q in f"{it['label']} {it['reason']}".lower()

    def _row_text(self, iid):
        it = self.items[iid]
        mark = self.CHK if self.checked.get(iid) else self.UNCHK
        return f"{mark}  {REC_ICON[it['rec']]}  {it['label']}"

    def _row_tag(self, iid):
        on = self.checked.get(iid)
        return "warn" if (on and self.items[iid]["rec"] == "red") else ("on" if on else "off")

    def _action_text(self, it):
        if it["prog"]:
            return "הסרת תוכנה"
        if it["perf"]:
            return "השבתה (הפיך)"
        if it["path"] == RECYCLE:
            return "ריקון"
        return "→ כספת" if (self.use_vault.get() and goes_to_vault(it)) else "מחיקה"

    @staticmethod
    def _size_text(it):
        return "" if ((it["prog"] or it["perf"]) and it["size"] <= 1) else fmt_size(it["size"])

    def render(self):
        self._rt = None
        if not self.cat_items:
            return
        tree = self.tree
        flt, q = self.filter_var.get(), self.search_var.get().strip().lower()
        active = flt != FILTERS[0] or bool(q)
        if self.open_cats is None:
            self.open_cats = {f"c{ci}" for ci in self.cat_items if cat_kind(ci) != "junk"}
        tree.delete(*tree.get_children())
        for ci in sorted(self.cat_items, key=lambda c: (KIND_ORDER[cat_kind(c)], c)):
            iids = [i for i in self.cat_items[ci] if self._visible(i, flt, q)]
            if not iids:
                continue
            cid = f"c{ci}"
            tree.insert("", "end", iid=cid, text="", tags=("cat",), open=active or cid in self.open_cats,
                        values=("", "", ""))
            for iid in iids:
                it = self.items[iid]
                tree.insert(cid, "end", iid=iid, text=self._row_text(iid), tags=(self._row_tag(iid),),
                            values=(self._action_text(it), it["reason"], self._size_text(it)))
            self._cat_text(cid)
        self.update_total()

    # --- סימונים ---
    def _cat_text(self, cid):
        ci = int(cid[1:])
        kids = self.tree.get_children(cid)
        n_on = sum(1 for k in kids if self.checked.get(k))
        mark = self.CHK if kids and n_on == len(kids) else (self.PART if n_on else self.UNCHK)
        sz = sum(self.items[k]["size"] for k in kids if self.checked.get(k)) \
            if cat_kind(ci) in ("junk", "personal") else 0
        self.tree.item(cid, text=f"{mark}  {cat_section_label(ci, self.use_vault.get())}",
                       values=("", f"{n_on} מתוך {len(kids)} מסומנים", ltr(fmt_size(sz)) if sz else ""))

    def _set_item(self, iid, state):
        self.checked[iid] = bool(state)
        if self.tree.exists(iid):
            self.tree.item(iid, text=self._row_text(iid), tags=(self._row_tag(iid),))

    def toggle(self, iid):
        if iid.startswith("c"):
            kids = self.tree.get_children(iid)
            targets = [k for k in kids if self.items[k]["rec"] != "red"]      # קבוצה לא מסמנת 🔴
            state = not (targets and all(self.checked.get(k) for k in targets))
            for k in kids:
                if state and self.items[k]["rec"] == "red":
                    continue
                self._set_item(k, state)
            self._cat_text(iid)
        else:
            self._set_item(iid, not self.checked.get(iid))
            self._cat_text(self.tree.parent(iid))
        self.update_total()

    def on_click(self, ev):
        iid = self.tree.identify_row(ev.y)
        if iid and "indicator" not in self.tree.identify_element(ev.x, ev.y):
            self.toggle(iid)
            return "break"

    def set_all(self, state):
        """סימון / ביטול של מה שמוצג כרגע (לפי הסינון). 'סמן הכל' אף פעם לא מסמן 🔴."""
        flt, q = self.filter_var.get(), self.search_var.get().strip().lower()
        for iid, it in self.items.items():
            if self._visible(iid, flt, q):
                self.checked[iid] = bool(state) and it["rec"] != "red"
        self.render()

    def reset_defaults(self):
        for iid, it in self.items.items():
            self.checked[iid] = it["default"]
        self.render()

    def selected(self):
        return [(i, self.items[i]) for i in self.items if self.checked.get(i)]

    def update_total(self):
        dn = ds = pn = kn = xn = warn = 0
        for iid, it in self.items.items():
            if not self.checked.get(iid):
                kn += 1
                continue
            if it["rec"] == "red":
                warn += 1
            if it["prog"]:
                pn += 1
            elif it["perf"]:
                xn += 1
            else:
                dn += 1
                ds += it["size"]
        self.v_del.config(text=ltr(fmt_size(ds)))
        self.s_del.config(text=f"{dn} קבצים ותיקיות" + (f"  ·  ⚠ {warn} נגד המלצה" if warn else ""))
        self.v_prog.config(text=str(pn))
        self.s_prog.config(text="תוכנות יוסרו")
        self.v_keep.config(text=str(kn))
        self.s_keep.config(text="פריטים נשארים")
        self.v_perf.config(text=str(xn))
        self.s_perf.config(text="פריטי הפעלה/משימות/שירותים")
        self.btn_clean.config(state="normal" if (dn or pn or xn) and not self.busy else "disabled")

    def refresh_kept(self):
        t = self.kept
        t.delete(*t.get_children())
        rows = [(REC_ORDER[it["rec"]], -it["size"], it) for iid, it in self.items.items()
                if not self.checked.get(iid)]
        rows.sort(key=lambda r: (r[0], r[1]))
        for _o, _s, it in rows[:1500]:
            t.insert("", "end", text=f"{REC_ICON[it['rec']]}  {it['label']}",
                     values=(it["reason"], self._size_text(it)), tags=("keep",))

    # --- מחיקה ---
    def confirm_clean(self):
        todo = self.selected()
        if not todo:
            return
        nprog = sum(1 for _, it in todo if it["prog"])
        nperf = sum(1 for _, it in todo if it["perf"])
        nfiles = len(todo) - nprog - nperf
        size = sum(it["size"] for _, it in todo if not (it["prog"] or it["perf"]))
        use_vault = self.use_vault.get()
        dry = self.dry_run.get()
        vault_items = [it for _, it in todo if use_vault and goes_to_vault(it)]
        nvault, svault = len(vault_items), sum(it["size"] for it in vault_items)
        head = "🧪 הדמיה בלבד - לא ישונה דבר. היה קורה:\n" if dry else "עומדים:\n"
        msg = head + (""
               f"• להסיר {nprog} תוכנות (לא ניתן לשחזר!)\n"
               f"• להשבית {nperf} פריטי הפעלה/משימות/שירותים (הפיך)\n"
               f"• להעביר לכספת {nvault} פריטים אישיים, כ-{ltr(fmt_size(svault))} (שחזור עד {VAULT_DAYS} ימים)\n"
               f"• למחוק לצמיתות {nfiles - nvault} פריטים, כ-{ltr(fmt_size(size - svault))}\n")
        if not use_vault and any(goes_to_vault(it) for _, it in todo):
            msg += "⚠ הכספת כבויה: קבצים אישיים יימחקו לצמיתות!\n"
        reds = [it for _, it in todo if it["rec"] == "red"]
        if reds:
            names = "\n".join("   • " + (it["label"] if len(it["label"]) < 70 else it["label"][:67] + "...")
                              for it in reds[:8])
            more = f"\n   ... ועוד {len(reds) - 8}" if len(reds) > 8 else ""
            msg += f"\n⚠ סימנת {len(reds)} פריטים 🔴 שההמלצה היא לשמור:\n{names}{more}\n"
        if self.deepfreeze and not dry:
            msg += ("\n❄ זוהה Deep Freeze. אם המחשב במצב Frozen, כל מה שייעשה (כולל הלוגים) "
                    "יתבטל באתחול הבא. ודא שהוא במצב Thawed.\n")
        msg += "\nלהמשיך?"
        if not any(i["guard"] for i in self.items.values()):
            if not messagebox.askyesno(
                    "אזהרה - אין פריטים עם מילת הגנה",
                    "לא נמצא אף פריט שתואם למילות ההגנה.\n"
                    "אם קסיוק / וידאוף מותקנות במחשב הזה, כנראה שהשמות אינם תואמים.\n"
                    "בדוק ב'הגדרות הגנה'.\n\nלהמשיך בכל זאת?", icon="warning"):
                return
        if not messagebox.askyesno("אישור הדמיה" if dry else "אישור מחיקה", msg, icon="warning"):
            return
        if not dry:
            from tkinter import simpledialog
            ans = simpledialog.askstring("אישור סופי", "כדי לאשר, הקלד את המילה:  מחק", parent=self)
            if (ans or "").strip() != "מחק":
                messagebox.showinfo("בוטל", "לא נמחק דבר.")
                return
        self.busy = True
        self.btn_clean.config(state="disabled")
        self.btn_scan.config(state="disabled")
        self.spinner.start()
        self.show_overlay("clean", "מריץ הדמיה" if dry else "מנקה את המחשב")
        stamp = time.strftime("%Y%m%d-%H%M%S")
        try:                                  # צילום מצב לפני הניקוי: רשימת תוכנות/שירותים/משימות
            if dry:
                raise OSError("dry run")
            inv = os.path.join(out_dir(), "Reports", f"inventory-{stamp}.txt")
            os.makedirs(os.path.dirname(inv), exist_ok=True)
            with open(inv, "w", encoding="utf-8") as fh:
                fh.write(self.build_report(per_cat=100))
        except Exception:
            pass
        batch = None
        if use_vault and not dry:
            try:
                batch = vault_new_batch()
            except OSError:
                batch = None
        log(f"clean: start dry={dry} vault={use_vault} items={len(todo)} red_selected={len(reds)}")
        threading.Thread(target=self._clean_thread, args=(todo, batch, dry, use_vault), daemon=True).start()

    def _clean_thread(self, todo, batch=None, dry=False, use_vault=False):
        freed = vaulted = failed = nprog = nperf = 0
        todo = sorted(todo, key=lambda x: 0 if x[1]["perf"] else (1 if x[1]["prog"] else 2))
        N = max(len(todo), 1)
        crashed = False
        try:
            for i, (_, it) in enumerate(todo, 1):
                path = it["path"]
                to_vault = (batch is not None or (dry and use_vault)) and goes_to_vault(it)
                if it["perf"]:
                    action, label = "perf", PERF_INFO[path]["name"]
                    msg = "משבית: " + label
                elif it["prog"]:
                    action, label = "uninstall", PROG_INFO[path]["name"]
                    msg = "מסיר תוכנה: " + label
                else:
                    label = "RecycleBin" if path == RECYCLE else path
                    action = "vault" if to_vault else "delete"
                    nm = "סל המחזור" if path == RECYCLE else os.path.basename(path)
                    msg = ("מעביר לכספת: " if to_vault else "מוחק: ") + nm
                self.after(0, lambda m=msg, v=i - 1: self.on_progress(m, v / N, (v + 0.92) / N, f"{v}/{N}"))
                moved = False
                try:
                    if dry:
                        ok, moved = True, to_vault
                    elif it["perf"]:
                        ok = apply_perf(PERF_INFO[path])
                    elif it["prog"]:
                        ok = uninstall_program(PROG_INFO[path])
                    elif to_vault:
                        ok = moved = vault_move(batch, path, it["size"])
                    else:
                        ok = empty_recycle_bin() if path == RECYCLE else delete_path(path)
                except Exception:
                    log_exc(f"{action} {label}")
                    ok = False
                log(f"{'DRY ' if dry else ''}{action} {'OK' if ok else 'FAIL'}: {redact(label)}")
                if ok:
                    if it["prog"]:
                        nprog += 1
                    elif it["perf"]:
                        nperf += 1
                    elif moved:
                        vaulted += it["size"]
                    else:
                        freed += it["size"]
                else:
                    failed += 1
                self.after(0, lambda v=i: self.on_progress(f"הושלמו {v} מתוך {N}", v / N, v / N, f"{v}/{N}"))
        except Exception:
            crashed = True
            log_exc("clean loop")
        finally:
            if batch is not None:
                vault_save(batch)
        if crashed:
            self.after(0, lambda: self._fail("הניקוי הופסק בשגיאה. מה שכבר בוצע נשמר ביומן."))
            return
        log(f"clean: done freed={freed} vaulted={vaulted} failed={failed}")
        self.after(0, lambda: self._clean_done(freed, failed, vaulted, dry, nprog, nperf))

    def _clean_done(self, freed, failed, vaulted=0, dry=False, nprog=0, nperf=0):
        self.spinner.stop()
        self.ring.finish()
        self.hide_overlay()
        self.busy = False
        self.btn_scan.config(state="normal")
        if dry:
            self.status.config(text="ההדמיה הסתיימה - לא שונה דבר")
            messagebox.showinfo("ההדמיה הסתיימה",
                                "לא שונה דבר במחשב.\n"
                                f"היו מתפנים כ-{ltr(fmt_size(freed))}\n"
                                f"היו עוברים לכספת כ-{ltr(fmt_size(vaulted))}\n"
                                f"היו מוסרות {nprog} תוכנות ומושבתים {nperf} פריטים.\n"
                                f"פריטים שהיו מדולגים: {failed}")
            self.update_total()
            return
        text = f"התפנו כ-{ltr(fmt_size(freed))}"
        if vaulted:
            text += f"\nהועברו לכספת כ-{ltr(fmt_size(vaulted))} (שחזור: '↩ שחזור וכספת')"
        self.status.config(text="הסתיים! " + text.replace("\n", " | "))
        messagebox.showinfo("סיום", f"{text}.\nפריטים שדולגו: {failed}\nיומן: {log_dir()}")
        self.start_scan()


if __name__ == "__main__":
    if os.name != "nt":
        print("התוכנה מיועדת ל-Windows בלבד.")
        sys.exit(1)
    App().mainloop()
