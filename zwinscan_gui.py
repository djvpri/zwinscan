#!/usr/bin/env python3
"""ZWinScan GUI — Windows Application Security Analyzer"""

import sys, os, time, datetime, json, re, base64, logging, traceback, subprocess
from pathlib import Path
from typing import List
from dataclasses import dataclass

# =========================================================
# Logging & crash handler  (setup FIRST, before anything else)
# =========================================================

_LOG_DIR  = Path.home() / '.zwinscan'
_LOG_DIR.mkdir(exist_ok=True)
LOG_FILE  = _LOG_DIR / 'zwinscan.log'

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
    ],
)
log = logging.getLogger('zwinscan')
log.info('App started')


def _excepthook(exc_type, exc_value, exc_tb):
    """Tangkap semua exception yang tidak tertangani."""
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_tb)
        return
    msg = ''.join(traceback.format_exception(exc_type, exc_value, exc_tb))
    log.critical(f'Unhandled exception:\n{msg}')
    try:
        from PyQt6.QtWidgets import QMessageBox, QApplication
        if QApplication.instance():
            dlg = QMessageBox()
            dlg.setWindowTitle('ZWinScan — Crash')
            dlg.setIcon(QMessageBox.Icon.Critical)
            dlg.setText(
                f'<b>Error tidak tertangani:</b><br><br>'
                f'{exc_type.__name__}: {exc_value}<br><br>'
                f'Log tersimpan di:<br><code>{LOG_FILE}</code>'
            )
            dlg.setDetailedText(msg)
            dlg.exec()
    except Exception:
        pass
    sys.__excepthook__(exc_type, exc_value, exc_tb)


sys.excepthook = _excepthook

# ── optional deps ──────────────────────────────────────────
try:
    import pefile; HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    from google import genai as _genai_mod; HAS_GENAI = True
except ImportError:
    HAS_GENAI = False

# ── config helpers ─────────────────────────────────────────
_CONFIG_FILE = _LOG_DIR / 'config.json'

def _load_config() -> dict:
    try: return json.loads(_CONFIG_FILE.read_text(encoding='utf-8'))
    except: return {}

def _save_config(cfg: dict):
    _CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding='utf-8')

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFileDialog, QScrollArea,
    QFrame, QSizePolicy, QLineEdit,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QUrl, QPoint
from PyQt6.QtGui import (
    QPainter, QColor, QDesktopServices, QDragEnterEvent,
    QDropEvent, QPen, QFont, QIcon, QPixmap, QShortcut, QKeySequence,
)

# =========================================================
# Scanner Core
# =========================================================

SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}

@dataclass
class Finding:
    severity: str
    category: str
    title: str
    detail: str = ''


class ZWinScanner:

    SECRET_PATTERNS = [
        ('JWT token',            r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',        'CRITICAL'),
        ('Private key header',   r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',                         'CRITICAL'),
        ('AWS access key',       r'AKIA[0-9A-Z]{16}',                                                        'CRITICAL'),
        ('Gemini / Google key',  r'AIza[0-9A-Za-z\-_]{35}',                                                  'HIGH'),
        ('Anthropic key',        r'sk-ant-[A-Za-z0-9\-_]{40,}',                                              'HIGH'),
        ('URL with credentials', r'https?://[^:\s]{1,64}:[^@\s]{1,64}@[^\s]{6,}',                           'HIGH'),
        ('Database URL',         r'(postgres|mysql|mongodb|redis)://[^\s]{10,}',                              'HIGH'),
        ('Hardcoded password',   r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']',               'HIGH'),
        ('SSL verify=False',     r'verify\s*=\s*False',                                                       'HIGH'),
        ('Generic API key',      r'(?i)api[_-]?key\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']',               'MEDIUM'),
        ('Internal IP address',  r'(?<!\d)(192\.168\.|10\.\d+\.|172\.(1[6-9]|2\d|3[01])\.)\d+\.\d+(?!\d)', 'LOW'),
    ]

    def __init__(self, path: str):
        self.target   = Path(path)
        self.findings: List[Finding] = []

    def _add(self, sev, cat, title, detail=''):
        self.findings.append(Finding(sev, cat, title, detail))

    def check_pe_flags(self):
        if not HAS_PEFILE:
            self._add('INFO', 'PE Flags', 'pefile tidak terinstall — PE checks dilewati'); return
        try:
            pe = pefile.PE(str(self.target), fast_load=True)
            dc = pe.OPTIONAL_HEADER.DllCharacteristics
            aslr, hi, dep, cfg = bool(dc&0x40), bool(dc&0x20), bool(dc&0x100), bool(dc&0x4000)
            pe.close()
            if not aslr: self._add('HIGH','PE Flags','ASLR tidak aktif','Address Space Layout Randomization dinonaktifkan.')
            elif not hi: self._add('LOW', 'PE Flags','High Entropy ASLR tidak aktif','Aktifkan /HIGHENTROPYVA untuk entropy lebih luas pada 64-bit.')
            else:        self._add('INFO','PE Flags','ASLR + High Entropy ASLR aktif')
            if not dep:  self._add('HIGH',  'PE Flags','DEP/NX tidak aktif','Data Execution Prevention dinonaktifkan.')
            else:        self._add('INFO',  'PE Flags','DEP/NX aktif')
            if not cfg:  self._add('MEDIUM','PE Flags','Control Flow Guard (CFG) tidak aktif','CFG mencegah ROP/JOP attacks.')
            else:        self._add('INFO',  'PE Flags','CFG aktif')
        except Exception as e:
            self._add('INFO','PE Flags',f'Gagal parse PE: {e}')

    def check_hardcoded_secrets(self):
        try: data = self.target.read_bytes()
        except: return
        strings = self._strings(data)
        seen = set()
        for name, pat, sev in self.SECRET_PATTERNS:
            for s in strings:
                m = re.search(pat, s)
                if m:
                    key = (name, m.group(0)[:40])
                    if key in seen: continue
                    seen.add(key)
                    self._add(sev,'Strings',f'{name} ditemukan di binary',f'Match: {m.group(0)[:120]}')
        if b'_MEIPASS' in data or b'PyInstaller' in data:
            self._add('MEDIUM','Strings','PyInstaller bundle terdeteksi',
                      'Source dapat diekstrak:\n  pyinstxtractor ZOMET.exe\n  decompyle3 zomet5.pyc')
        if b'UPX!' in data or b'UPX0' in data:
            self._add('LOW','Strings','UPX compression terdeteksi','Dapat di-unpack: upx -d <file>')

    @staticmethod
    def _strings(data: bytes, n=8):
        r, b = [], []
        for c in data:
            if 0x20 <= c <= 0x7e: b.append(chr(c))
            else:
                if len(b) >= n: r.append(''.join(b))
                b = []
        if len(b) >= n: r.append(''.join(b))
        return r

    def check_credential_files(self):
        """Scan folder exe dan subfolder dangkal untuk file konfigurasi/credential."""
        exe_dir = self.target.parent
        CRED_NAMES = {
            'secret', 'secrets', 'credential', 'credentials', 'password',
            'passwd', 'token', 'auth', 'apikey', 'api_key', 'private',
        }
        CRED_EXTS  = {'.env', '.ini', '.toml', '.cfg', '.conf', '.json',
                      '.yaml', '.yml', '.xml', '.properties', '.key', '.pem'}
        # scan exe dir + shallow subdirs (config/, settings/, data/, resources/)
        search_dirs = [exe_dir]
        for sub in ('config', 'settings', 'data', 'resources', 'cfg', 'conf'):
            d = exe_dir / sub
            if d.is_dir():
                search_dirs.append(d)

        seen = set()
        for d in search_dirs:
            try:
                for f in d.iterdir():
                    if not f.is_file() or f in seen: continue
                    seen.add(f)
                    name_low = f.stem.lower()
                    if f.suffix.lower() in CRED_EXTS or any(k in name_low for k in CRED_NAMES):
                        self._inspect_config_file(f)
            except PermissionError:
                pass

    def _inspect_config_file(self, path):
        try:
            txt = path.read_text(encoding='utf-8', errors='ignore')
            if not txt.strip(): return
            # check each known secret pattern against file text
            for label, pattern, sev in self.SECRET_PATTERNS:
                m = re.search(pattern, txt)
                if m:
                    snippet = txt[max(0, m.start()-30):m.end()+60].strip()
                    self._add(sev, 'Credential Files',
                              f'{label} di {path.name}',
                              f'Path: {path}\nSnippet: ...{snippet}...')
        except: pass

    def check_network(self):
        try: data = self.target.read_bytes()
        except: return
        strings = self._strings(data)
        if any(('desktop-login' in s or '/callback' in s) and ('127.0.0.1' in s or 'localhost' in s) for s in strings):
            self._add('MEDIUM','Network / SSO','Local OAuth callback server terdeteksi',
                      'Proses lain bisa race untuk menangkap token SSO.\n'
                      'Mitigasi: validasi state parameter OAuth + PKCE flow.')
        for s in strings:
            if re.search(r'verify\s*=\s*False', s):
                self._add('HIGH','Network / SSO','SSL verify=False ditemukan',
                          f'String: {s[:100]}\nMemungkinkan MITM attack pada HTTPS.'); break

    # ------------------------------------------------------------------
    # Fitur baru
    # ------------------------------------------------------------------

    def check_imports(self):
        """Analisis import table — flag API berbahaya."""
        if not HAS_PEFILE:
            return
        INJECTION = {'CreateRemoteThread','VirtualAllocEx','WriteProcessMemory',
                     'NtWriteVirtualMemory','RtlCreateUserThread','QueueUserAPC'}
        EVASION   = {'IsDebuggerPresent','CheckRemoteDebuggerPresent',
                     'NtQueryInformationProcess','OutputDebugStringA'}
        EXEC      = {'WinExec','ShellExecuteA','ShellExecuteW','ShellExecuteExW',
                     'CreateProcessA','CreateProcessW'}
        PERSIST   = {'RegSetValueExA','RegSetValueExW','SHGetSpecialFolderPathA',
                     'SHGetSpecialFolderPathW','CreateServiceA','CreateServiceW'}
        try:
            pe = pefile.PE(str(self.target), fast_load=False)
            all_imports = {}
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode(errors='ignore').lower()
                    funcs = set()
                    for imp in entry.imports:
                        if imp.name:
                            funcs.add(imp.name.decode(errors='ignore'))
                    all_imports[dll] = funcs

            all_funcs = set().union(*all_imports.values()) if all_imports else set()
            found_inj  = all_funcs & INJECTION
            found_eva  = all_funcs & EVASION
            found_exec = all_funcs & EXEC
            found_per  = all_funcs & PERSIST

            if found_inj:
                self._add('CRITICAL','Import Table',
                          f'API code injection: {", ".join(sorted(found_inj))}',
                          'Fungsi ini digunakan untuk menyuntikkan kode ke proses lain.\n'
                          f'Detail: {", ".join(sorted(found_inj))}')
            if found_eva:
                self._add('HIGH','Import Table',
                          f'API anti-debugging/evasion: {", ".join(sorted(found_eva))}',
                          'Mendeteksi kehadiran debugger untuk menghindari analisis.\n'
                          f'Detail: {", ".join(sorted(found_eva))}')
            if found_per:
                self._add('MEDIUM','Import Table',
                          f'API persistence/autostart: {", ".join(sorted(found_per))}',
                          'Dapat digunakan untuk mendaftar ke startup Windows.\n'
                          f'Detail: {", ".join(sorted(found_per))}')
            if found_exec:
                self._add('LOW','Import Table',
                          f'API eksekusi proses: {", ".join(sorted(found_exec))}',
                          f'Menjalankan program/shell command.\nDetail: {", ".join(sorted(found_exec))}')

            dlls = list(all_imports.keys())
            self._add('INFO','Import Table',
                      f'{len(dlls)} DLL diimpor',
                      'DLLs: ' + ', '.join(dlls[:30]) + (f' ... (+{len(dlls)-30})' if len(dlls)>30 else ''))
            pe.close()
        except Exception as e:
            log.debug(f'check_imports error: {e}')

    def check_section_entropy(self):
        """Hitung Shannon entropy tiap PE section — entropy tinggi = packing/obfuscation."""
        if not HAS_PEFILE:
            return
        import math
        def entropy(data):
            if not data: return 0.0
            freq = [0]*256
            for b in data: freq[b] += 1
            n = len(data)
            return -sum((f/n)*math.log2(f/n) for f in freq if f)

        try:
            pe = pefile.PE(str(self.target), fast_load=False)
            high_sections = []
            details = []
            for sec in pe.sections:
                name = sec.Name.rstrip(b'\x00').decode(errors='ignore')
                data = sec.get_data()
                e    = entropy(data)
                details.append(f'{name:<10} entropy={e:.2f}  size={len(data)//1024}KB')
                if e > 7.2:
                    high_sections.append(f'{name}({e:.2f})')
            pe.close()

            if high_sections:
                self._add('HIGH','Entropy',
                          f'Section entropy tinggi: {", ".join(high_sections)}',
                          'Entropy > 7.2 mengindikasikan packing/obfuscation (UPX, custom packer).\n'
                          'Binary mungkin menyembunyikan payload.\n\n'
                          + '\n'.join(details))
            else:
                self._add('INFO','Entropy','Entropy semua section normal',
                          '\n'.join(details))
        except Exception as e:
            log.debug(f'check_section_entropy error: {e}')

    def check_compile_timestamp(self):
        """Baca compile timestamp dari PE header."""
        if not HAS_PEFILE:
            return
        import datetime as dt
        try:
            pe   = pefile.PE(str(self.target), fast_load=True)
            ts   = pe.FILE_HEADER.TimeDateStamp
            pe.close()
            compiled = dt.datetime.utcfromtimestamp(ts)
            now      = dt.datetime.utcnow()
            age_days = (now - compiled).days
            compiled_str = compiled.strftime('%Y-%m-%d %H:%M UTC')

            if ts == 0:
                self._add('MEDIUM','Timestamp','Compile timestamp dihapus (zero)',
                          'Timestamp = 0 bisa menandakan binary di-strip untuk menyembunyikan waktu kompilasi.')
            elif compiled > now:
                self._add('HIGH','Timestamp',
                          f'Timestamp di masa depan: {compiled_str}',
                          'Timestamp tidak valid — kemungkinan dimanipulasi.')
            elif age_days > 365*10:
                self._add('MEDIUM','Timestamp',
                          f'Binary sangat lama: dikompilasi {compiled_str} ({age_days//365} tahun lalu)',
                          'Binary sangat tua mungkin tidak mendapat security patch terbaru.')
            else:
                self._add('INFO','Timestamp',
                          f'Dikompilasi: {compiled_str} ({age_days} hari lalu)')
        except Exception as e:
            log.debug(f'check_compile_timestamp error: {e}')

    def check_urls(self):
        """Ekstrak URL dan domain dari binary — flag cleartext HTTP, hardcoded IP."""
        try:
            data    = self.target.read_bytes()
            strings = self._strings(data, n=10)
        except:
            return

        url_pat = re.compile(r'https?://[^\s\x00"\'<>]{8,}')
        ip_pat  = re.compile(r'\b(?!10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)'
                             r'(?:\d{1,3}\.){3}\d{1,3}\b')

        http_urls, ip_hits, seen_urls = [], [], set()
        for s in strings:
            for m in url_pat.finditer(s):
                u = m.group(0).rstrip('.,);')
                if u in seen_urls: continue
                seen_urls.add(u)
                if u.startswith('http://') and 'localhost' not in u and '127.0.0.1' not in u:
                    http_urls.append(u)
            for m in ip_pat.finditer(s):
                ip = m.group(0)
                parts = ip.split('.')
                if all(0 <= int(p) <= 255 for p in parts) and ip not in ('0.0.0.0','255.255.255.255'):
                    ip_hits.append(ip)

        if http_urls:
            self._add('MEDIUM','URLs',
                      f'{len(http_urls)} URL cleartext HTTP ditemukan',
                      'URL tanpa enkripsi memungkinkan MITM attack:\n' +
                      '\n'.join(f'  {u}' for u in http_urls[:20]))
        if ip_hits:
            uniq_ips = list(dict.fromkeys(ip_hits))[:20]
            self._add('LOW','URLs',
                      f'{len(uniq_ips)} public IP hardcoded ditemukan',
                      'IP hardcoded dapat digunakan untuk C2 atau bypass DNS:\n' +
                      '\n'.join(f'  {ip}' for ip in uniq_ips))
        if seen_urls:
            https_list = [u for u in seen_urls if u.startswith('https://')]
            if https_list:
                self._add('INFO','URLs',
                          f'{len(https_list)} URL HTTPS ditemukan',
                          '\n'.join(f'  {u}' for u in sorted(https_list)[:30]))

    def check_uac_manifest(self):
        """Periksa level UAC yang diminta di PE manifest."""
        try:
            data = self.target.read_bytes()
        except:
            return
        text = data.decode(errors='ignore')
        if 'requireAdministrator' in text:
            self._add('HIGH','UAC Manifest',
                      'Exe meminta hak Administrator (requireAdministrator)',
                      'Aplikasi selalu jalan sebagai Admin.\n'
                      'Jika tidak diperlukan, ini memperluas attack surface secara tidak perlu.')
        elif 'highestAvailable' in text:
            self._add('MEDIUM','UAC Manifest',
                      'Exe meminta highestAvailable privilege',
                      'Akan naik ke Admin jika user adalah Administrator.')
        elif 'asInvoker' in text:
            self._add('INFO','UAC Manifest','UAC level: asInvoker (hak normal)',
                      'Tidak meminta elevasi otomatis.')
        else:
            self._add('LOW','UAC Manifest','Manifest UAC tidak ditemukan',
                      'Tidak ada requestedExecutionLevel di manifest.\n'
                      'Windows akan menebak level privilege secara heuristik.')

        # PDB path leak
        pdb_m = re.search(rb'[A-Za-z]:\\[^\x00]{5,120}\.pdb', data)
        if pdb_m:
            try:
                pdb_path = pdb_m.group(0).decode(errors='ignore')
                self._add('LOW','UAC Manifest',
                          f'PDB path bocor: {Path(pdb_path).name}',
                          f'Path lengkap tersimpan di binary:\n{pdb_path}\n'
                          'Membocorkan struktur direktori dan nama proyek developer.')
            except: pass

    def check_signature(self):
        """Cek digital signature exe via PowerShell Get-AuthenticodeSignature."""
        import subprocess
        try:
            cmd = (
                f'(Get-AuthenticodeSignature -FilePath "{self.target}") | '
                'Select-Object -Property Status,SignerCertificate | '
                'ConvertTo-Json -Depth 3'
            )
            r = subprocess.run(
                ['powershell', '-NoProfile', '-NonInteractive', '-Command', cmd],
                capture_output=True, text=True, timeout=15
            )
            out = r.stdout.strip()
            if not out:
                self._add('MEDIUM','Signature','Tidak dapat membaca signature','PowerShell tidak mengembalikan data.')
                return

            sig = json.loads(out)
            status = sig.get('Status','') if isinstance(sig, dict) else ''
            cert   = sig.get('SignerCertificate') if isinstance(sig, dict) else None

            if status == 'Valid':
                subject = ''
                if cert and isinstance(cert, dict):
                    subject = cert.get('Subject','') or cert.get('FriendlyName','')
                self._add('INFO','Signature',
                          f'Tanda tangan valid: {subject[:80] or "Unknown signer"}')
            elif status == 'NotSigned':
                self._add('HIGH','Signature',
                          'Exe tidak ditandatangani (unsigned)',
                          'Tidak ada digital signature.\n'
                          'Tidak ada jaminan integritas — bisa saja dimodifikasi.')
            elif status == 'HashMismatch':
                self._add('CRITICAL','Signature',
                          'Hash mismatch — binary kemungkinan dimodifikasi!',
                          'Tanda tangan ada tapi hash tidak cocok.\n'
                          'Binary mungkin telah di-tamper/di-trojanize.')
            elif status in ('UnknownError','NotTrusted'):
                self._add('MEDIUM','Signature',
                          f'Signature tidak dipercaya: status={status}',
                          'Sertifikat tidak dikenali atau tidak dalam trust chain Windows.')
            else:
                self._add('LOW','Signature',f'Status signature: {status}')
        except subprocess.TimeoutExpired:
            self._add('INFO','Signature','Cek signature timeout (>15s)')
        except Exception as e:
            log.debug(f'check_signature error: {e}')


# =========================================================
# AI Modules
# =========================================================

def _ai_call(api_key: str, prompt: str, timeout: int = 45) -> str:
    """Single Gemini call, returns text or raises."""
    if not HAS_GENAI:
        raise ImportError('google-genai tidak terinstall')
    client = _genai_mod.Client(api_key=api_key)
    resp   = client.models.generate_content(
        model='gemini-2.5-flash', contents=prompt)
    return resp.text.strip()


def ai_classify_strings(api_key: str, strings: list, exe_name: str) -> dict:
    """Kirim sampel string suspicious ke Gemini untuk diklasifikasikan."""
    sample = '\n'.join(strings[:120])
    prompt = f"""Kamu adalah reverse engineer. Berikut string-string yang diekstrak dari binary Windows exe bernama "{exe_name}".

Strings:
{sample}

Klasifikasikan string yang BENAR-BENAR mencurigakan saja (abaikan string library/framework normal).
Kembalikan HANYA JSON valid:
{{
  "suspicious": [
    {{"string": "<string>", "reason": "<penjelasan singkat>", "severity": "CRITICAL|HIGH|MEDIUM|LOW"}}
  ],
  "notable": "<observasi menarik 1-2 kalimat, atau kosong jika tidak ada>"
}}"""
    raw = _ai_call(api_key, prompt)
    m   = re.search(r'\{[\s\S]+\}', raw)
    return json.loads(m.group(0)) if m else {'suspicious': [], 'notable': raw[:200]}


def ai_executive_summary(api_key: str, findings: list, exe_name: str, exe_size: str) -> dict:
    """Kirim semua findings ke Gemini, dapatkan ringkasan eksekutif."""
    lines = []
    for f in findings:
        lines.append(f'[{f.severity}] {f.category} — {f.title}')
        if f.detail:
            lines.append(f'  Detail: {f.detail[:200]}')
    findings_text = '\n'.join(lines)

    prompt = f"""Kamu adalah security analyst senior. Analisis hasil scan keamanan aplikasi Windows ini.

Target: {exe_name} ({exe_size})
Total findings: {len(findings)}

=== FINDINGS ===
{findings_text}
=== END ===

Berikan analisis dalam HANYA JSON valid:
{{
  "risk_score": <1-10>,
  "verdict": "<AMAN|MENCURIGAKAN|BERBAHAYA>",
  "app_type": "<tipe aplikasi berdasarkan analisis, mis: trading platform, media player, dll>",
  "summary": "<2-3 kalimat ringkasan risiko dalam Bahasa Indonesia>",
  "top_concerns": ["<concern 1>", "<concern 2>", "<concern 3>"],
  "remediation": ["<langkah konkret 1>", "<langkah konkret 2>", "<langkah konkret 3>"]
}}"""
    raw = _ai_call(api_key, prompt, timeout=60)
    m   = re.search(r'\{[\s\S]+\}', raw)
    return json.loads(m.group(0)) if m else {
        'risk_score': 0, 'verdict': 'TIDAK DIKETAHUI',
        'app_type': '?', 'summary': raw[:300],
        'top_concerns': [], 'remediation': []
    }


# =========================================================
# HTML Report
# =========================================================

def save_html(findings, target, out, duration=''):
    now   = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    tname = Path(target).name
    tsize = f'{Path(target).stat().st_size/1_048_576:.1f} MB'
    counts = {}
    for f in findings: counts[f.severity] = counts.get(f.severity,0)+1

    def _esc(s): return s.replace('\\','\\\\').replace('`','\\`').replace('$','\\$')

    js = 'const F=[\n'
    for f in sorted(findings, key=lambda x: SEV_ORDER.get(x.severity,9)):
        js += f'  {{s:{repr(f.severity)},c:{repr(f.category)},t:{repr(f.title)},d:`{_esc(f.detail)}`}},\n'
    js += ']'

    cards = ''.join(
        f'<div class="sc" data-s="{s}" onclick="flt(\'{s}\')">'
        f'<b style="color:var(--{s.lower()})">{counts.get(s,0)}</b>'
        f'<span>{s}</span></div>'
        for s in ['CRITICAL','HIGH','MEDIUM','LOW']
    )

    html = f"""<!DOCTYPE html><html lang="id"><head><meta charset="UTF-8">
<title>ZWinScan — {tname}</title>
<style>:root{{--bg:#050d1a;--sf:#0b1628;--ev:#101f35;--br:#162b47;--bh:#1e3a5f;--tx:#c8d8e8;--td:#4a6580;--tm:#2a3f58;--ac:#00dcb4;--critical:#f03737;--high:#f87325;--medium:#d4a017;--low:#3b8cf8;--info:#3d5570;--fm:'Consolas','SF Mono',monospace;--fu:system-ui,sans-serif;--r:6px}}
*{{box-sizing:border-box;margin:0;padding:0}}html,body{{height:100%;background:var(--bg);color:var(--tx);font-family:var(--fu);font-size:14px}}
.bar{{position:fixed;top:0;left:0;right:0;height:50px;background:rgba(5,13,26,.96);border-bottom:1px solid var(--br);display:flex;align-items:center;gap:16px;padding:0 24px;z-index:99;backdrop-filter:blur(8px)}}
.logo{{font-family:var(--fm);font-size:14px;font-weight:700;color:var(--ac);display:flex;align-items:center;gap:7px;white-space:nowrap}}
.sep{{width:1px;height:18px;background:var(--br)}}
.meta{{margin-left:auto;font-family:var(--fm);font-size:11px;color:var(--td);white-space:nowrap}}
.dot{{width:7px;height:7px;border-radius:50%;background:var(--ac);box-shadow:0 0 5px #00dcb450;display:inline-block;margin-right:5px;vertical-align:middle;animation:p 2.4s infinite}}
@keyframes p{{0%,100%{{opacity:1}}50%{{opacity:.3}}}}
.wrap{{display:flex;padding-top:50px;min-height:100vh}}
.side{{width:260px;flex-shrink:0;position:sticky;top:50px;height:calc(100vh - 50px);overflow-y:auto;border-right:1px solid var(--br);padding:20px 16px;display:flex;flex-direction:column;gap:20px}}
.slbl{{font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--tm);font-weight:600;margin-bottom:8px}}
.sg{{display:grid;grid-template-columns:1fr 1fr;gap:7px}}
.sc{{background:var(--sf);border:1px solid var(--br);border-radius:var(--r);padding:9px 10px;cursor:pointer;transition:all .15s;position:relative;overflow:hidden;text-align:center}}
.sc::before{{content:'';position:absolute;left:0;top:0;bottom:0;width:3px}}
.sc[data-s=CRITICAL]::before{{background:var(--critical)}} .sc[data-s=HIGH]::before{{background:var(--high)}} .sc[data-s=MEDIUM]::before{{background:var(--medium)}} .sc[data-s=LOW]::before{{background:var(--low)}}
.sc:hover,.sc.on{{border-color:var(--ac)}} .sc b{{font-family:var(--fm);font-size:20px;font-weight:700;display:block}} .sc span{{font-size:9px;color:var(--td);letter-spacing:.05em}}
.sa{{grid-column:1/-1;background:var(--sf);border:1px solid var(--br);border-radius:var(--r);padding:7px;font-size:12px;color:var(--td);text-align:center;cursor:pointer;transition:all .15s}}
.sa:hover,.sa.on{{border-color:var(--ac);color:var(--ac)}}
.ti{{font-size:11px;font-family:var(--fm)}} .ti+.ti{{margin-top:4px}} .tk{{color:var(--tm);display:inline-block;width:44px}} .tv{{color:var(--td);word-break:break-all}}
.main{{flex:1;min-width:0;padding:24px 28px}}
.mh{{display:flex;align-items:baseline;gap:10px;margin-bottom:18px}}
.mh h2{{font-size:15px;font-weight:600}} .mc{{font-family:var(--fm);font-size:12px;color:var(--td)}}
.fw{{position:relative}}
.sl{{position:absolute;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,rgba(0,220,180,.15),transparent);animation:sd 3s ease-in-out 1 forwards;pointer-events:none;z-index:5}}
@keyframes sd{{0%{{top:0;opacity:1}}85%{{top:100%;opacity:.5}}100%{{top:100%;opacity:0}}}}
.fi{{border:1px solid var(--br);border-radius:var(--r);margin-bottom:7px;background:var(--sf);position:relative;overflow:hidden;transition:border-color .15s}}
.fi::before{{content:'';position:absolute;left:0;top:0;bottom:0;width:3px}}
.fi[data-s=CRITICAL]{{--fs:var(--critical);--fb:rgba(240,55,55,.07)}} .fi[data-s=HIGH]{{--fs:var(--high);--fb:rgba(248,115,37,.07)}} .fi[data-s=MEDIUM]{{--fs:var(--medium);--fb:rgba(212,160,23,.07)}} .fi[data-s=LOW]{{--fs:var(--low);--fb:rgba(59,140,248,.07)}} .fi[data-s=INFO]{{--fs:var(--info);--fb:rgba(61,85,112,.05)}}
.fi::before{{background:var(--fs)}} .fi:hover{{border-color:var(--bh)}} .fi.op{{border-color:var(--fs)}}
.fh{{display:flex;align-items:center;gap:10px;padding:12px 12px 12px 16px;cursor:pointer;user-select:none}}
.fs{{font-family:var(--fm);font-size:10px;font-weight:700;color:var(--fs);letter-spacing:.05em;flex-shrink:0;width:56px}}
.fc{{font-family:var(--fm);font-size:10px;color:var(--td);flex-shrink:0;background:var(--ev);border:1px solid var(--br);border-radius:3px;padding:1px 6px;white-space:nowrap}}
.ft{{flex:1;font-size:13px;color:var(--tx);min-width:0}}
.fv{{color:var(--tm);font-size:10px;flex-shrink:0;transition:transform .2s}} .fi.op .fv{{transform:rotate(180deg)}}
.fb{{display:none;padding:0 12px 12px 16px;border-top:1px solid var(--br)}}
.fi.op .fb{{display:block}}
.fd{{font-family:var(--fm);font-size:12px;color:var(--td);line-height:1.7;white-space:pre-wrap;word-break:break-all;background:var(--fb);border-radius:4px;padding:10px 12px;margin-top:9px;border-left:2px solid var(--fs)}}
.em{{padding:40px 0;text-align:center;font-family:var(--fm);font-size:13px;color:var(--tm);display:none}} .em.on{{display:block}}
::-webkit-scrollbar{{width:4px}}::-webkit-scrollbar-thumb{{background:var(--bh);border-radius:2px}}
</style></head><body>
<div class="bar">
  <div class="logo"><svg width="16" height="16" viewBox="0 0 18 18" fill="none"><circle cx="9" cy="9" r="8" stroke="#00dcb4" stroke-width="1.5"/><path d="M9 4v5l3 3" stroke="#00dcb4" stroke-width="1.5" stroke-linecap="round"/><circle cx="9" cy="9" r="2" fill="#00dcb4" opacity=".4"/></svg>ZWinScan</div>
  <div class="sep"></div>
  <span style="font-family:var(--fm);font-size:12px;color:var(--td)">{tname} &nbsp;·&nbsp; {tsize}</span>
  <div class="meta"><span class="dot"></span>{now}{(' &nbsp;·&nbsp; '+duration) if duration else ''}</div>
</div>
<div class="wrap">
  <aside class="side">
    <div><div class="slbl">Ringkasan</div>
    <div class="sg">{cards}<div class="sa on" onclick="flt(null)">Semua temuan</div></div></div>
    <div><div class="slbl">Target</div>
    <div class="ti"><span class="tk">file</span><span class="tv">{tname}</span></div>
    <div class="ti"><span class="tk">size</span><span class="tv">{tsize}</span></div>
    <div class="ti"><span class="tk">scan</span><span class="tv">{now}</span></div></div>
  </aside>
  <main class="main">
    <div class="mh"><h2>Findings</h2><span class="mc" id="mc"></span></div>
    <div class="fw"><div class="sl"></div><div id="fl"></div><div class="em" id="em">Tidak ada temuan.</div></div>
  </main>
</div>
<script>
{js}
const O={{CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4}}
let af=null
function r(){{
  const fl=document.getElementById('fl'),em=document.getElementById('em'),mc=document.getElementById('mc')
  fl.innerHTML=''
  const v=[...F].sort((a,b)=>O[a.s]-O[b.s]).filter(f=>!af||f.s===af)
  mc.textContent=v.length+' dari '+F.length+' temuan'
  em.classList.toggle('on',v.length===0)
  v.forEach(f=>{{
    const el=document.createElement('div');el.className='fi';el.dataset.s=f.s
    el.innerHTML=`<div class="fh" onclick="this.parentElement.classList.toggle('op')"><span class="fs">${{f.s}}</span><span class="fc">${{f.c}}</span><span class="ft">${{f.t}}</span><span class="fv">▼</span></div><div class="fb"><div class="fd">${{f.d.replace(/</g,'&lt;')}}</div></div>`
    fl.appendChild(el)
  }})
}}
function flt(s){{af=s;document.querySelectorAll('.sc').forEach(c=>c.classList.toggle('on',c.dataset.s===s));document.querySelector('.sa').classList.toggle('on',!s);r()}}
r()
</script></body></html>"""

    Path(out).write_text(html, encoding='utf-8')


# =========================================================
# Worker Thread
# =========================================================

class ScanWorker(QThread):
    module_started  = pyqtSignal(str)
    module_done     = pyqtSignal(str, int, float)
    scan_done       = pyqtSignal(list, str)
    ai_summary_done = pyqtSignal(dict)   # executive summary result
    ai_strings_done = pyqtSignal(dict)   # string classifier result
    ai_error        = pyqtSignal(str)

    def __init__(self, target: str, api_key: str = ''):
        super().__init__()
        self.target  = target
        self.api_key = api_key

    def run(self):
        log.info(f'Scan started: {self.target}')
        try:
            scanner = ZWinScanner(self.target)
            modules = [
                ('PE Security Flags',  scanner.check_pe_flags),
                ('Import Table',       scanner.check_imports),
                ('Section Entropy',    scanner.check_section_entropy),
                ('Compile Timestamp',  scanner.check_compile_timestamp),
                ('Digital Signature',  scanner.check_signature),
                ('UAC & Manifest',     scanner.check_uac_manifest),
                ('Hardcoded Secrets',  scanner.check_hardcoded_secrets),
                ('URL & Network',      scanner.check_urls),
                ('Network / SSO',      scanner.check_network),
                ('Credential Files',   scanner.check_credential_files),
            ]
            t0 = time.time()
            prev = 0
            for name, fn in modules:
                self.module_started.emit(name)
                tm = time.time()
                log.debug(f'Module: {name}')
                fn()
                new_count = len(scanner.findings) - prev
                prev = len(scanner.findings)
                elapsed = time.time() - tm
                log.debug(f'Module done: {name} — {new_count} findings in {elapsed:.2f}s')
                self.module_done.emit(name, new_count, elapsed)

            duration  = f'{time.time() - t0:.1f}s'
            exe_name  = Path(self.target).stem
            exe_size  = f'{Path(self.target).stat().st_size/1_048_576:.1f} MB'
            html_out  = str(Path(self.target).parent / f'zwinscan_{exe_name}_report.html')
            try:
                save_html(scanner.findings, self.target, html_out, duration)
            except PermissionError:
                html_out = str(_LOG_DIR / f'zwinscan_{exe_name}_report.html')
                log.warning(f'No write access to exe dir, saving report to: {html_out}')
                save_html(scanner.findings, self.target, html_out, duration)
            log.info(f'Scan done: {len(scanner.findings)} findings, report: {html_out}')
            self.scan_done.emit(scanner.findings, html_out)

            # ── AI modules (run after main scan, non-blocking for UI) ──
            if self.api_key and HAS_GENAI:
                # 1. String classifier
                self.module_started.emit('AI: String Classifier')
                tm = time.time()
                try:
                    suspicious_strings = scanner._strings(Path(self.target).read_bytes(), n=12)
                    result = ai_classify_strings(self.api_key, suspicious_strings, exe_name)
                    self.ai_strings_done.emit(result)
                    n = len(result.get('suspicious', []))
                    self.module_done.emit('AI: String Classifier', n, time.time()-tm)
                    log.info(f'AI strings: {n} suspicious')
                except Exception as e:
                    self.module_done.emit('AI: String Classifier', 0, time.time()-tm)
                    self.ai_error.emit(f'String classifier: {e}')
                    log.error(f'AI strings error: {e}')

                # 2. Executive summary
                self.module_started.emit('AI: Executive Summary')
                tm = time.time()
                try:
                    result = ai_executive_summary(self.api_key, scanner.findings, exe_name, exe_size)
                    self.ai_summary_done.emit(result)
                    self.module_done.emit('AI: Executive Summary', 1, time.time()-tm)
                    log.info(f'AI summary: {result.get("verdict")} score={result.get("risk_score")}')
                except Exception as e:
                    self.module_done.emit('AI: Executive Summary', 0, time.time()-tm)
                    self.ai_error.emit(f'Executive summary: {e}')
                    log.error(f'AI summary error: {e}')

        except Exception:
            log.error(f'Scan thread exception:\n{traceback.format_exc()}')
            self.scan_done.emit([], '')


class ChatWorker(QThread):
    """Kirim pesan ke Gemini, emit respons — agar GUI tidak freeze."""
    reply_ready = pyqtSignal(str)
    error       = pyqtSignal(str)

    def __init__(self, api_key: str, history: list, message: str, context: str):
        super().__init__()
        self.api_key = api_key
        self.history = history   # [{'role':'user'|'model','parts':[str]}, ...]
        self.message = message
        self.context = context

    def run(self):
        try:
            from google.genai import types as _gtypes
            client = _genai_mod.Client(api_key=self.api_key)

            sys_instr = (
                'Kamu adalah security analyst yang membantu menganalisis hasil scan keamanan '
                'aplikasi Windows. Jawab dalam Bahasa Indonesia, singkat dan teknis.\n\n'
                f'Konteks scan:\n{self.context}'
            )
            # Convert history format
            history_contents = []
            for h in self.history:
                role  = h.get('role', 'user')
                parts = h.get('parts', [''])
                history_contents.append(
                    _gtypes.Content(role=role, parts=[_gtypes.Part(text=p) for p in parts])
                )

            chat = client.chats.create(
                model='gemini-2.5-flash',
                config=_gtypes.GenerateContentConfig(system_instruction=sys_instr),
                history=history_contents,
            )
            resp = chat.send_message(self.message)
            self.reply_ready.emit(resp.text.strip())
        except Exception as e:
            self.error.emit(str(e))


# =========================================================
# UI Components
# =========================================================

SEV_COLORS = {
    'CRITICAL': ('#f03737', 'rgba(240,55,55,40)'),
    'HIGH':     ('#f87325', 'rgba(248,115,37,40)'),
    'MEDIUM':   ('#d4a017', 'rgba(212,160,23,40)'),
    'LOW':      ('#3b8cf8', 'rgba(59,140,248,40)'),
    'INFO':     ('#3d5570', 'rgba(61,85,112,30)'),
}

APP_STYLE = """
QWidget { background: #050d1a; color: #c8d8e8; font-family: 'Segoe UI', sans-serif; font-size: 13px; }
QScrollArea { border: none; background: transparent; }
QScrollArea > QWidget > QWidget { background: transparent; }
QScrollBar:vertical { background: #050d1a; width: 5px; border: none; }
QScrollBar::handle:vertical { background: #162b47; border-radius: 2px; min-height: 20px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
"""

SCAN_BTN_STYLE = """
QPushButton {
    background: #00dcb4;
    color: #050d1a;
    border: none;
    border-radius: 6px;
    font-size: 13px;
    font-weight: 700;
    letter-spacing: 1px;
    padding: 12px;
}
QPushButton:hover { background: #00c9a4; }
QPushButton:pressed { background: #00b894; }
QPushButton:disabled { background: #0d2a22; color: #1a4a3a; }
"""

BROWSE_BTN_STYLE = """
QPushButton {
    background: #101f35;
    color: #4a6580;
    border: 1px solid #162b47;
    border-radius: 6px;
    font-size: 12px;
    padding: 8px 16px;
}
QPushButton:hover { border-color: #00dcb4; color: #c8d8e8; }
"""

OPEN_BTN_STYLE = """
QPushButton {
    background: #0b1628;
    color: #00dcb4;
    border: 1px solid #00dcb4;
    border-radius: 6px;
    font-size: 13px;
    font-weight: 600;
    padding: 10px;
}
QPushButton:hover { background: rgba(0,220,180,18); }
"""


class TitleBar(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.setFixedHeight(48)
        self._drag = None
        lo = QHBoxLayout(self)
        lo.setContentsMargins(18, 0, 10, 0)
        lo.setSpacing(8)

        dot = QLabel("●")
        dot.setStyleSheet("color: #00dcb4; font-size: 11px;")

        name = QLabel("ZWinScan")
        name.setStyleSheet("color: #00dcb4; font-family: Consolas; font-size: 14px; font-weight: bold; letter-spacing: 1px;")

        tag = QLabel("Windows App Security Analyzer")
        tag.setStyleSheet("color: #2a3f58; font-size: 11px; margin-left: 4px;")

        hint = QLabel("Ctrl+↑↓  opacity")
        hint.setStyleSheet("color: #1e3a5f; font-size: 10px; font-family: Consolas;")

        lo.addWidget(dot)
        lo.addWidget(name)
        lo.addWidget(tag)
        lo.addStretch()
        lo.addWidget(hint)

        close = QPushButton("×")
        close.setFixedSize(30, 30)
        close.setCursor(Qt.CursorShape.PointingHandCursor)
        close.setStyleSheet("""
            QPushButton { background: transparent; color: #3d5570; font-size: 20px;
                          border: none; border-radius: 4px; }
            QPushButton:hover { background: rgba(240,55,55,30); color: #f03737; }
        """)
        close.clicked.connect(self.window().close)
        lo.addWidget(close)

        self.setStyleSheet("background: #050d1a; border-bottom: 1px solid #162b47;")

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self._drag = e.globalPosition().toPoint() - self.window().pos()

    def mouseMoveEvent(self, e):
        if self._drag and e.buttons() & Qt.MouseButton.LeftButton:
            self.window().move(e.globalPosition().toPoint() - self._drag)

    def mouseReleaseEvent(self, e):
        self._drag = None


class DropZone(QWidget):
    file_dropped = pyqtSignal(str)
    clicked      = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setMinimumHeight(130)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._drag_over = False
        self._has_file  = False
        self._build()

    def _build(self):
        lo = QVBoxLayout(self)
        lo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lo.setSpacing(5)

        self.icon = QLabel("↓")
        self.icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon.setStyleSheet("color: #2a3f58; font-size: 30px;")

        self.line1 = QLabel("Drop .exe file here")
        self.line1.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.line1.setStyleSheet("color: #4a6580; font-size: 14px; font-weight: 500;")

        self.line2 = QLabel("atau klik Browse untuk memilih")
        self.line2.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.line2.setStyleSheet("color: #2a3f58; font-size: 11px;")

        lo.addWidget(self.icon)
        lo.addWidget(self.line1)
        lo.addWidget(self.line2)

    def set_file(self, path: str):
        self._has_file = True
        self.icon.setText("✓")
        self.icon.setStyleSheet("color: #00dcb4; font-size: 28px;")
        self.line1.setText(Path(path).name)
        self.line1.setStyleSheet("color: #c8d8e8; font-size: 13px; font-weight: 600; font-family: Consolas;")
        sz = Path(path).stat().st_size / 1_048_576
        self.line2.setText(f"{sz:.1f} MB  ·  Siap di-scan")
        self.line2.setStyleSheet("color: #4a6580; font-size: 11px;")
        self.update()

    def reset(self):
        self._has_file = False
        self.icon.setText("↓")
        self.icon.setStyleSheet("color: #2a3f58; font-size: 30px;")
        self.line1.setText("Drop .exe file here")
        self.line1.setStyleSheet("color: #4a6580; font-size: 14px; font-weight: 500;")
        self.line2.setText("atau klik Browse untuk memilih")
        self.line2.setStyleSheet("color: #2a3f58; font-size: 11px;")
        self.update()

    def dragEnterEvent(self, e: QDragEnterEvent):
        if e.mimeData().hasUrls():
            urls = e.mimeData().urls()
            if urls and urls[0].toLocalFile().lower().endswith('.exe'):
                e.acceptProposedAction()
                self._drag_over = True
                self.line1.setText("Lepaskan di sini")
                self.line1.setStyleSheet("color: #00dcb4; font-size: 14px; font-weight: 500;")
                self.update()

    def dragLeaveEvent(self, e):
        self._drag_over = False
        if not self._has_file:
            self.line1.setText("Drop .exe file here")
            self.line1.setStyleSheet("color: #4a6580; font-size: 14px; font-weight: 500;")
        self.update()

    def dropEvent(self, e: QDropEvent):
        self._drag_over = False
        urls = e.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if path.lower().endswith('.exe'):
                self.file_dropped.emit(path)
        self.update()

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        if self._drag_over:
            p.fillRect(self.rect(), QColor(0, 220, 180, 18))
            pen = QPen(QColor('#00dcb4'), 1, Qt.PenStyle.DashLine)
        elif self._has_file:
            p.fillRect(self.rect(), QColor(0, 220, 180, 10))
            pen = QPen(QColor(0, 220, 180, 80), 1, Qt.PenStyle.SolidLine)
        else:
            p.fillRect(self.rect(), QColor('#0b1628'))
            pen = QPen(QColor('#162b47'), 1, Qt.PenStyle.DashLine)
        p.setPen(pen)
        p.drawRoundedRect(self.rect().adjusted(1, 1, -1, -1), 8, 8)
        p.end()


class ModuleRow(QWidget):
    def __init__(self, name: str):
        super().__init__()
        self.setFixedHeight(38)
        lo = QHBoxLayout(self)
        lo.setContentsMargins(14, 0, 14, 0)
        lo.setSpacing(10)

        self._status = QLabel("·")
        self._status.setFixedWidth(14)
        self._status.setStyleSheet("color: #2a3f58; font-size: 14px; font-family: Consolas;")

        self._name = QLabel(name)
        self._name.setStyleSheet("color: #4a6580; font-family: Consolas; font-size: 12px;")
        self._name.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

        self._count = QLabel("")
        self._count.setFixedWidth(88)
        self._count.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self._count.setStyleSheet("color: #2a3f58; font-family: Consolas; font-size: 11px;")

        self._time = QLabel("")
        self._time.setFixedWidth(40)
        self._time.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self._time.setStyleSheet("color: #2a3f58; font-family: Consolas; font-size: 11px;")

        lo.addWidget(self._status)
        lo.addWidget(self._name)
        lo.addWidget(self._count)
        lo.addWidget(self._time)

        self.setStyleSheet("QWidget { background: #0b1628; border-bottom: 1px solid #0d1f35; }")

    def set_running(self):
        self._status.setText("⟳")
        self._status.setStyleSheet("color: #00dcb4; font-size: 13px; font-family: Consolas;")
        self._name.setStyleSheet("color: #c8d8e8; font-family: Consolas; font-size: 12px;")

    def set_done(self, count: int, elapsed: float):
        self._status.setText("✓")
        self._status.setStyleSheet("color: #00dcb4; font-size: 13px; font-family: Consolas;")
        self._count.setText(f"{count} finding{'s' if count != 1 else ''}")
        self._count.setStyleSheet("color: #4a6580; font-family: Consolas; font-size: 11px;")
        self._time.setText(f"{elapsed:.1f}s")
        self._time.setStyleSheet("color: #3d5570; font-family: Consolas; font-size: 11px;")


class SeverityCard(QFrame):
    def __init__(self, sev: str, count: int):
        super().__init__()
        color, bg = SEV_COLORS.get(sev, ('#3d5570', 'rgba(61,85,112,30)'))
        self.setStyleSheet(f"QFrame {{ background: {bg}; border: 1px solid {color}; border-radius: 6px; }}")
        lo = QVBoxLayout(self)
        lo.setContentsMargins(16, 10, 16, 10)
        lo.setSpacing(2)
        lo.setAlignment(Qt.AlignmentFlag.AlignCenter)

        n = QLabel(str(count))
        n.setAlignment(Qt.AlignmentFlag.AlignCenter)
        n.setStyleSheet(f"color:{color};font-size:24px;font-weight:700;font-family:Consolas;background:transparent;border:none;")

        s = QLabel(sev)
        s.setAlignment(Qt.AlignmentFlag.AlignCenter)
        s.setStyleSheet("color:#4a6580;font-size:10px;letter-spacing:1px;background:transparent;border:none;")

        lo.addWidget(n)
        lo.addWidget(s)


# =========================================================
# Main Window
# =========================================================

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self._target      = ''
        self._worker      = None
        self._chat_worker = None
        self._mod_rows    = {}
        self._html_out    = ''
        self._findings    = []
        self._chat_history = []
        self._chat_context = ''
        cfg = _load_config()
        self._api_key = cfg.get('gemini_api_key', '')
        self._setwindow()
        self._build()

    def _setwindow(self):
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        self._opacity = 0.75
        self.setWindowOpacity(self._opacity)
        self.setFixedSize(700, 580)
        self.setStyleSheet(APP_STYLE)
        screen = QApplication.primaryScreen().geometry()
        self.move((screen.width()-700)//2, (screen.height()-580)//2)

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Title bar
        root.addWidget(TitleBar(self))

        # Global opacity shortcuts (work regardless of which widget has focus)
        QShortcut(QKeySequence("Ctrl+Up"),   self).activated.connect(lambda: self._adjust_opacity(+0.05))
        QShortcut(QKeySequence("Ctrl+Down"), self).activated.connect(lambda: self._adjust_opacity(-0.05))

        # Scrollable content area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { background: #050d1a; border: none; }")

        content = QWidget()
        content.setStyleSheet("background: #050d1a;")
        inner = QVBoxLayout(content)
        inner.setContentsMargins(24, 24, 24, 24)
        inner.setSpacing(16)

        # Drop zone
        self.drop = DropZone()
        self.drop.file_dropped.connect(self._on_file)
        self.drop.clicked.connect(self._browse)
        inner.addWidget(self.drop)

        # Path + browse row
        path_row = QHBoxLayout()
        path_row.setSpacing(8)
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("Paste atau ketik path .exe di sini, lalu tekan Enter …")
        self.path_edit.setStyleSheet("""
            QLineEdit { background:#0b1628; border:1px solid #162b47; border-radius:6px;
                        color:#c8d8e8; font-family:Consolas; font-size:11px;
                        padding:7px 10px; }
            QLineEdit:focus { border-color: #1e3a5f; }
        """)
        self.path_edit.returnPressed.connect(self._on_path_entered)
        browse = QPushButton("Browse")
        browse.setFixedWidth(88)
        browse.setFixedHeight(34)
        browse.setCursor(Qt.CursorShape.PointingHandCursor)
        browse.setStyleSheet(BROWSE_BTN_STYLE)
        browse.clicked.connect(self._browse)
        path_row.addWidget(self.path_edit)
        path_row.addWidget(browse)
        inner.addLayout(path_row)

        # API Key row
        key_row = QHBoxLayout()
        key_row.setSpacing(6)
        key_lbl = QLabel("🤖")
        key_lbl.setFixedWidth(20)
        key_lbl.setStyleSheet("font-size:14px; background:transparent;")
        self.key_edit = QLineEdit(self._api_key)
        self.key_edit.setPlaceholderText("Gemini API Key (opsional — untuk analisis AI)")
        self.key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.key_edit.setStyleSheet("""
            QLineEdit { background:#0b1628; border:1px solid #162b47; border-radius:6px;
                        color:#7a9ab8; font-family:Consolas; font-size:11px; padding:6px 10px; }
            QLineEdit:focus { border-color:#1e3a5f; color:#c8d8e8; }
        """)
        self.key_edit.textChanged.connect(self._on_key_changed)
        self._key_eye = QPushButton("👁")
        self._key_eye.setFixedSize(30, 30)
        self._key_eye.setStyleSheet("QPushButton{background:#0b1628;border:1px solid #162b47;"
                                    "border-radius:6px;font-size:12px;color:#4a6580;}"
                                    "QPushButton:hover{color:#c8d8e8;border-color:#3b5070;}")
        self._key_eye.setCursor(Qt.CursorShape.PointingHandCursor)
        self._key_eye.clicked.connect(self._toggle_key_echo)
        key_row.addWidget(key_lbl)
        key_row.addWidget(self.key_edit)
        key_row.addWidget(self._key_eye)
        inner.addLayout(key_row)

        # Scan button
        self.scan_btn = QPushButton("SCAN")
        self.scan_btn.setFixedHeight(44)
        self.scan_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scan_btn.setStyleSheet(SCAN_BTN_STYLE)
        self.scan_btn.clicked.connect(self._start_scan)
        self.scan_btn.setEnabled(False)
        inner.addWidget(self.scan_btn)

        # Divider
        div = QFrame()
        div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet("color: #162b47;")
        inner.addWidget(div)

        # Progress log
        log_label = QLabel("Modul")
        log_label.setStyleSheet("color: #2a3f58; font-size: 10px; letter-spacing: 2px; text-transform: uppercase;")
        inner.addWidget(log_label)

        self.log_frame = QFrame()
        self.log_frame.setStyleSheet("QFrame { background:#0b1628; border:1px solid #162b47; border-radius:6px; }")
        self.log_layout = QVBoxLayout(self.log_frame)
        self.log_layout.setContentsMargins(0, 0, 0, 0)
        self.log_layout.setSpacing(0)

        placeholder = QLabel("Belum ada scan yang dijalankan.")
        placeholder.setObjectName("log_placeholder")
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        placeholder.setFixedHeight(60)
        placeholder.setStyleSheet("color: #2a3f58; font-family: Consolas; font-size: 12px;")
        self.log_layout.addWidget(placeholder)
        inner.addWidget(self.log_frame)

        # Results panel (hidden until scan done)
        self.results_panel = QWidget()
        self.results_panel.setVisible(False)
        res_lo = QVBoxLayout(self.results_panel)
        res_lo.setContentsMargins(0, 0, 0, 0)
        res_lo.setSpacing(12)

        res_label = QLabel("Hasil")
        res_label.setStyleSheet("color: #2a3f58; font-size: 10px; letter-spacing: 2px;")
        res_lo.addWidget(res_label)

        self.cards_row = QHBoxLayout()
        self.cards_row.setSpacing(8)
        res_lo.addLayout(self.cards_row)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)

        self.open_btn = QPushButton("Buka Laporan HTML")
        self.open_btn.setFixedHeight(42)
        self.open_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.open_btn.setStyleSheet(OPEN_BTN_STYLE)
        self.open_btn.clicked.connect(self._open_report)
        btn_row.addWidget(self.open_btn)

        self.log_btn = QPushButton("Lihat Log")
        self.log_btn.setFixedHeight(42)
        self.log_btn.setFixedWidth(100)
        self.log_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.log_btn.setStyleSheet("""
            QPushButton { background:#0b1628; color:#7a9ab8; border:1px solid #162b47;
                          border-radius:6px; font-size:12px; }
            QPushButton:hover { color:#c8d8e8; border-color:#3b5070; }
        """)
        self.log_btn.setToolTip(str(LOG_FILE))
        self.log_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(LOG_FILE))))
        btn_row.addWidget(self.log_btn)

        res_lo.addLayout(btn_row)

        inner.addWidget(self.results_panel)

        # ── AI Summary Panel ──────────────────────────────
        self.ai_panel = QWidget()
        self.ai_panel.setVisible(False)
        ai_lo = QVBoxLayout(self.ai_panel)
        ai_lo.setContentsMargins(0, 0, 0, 0)
        ai_lo.setSpacing(8)

        ai_hdr = QLabel("AI Analysis")
        ai_hdr.setStyleSheet("color:#2a3f58;font-size:10px;letter-spacing:2px;")
        ai_lo.addWidget(ai_hdr)

        self.ai_card = QFrame()
        self.ai_card.setStyleSheet(
            "QFrame{background:#0b1628;border:1px solid #1e3a5f;border-radius:8px;}")
        ai_card_lo = QVBoxLayout(self.ai_card)
        ai_card_lo.setContentsMargins(16, 14, 16, 14)
        ai_card_lo.setSpacing(10)

        self.ai_verdict_lbl = QLabel("Memuat analisis AI…")
        self.ai_verdict_lbl.setStyleSheet(
            "color:#00dcb4;font-size:15px;font-weight:700;font-family:Consolas;background:transparent;border:none;")
        self.ai_verdict_lbl.setWordWrap(True)
        ai_card_lo.addWidget(self.ai_verdict_lbl)

        self.ai_summary_lbl = QLabel()
        self.ai_summary_lbl.setWordWrap(True)
        self.ai_summary_lbl.setStyleSheet(
            "color:#7a9ab8;font-size:12px;line-height:1.6;background:transparent;border:none;")
        ai_card_lo.addWidget(self.ai_summary_lbl)

        self.ai_concerns_lbl = QLabel()
        self.ai_concerns_lbl.setWordWrap(True)
        self.ai_concerns_lbl.setStyleSheet(
            "color:#c8d8e8;font-size:12px;background:transparent;border:none;")
        ai_card_lo.addWidget(self.ai_concerns_lbl)

        self.ai_remediation_lbl = QLabel()
        self.ai_remediation_lbl.setWordWrap(True)
        self.ai_remediation_lbl.setStyleSheet(
            "color:#4a6580;font-size:11px;font-family:Consolas;background:transparent;border:none;")
        ai_card_lo.addWidget(self.ai_remediation_lbl)

        ai_lo.addWidget(self.ai_card)
        inner.addWidget(self.ai_panel)

        # ── AI Strings Panel ──────────────────────────────
        self.ai_str_panel = QWidget()
        self.ai_str_panel.setVisible(False)
        ais_lo = QVBoxLayout(self.ai_str_panel)
        ais_lo.setContentsMargins(0, 0, 0, 0)
        ais_lo.setSpacing(8)

        ais_hdr = QLabel("AI: String Classifier")
        ais_hdr.setStyleSheet("color:#2a3f58;font-size:10px;letter-spacing:2px;")
        ais_lo.addWidget(ais_hdr)

        self.ai_str_card = QFrame()
        self.ai_str_card.setStyleSheet(
            "QFrame{background:#0b1628;border:1px solid #162b47;border-radius:8px;}")
        ais_card_lo = QVBoxLayout(self.ai_str_card)
        ais_card_lo.setContentsMargins(14, 12, 14, 12)
        ais_card_lo.setSpacing(6)

        self.ai_str_lbl = QLabel()
        self.ai_str_lbl.setWordWrap(True)
        self.ai_str_lbl.setStyleSheet(
            "color:#7a9ab8;font-size:12px;font-family:Consolas;background:transparent;border:none;")
        ais_card_lo.addWidget(self.ai_str_lbl)

        ais_lo.addWidget(self.ai_str_card)
        inner.addWidget(self.ai_str_panel)

        # ── Chat Panel ────────────────────────────────────
        self.chat_panel = QWidget()
        self.chat_panel.setVisible(False)
        chat_lo = QVBoxLayout(self.chat_panel)
        chat_lo.setContentsMargins(0, 0, 0, 0)
        chat_lo.setSpacing(8)

        chat_hdr = QLabel("Tanya AI")
        chat_hdr.setStyleSheet("color:#2a3f58;font-size:10px;letter-spacing:2px;")
        chat_lo.addWidget(chat_hdr)

        self.chat_box = QLabel()
        self.chat_box.setWordWrap(True)
        self.chat_box.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.chat_box.setTextFormat(Qt.TextFormat.RichText)
        self.chat_box.setStyleSheet("""
            QLabel { background:#0b1628; border:1px solid #162b47; border-radius:8px;
                     color:#c8d8e8; font-size:12px; padding:12px; min-height:80px; }
        """)
        self.chat_box.setText('<span style="color:#2a3f58;">Tanya apapun tentang hasil scan ini…</span>')
        chat_lo.addWidget(self.chat_box)

        chat_input_row = QHBoxLayout()
        chat_input_row.setSpacing(6)
        self.chat_input = QLineEdit()
        self.chat_input.setPlaceholderText("Ketik pertanyaan dan tekan Enter…")
        self.chat_input.setStyleSheet("""
            QLineEdit { background:#0b1628; border:1px solid #162b47; border-radius:6px;
                        color:#c8d8e8; font-family:Consolas; font-size:12px; padding:8px 10px; }
            QLineEdit:focus { border-color:#1e3a5f; }
        """)
        self.chat_input.returnPressed.connect(self._send_chat)
        self.chat_send = QPushButton("Kirim")
        self.chat_send.setFixedWidth(70)
        self.chat_send.setFixedHeight(36)
        self.chat_send.setCursor(Qt.CursorShape.PointingHandCursor)
        self.chat_send.setStyleSheet("""
            QPushButton { background:#00dcb4; color:#050d1a; border:none; border-radius:6px;
                          font-size:12px; font-weight:700; }
            QPushButton:hover { background:#00c9a4; }
            QPushButton:disabled { background:#0d2a22; color:#1a4a3a; }
        """)
        self.chat_send.clicked.connect(self._send_chat)
        chat_input_row.addWidget(self.chat_input)
        chat_input_row.addWidget(self.chat_send)
        chat_lo.addLayout(chat_input_row)

        inner.addWidget(self.chat_panel)
        inner.addStretch()

        scroll.setWidget(content)
        root.addWidget(scroll)

    # ── slots ────────────────────────────────────────────

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(self, "Pilih file .exe", "", "Executable (*.exe)")
        if path:
            self._on_file(path)

    def _on_path_entered(self):
        path = self.path_edit.text().strip().strip('"').strip("'")
        if path and Path(path).is_file() and path.lower().endswith('.exe'):
            self._on_file(path, update_edit=False)
        else:
            self.path_edit.setStyleSheet("""
                QLineEdit { background:#0b1628; border:1px solid #f03737; border-radius:6px;
                            color:#c8d8e8; font-family:Consolas; font-size:11px;
                            padding:7px 10px; }
            """)

    def _on_file(self, path: str, update_edit: bool = True):
        self._target = path
        if update_edit:
            self.path_edit.setText(path)
        self.path_edit.setStyleSheet("""
            QLineEdit { background:#0b1628; border:1px solid #162b47; border-radius:6px;
                        color:#c8d8e8; font-family:Consolas; font-size:11px;
                        padding:7px 10px; }
            QLineEdit:focus { border-color: #1e3a5f; }
        """)
        self.drop.set_file(path)
        self.scan_btn.setEnabled(True)
        self.results_panel.setVisible(False)

    def _on_key_changed(self, text: str):
        self._api_key = text.strip()
        cfg = _load_config()
        cfg['gemini_api_key'] = self._api_key
        _save_config(cfg)

    def _toggle_key_echo(self):
        if self.key_edit.echoMode() == QLineEdit.EchoMode.Password:
            self.key_edit.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.key_edit.setEchoMode(QLineEdit.EchoMode.Password)

    def _start_scan(self):
        if not self._target or not Path(self._target).is_file():
            return

        self.scan_btn.setEnabled(False)
        self.scan_btn.setText("Scanning…")
        self.results_panel.setVisible(False)
        self.ai_panel.setVisible(False)
        self.ai_str_panel.setVisible(False)
        self.chat_panel.setVisible(False)
        self._mod_rows.clear()
        self._findings.clear()
        self._chat_history.clear()

        # Clear log
        while self.log_layout.count():
            item = self.log_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        self._worker = ScanWorker(self._target, self._api_key)
        self._worker.module_started.connect(self._on_module_started)
        self._worker.module_done.connect(self._on_module_done)
        self._worker.scan_done.connect(self._on_scan_done)
        self._worker.ai_summary_done.connect(self._on_ai_summary)
        self._worker.ai_strings_done.connect(self._on_ai_strings)
        self._worker.ai_error.connect(lambda e: log.warning(f'AI: {e}'))
        self._worker.start()

    def _on_module_started(self, name: str):
        row = ModuleRow(name)
        row.set_running()
        self._mod_rows[name] = row
        self.log_layout.addWidget(row)

    def _on_module_done(self, name: str, count: int, elapsed: float):
        if name in self._mod_rows:
            self._mod_rows[name].set_done(count, elapsed)

    def _on_scan_done(self, findings: list, html_path: str):
        self._html_out = html_path
        self._findings = findings
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("SCAN ULANG")

        # Build chat context
        lines = [f'[{f.severity}] {f.category}: {f.title}' for f in findings]
        self._chat_context = (
            f'Target: {Path(self._target).name}\n'
            f'Findings ({len(findings)}):\n' + '\n'.join(lines)
        )

        # clear old cards
        while self.cards_row.count():
            item = self.cards_row.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        counts = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            card = SeverityCard(sev, counts.get(sev, 0))
            self.cards_row.addWidget(card)

        self.results_panel.setVisible(True)

        # Show chat panel if API key available
        if self._api_key and HAS_GENAI:
            self.chat_panel.setVisible(True)
            self.ai_panel.setVisible(True)
            self.ai_verdict_lbl.setText("⟳ Menunggu AI Executive Summary…")

    def _on_ai_summary(self, result: dict):
        score   = result.get('risk_score', 0)
        verdict = result.get('verdict', '?')
        app_type= result.get('app_type', '')
        summary = result.get('summary', '')
        concerns= result.get('top_concerns', [])
        remediation = result.get('remediation', [])

        color = {'AMAN':'#00dcb4','MENCURIGAKAN':'#d4a017','BERBAHAYA':'#f03737'}.get(verdict,'#7a9ab8')
        self.ai_verdict_lbl.setStyleSheet(
            f'color:{color};font-size:15px;font-weight:700;font-family:Consolas;'
            'background:transparent;border:none;')
        self.ai_verdict_lbl.setText(f'[{score}/10] {verdict}  ·  {app_type}')
        self.ai_summary_lbl.setText(summary)

        if concerns:
            self.ai_concerns_lbl.setText(
                '<b style="color:#4a6580">Top concerns:</b><br>' +
                '<br>'.join(f'▸ {c}' for c in concerns))
        if remediation:
            self.ai_remediation_lbl.setText(
                'Rekomendasi:\n' + '\n'.join(f'  {i+1}. {r}' for i, r in enumerate(remediation)))

        self.ai_panel.setVisible(True)

    def _on_ai_strings(self, result: dict):
        suspicious = result.get('suspicious', [])
        notable    = result.get('notable', '')
        if not suspicious and not notable:
            return
        lines = []
        for item in suspicious[:15]:
            sev = item.get('severity','?')
            s   = item.get('string','')[:60]
            r   = item.get('reason','')
            lines.append(f'[{sev}] {s}\n        → {r}')
        if notable:
            lines.append(f'\nCatatan: {notable}')
        self.ai_str_lbl.setText('\n'.join(lines) if lines else 'Tidak ada string mencurigakan.')
        self.ai_str_panel.setVisible(True)

    def _send_chat(self):
        msg = self.chat_input.text().strip()
        if not msg or not self._api_key:
            return
        self.chat_input.clear()
        self.chat_send.setEnabled(False)

        # append user message to display
        prev = self.chat_box.text()
        if 'Tanya apapun' in prev:
            prev = ''
        user_html = f'<span style="color:#00dcb4">Kamu:</span> {msg}'
        self.chat_box.setText((prev + '<br>' if prev else '') + user_html +
                              '<br><span style="color:#2a3f58">AI: ⟳</span>')

        self._chat_worker = ChatWorker(
            self._api_key, self._chat_history, msg, self._chat_context)
        self._chat_worker.reply_ready.connect(self._on_chat_reply)
        self._chat_worker.error.connect(self._on_chat_error)
        self._chat_worker.start()

    def _on_chat_reply(self, text: str):
        self._chat_history.append({'role': 'user',  'parts': [self.chat_input.text() or '']})
        self._chat_history.append({'role': 'model', 'parts': [text]})
        # rebuild display (simple approach — last 10 turns)
        lines = self.chat_box.text()
        # replace spinner line
        lines = lines.rsplit('<br><span style="color:#2a3f58">AI: ⟳</span>', 1)[0]
        ai_html = f'<span style="color:#7a9ab8">AI:</span> {text.replace(chr(10),"<br>")}'
        self.chat_box.setText(lines + '<br>' + ai_html)
        self.chat_send.setEnabled(True)

    def _on_chat_error(self, err: str):
        prev = self.chat_box.text()
        prev = prev.rsplit('<br><span style="color:#2a3f58">AI: ⟳</span>', 1)[0]
        self.chat_box.setText(prev + f'<br><span style="color:#f03737">Error: {err}</span>')
        self.chat_send.setEnabled(True)

    def _open_report(self):
        if self._html_out and Path(self._html_out).is_file():
            QDesktopServices.openUrl(QUrl.fromLocalFile(self._html_out))

    def _adjust_opacity(self, delta: float):
        self._opacity = round(min(1.0, max(0.1, self._opacity + delta)), 2)
        self.setWindowOpacity(self._opacity)

    def keyPressEvent(self, event):
        super().keyPressEvent(event)


# =========================================================
# Main
# =========================================================

def _qt_message_handler(mode, context, message):
    from PyQt6.QtCore import QtMsgType
    level_map = {
        QtMsgType.QtDebugMsg:    log.debug,
        QtMsgType.QtInfoMsg:     log.info,
        QtMsgType.QtWarningMsg:  log.warning,
        QtMsgType.QtCriticalMsg: log.error,
        QtMsgType.QtFatalMsg:    log.critical,
    }
    level_map.get(mode, log.warning)(f'[Qt] {message}')


def main():
    from PyQt6.QtCore import qInstallMessageHandler
    qInstallMessageHandler(_qt_message_handler)

    log.info(f'Platform: {sys.platform} | Python {sys.version.split()[0]}')
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    log.info('MainWindow creating...')
    win = MainWindow()
    win.show()
    win.raise_()
    win.activateWindow()
    log.info('App event loop started')
    code = app.exec()
    log.info(f'App exited with code {code}')
    sys.exit(code)


if __name__ == '__main__':
    main()
