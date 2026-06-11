import json
import os
import sys
import urllib.parse
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Fix encoding Windows
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    from curl_cffi import requests
    _CURL = True
except ImportError:
    import requests  # type: ignore
    _CURL = False

try:
    import pyotp
except ImportError:
    pyotp = None  # type: ignore

# ─── Cấu hình ──────────────────────────────────────────────────────────────
EMAIL        = "[EMAIL_ADDRESS]"
PASSWORD     = "[PASSWORD]"
TOTP_SECRET  = "IKGRXYGPDZHM5XRS755W3QLFBSDGCEUY"  # None nếu không có 2FA
WEBHOOK_URL  = ""  # webhook URL để nhận thông tin đăng nhập thành công
OUTPUT_FILE  = str(Path(__file__).parent / "cookies.json")
# ───────────────────────────────────────────────────────────────────────────

# ─── Hằng số ───────────────────────────────────────────────────────────────
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/134.0.0.0 Safari/537.36"
)
AUTH_BASE = "https://auth.openai.com"
OUT_DIR   = Path(__file__).parent.resolve()


# ─── Sentinel ──────────────────────────────────────────────────────────────

def _build_sentinel(session, did: str, flow: str) -> str:
    """Lấy Sentinel token — bắt buộc với mọi API login của OpenAI."""
    resp = session.post(
        "https://sentinel.openai.com/backend-api/sentinel/req",
        headers={
            "origin":       "https://sentinel.openai.com",
            "referer":      "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6",
            "content-type": "text/plain;charset=UTF-8",
        },
        data=json.dumps({"p": "", "id": did, "flow": flow}),
        timeout=15,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"Sentinel that bai: HTTP {resp.status_code} - {resp.text[:200]}")
    token = (resp.json() or {}).get("token", "")
    return json.dumps({"p": "", "t": "", "c": token, "id": did, "flow": flow})


# ─── TOTP ──────────────────────────────────────────────────────────────────

def _totp(secret: str) -> Optional[str]:
    if not secret:
        return None
    if pyotp is None:
        print("[!] pyotp chua cai dat  →  pip install pyotp")
        return None
    try:
        return pyotp.TOTP(secret).now()
    except Exception as e:
        print(f"[!] TOTP error: {e}")
        return None


# ─── Lưu / tải cookies ─────────────────────────────────────────────────────

def _filter_chatgpt_cookies(cookies: List[Dict]) -> List[Dict]:
    """
    Lọc chỉ lấy cookies dành cho domain .chatgpt.com
    Bao gồm:
    - Cookies từ .chatgpt.com, chatgpt.com
    - Cookies session quan trọng (__Secure-next-auth.session-token, v.v.)
    - Cookies account (__Host-next-auth.csrf-token, __Secure-oai-is, v.v.)
    - Cookies tracking (oai-did, oai-sc, oai-asli, v.v.)
    """
    filtered = []
    
    # Danh sách cookies quan trọng cần lấy dù domain là gì
    important_cookies = {
        '__Secure-next-auth.session-token',
        '__Host-next-auth.csrf-token',
        '__Secure-oai-is',
        '_account',
        '_account_is_fedramp',
        'oai-login-page-load-pending',
        '__Secure-next-auth.callback-url',
    }
    
    # Cookies tracking và session từ openai.com cũng cần thiết
    tracking_cookies = {
        'oai-did',
        'oai-sc',
        'oai-asli',
        'oai-cbi',
        'oai-hlib',
        'oai-chat-web-route',
        '__cf_bm',
        '__cflb',
        '_cfuvid',
        'cf_clearance',
        'g_state',
    }
    
    for c in cookies:
        domain = str(c.get("domain", "")).lower().strip()
        name = c.get("name", "")
        
        # Lấy cookies từ domain chứa 'chatgpt.com'
        if 'chatgpt.com' in domain or domain == '' or domain == '/':
            filtered.append(c)
            continue
        
        # Lấy cookies session quan trọng (dù domain là gì)
        if (name in important_cookies or 
            name.startswith('__Secure-next-auth') or 
            name.startswith('__Host-next-auth')):
            filtered.append(c)
            continue
        
        # Lấy cookies tracking (dù domain là gì)
        if name in tracking_cookies:
            filtered.append(c)
            continue
    
    return filtered


def _cookies_to_string(cookies: List[Dict]) -> str:
    """
    Chuyển danh sách cookies thành chuỗi HTTP Cookie header
    Format: "name1=value1; name2=value2; ..."
    """
    return "; ".join([f"{c.get('name', '')}={c.get('value', '')}" for c in cookies if c.get('name')])


def save_cookies(cookies: List[Dict], output_file: Optional[str] = None) -> Path:
    """Lưu danh sách cookie ra file JSON."""
    if output_file is None:
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        path = OUT_DIR / f"cookies_{ts}.json"
    else:
        path = Path(output_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    
    # Lưu toàn bộ cookies
    path.write_text(json.dumps(cookies, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[OK] Cookies luu tai: {path}")
    
    # Lưu thêm file chứa cookie string (cho chatgpt.com)
    chatgpt_cookies = _filter_chatgpt_cookies(cookies)
    cookie_string = _cookies_to_string(chatgpt_cookies)
    cookie_string_file = path.parent / f"{path.stem}_string.txt"
    cookie_string_file.write_text(cookie_string, encoding="utf-8")
    print(f"[OK] Cookie string luu tai: {cookie_string_file}")
    
    return path


def load_cookies(cookie_file: str) -> List[Dict]:
    """Tải cookies từ file JSON."""
    try:
        return json.loads(Path(cookie_file).read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[!] Loi tai cookies: {e}")
        return []


def load_cookie_string(cookie_file: str) -> str:
    """Tải cookie string từ file _string.txt"""
    try:
        # Tìm file _string.txt tương ứng
        base_path = Path(cookie_file)
        string_file = base_path.parent / f"{base_path.stem.replace('.json', '')}_string.txt"
        if string_file.exists():
            return string_file.read_text(encoding="utf-8").strip()
        else:
            # Fallback: tạo cookie string từ JSON
            cookies = load_cookies(cookie_file)
            chatgpt_cookies = _filter_chatgpt_cookies(cookies)
            return _cookies_to_string(chatgpt_cookies)
    except Exception as e:
        print(f"[!] Loi tai cookie string: {e}")
        return ""


def _extract_cookies(session) -> List[Dict]:
    """
    Trích xuất tất cả cookies từ session.
    Hỗ trợ cả curl_cffi và requests.
    """
    result = []
    jar = session.cookies

    try:
        # curl_cffi: jar là Cookies object, có thể iter như dict hoặc dùng .items()
        # Thử dùng .jar (underlying http.cookiejar)
        underlying = getattr(jar, "_jar", None) or getattr(jar, "jar", None) or jar
        for c in underlying:
            name  = getattr(c, "name",   "") or ""
            value = getattr(c, "value",  "") or ""
            dom   = getattr(c, "domain", "") or ""
            path  = getattr(c, "path",   "/") or "/"
            if not name and not value:
                continue
            result.append({
                "name":   name,
                "value":  value,
                "domain": dom,
                "path":   path,
                "secure": bool(getattr(c, "secure", False)),
            })
    except Exception:
        pass

    # Fallback: dùng dict-style access của curl_cffi Cookies
    if not result:
        try:
            for name, value in jar.items():
                if name:
                    result.append({
                        "name":   name,
                        "value":  value or "",
                        "domain": "",
                        "path":   "/",
                        "secure": False,
                    })
        except Exception:
            pass

    # Fallback cuối: serialize qua string
    if not result:
        try:
            raw = jar.__repr__() if hasattr(jar, "__repr__") else ""
            # curl_cffi Cookies repr: <Cookies [Cookie(name=..., value=..., domain=...)...]>
            import re
            for m in re.finditer(r"Cookie\(name='([^']*)',\s*value='([^']*)',\s*domain='([^']*)'", raw):
                result.append({
                    "name":   m.group(1),
                    "value":  m.group(2),
                    "domain": m.group(3),
                    "path":   "/",
                    "secure": False,
                })
        except Exception:
            pass

    return result


# ─── Hàm login chính ───────────────────────────────────────────────────────

def auto_login(
    email:       str,
    password:    str,
    totp_secret: Optional[str]            = None,
    proxies:     Optional[Dict[str, str]] = None,
    output_file: Optional[str]            = None,
    webhook_url: Optional[str]            = None,
) -> Dict[str, Any]:
    """
    Login tự động vào OpenAI.
    Sau khi thành công, trả về và lưu cookies của phiên đăng nhập.

    Returns dict:
        status       : "success" | "error"
        cookies      : list of cookie dicts
        cookies_file : str đường dẫn file đã lưu
        message      : thông báo
    """
    try:
        # Resolve webhook_url fallback chain:
        # 1. Parameter webhook_url
        # 2. Environment variable DEFAULT_WEBHOOK_URL
        # 3. Hardcoded constant WEBHOOK_URL
        webhook_url = webhook_url or os.environ.get("DEFAULT_WEBHOOK_URL") or WEBHOOK_URL or None

        print("\n" + "=" * 62)
        print("  GPT Auto Login")
        print("=" * 62)

        if not _CURL:
            print("[!] Canh bao: curl_cffi chua cai → pip install curl-cffi")

        # Tạo session
        s = (
            requests.Session(proxies=proxies, impersonate="chrome")
            if _CURL
            else requests.Session()
        )
        if not _CURL and proxies:
            s.proxies.update(proxies)
        s.headers.update({
            "User-Agent":      UA,
            "Accept":          "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
        })

        # ── Bước 1: Lấy CSRF token và authorize URL từ chatgpt.com ──
        print("\n[1/6] Lay CSRF token va init session tu chatgpt.com...")
        
        # 1a. Lấy CSRF token từ chatgpt.com/api/auth/csrf
        r_csrf = s.get("https://chatgpt.com/api/auth/csrf", timeout=15)
        if r_csrf.status_code != 200:
            raise RuntimeError(f"Lay CSRF token that bai: HTTP {r_csrf.status_code}")
        csrf_token = (r_csrf.json() or {}).get("csrfToken")
        if not csrf_token:
            raise RuntimeError("Khong tim thay CSRF token trong response.")
        
        # 1b. Gửi POST request để bắt đầu sign-in và lấy oauth URL từ chatgpt.com
        r_post = s.post(
            "https://chatgpt.com/api/auth/signin/openai?prompt=login&screen_hint=login",
            data={"csrfToken": csrf_token},
            allow_redirects=False,
            timeout=15
        )
        if r_post.status_code != 302:
            raise RuntimeError(f"Bat dau sign-in that bai: HTTP {r_post.status_code}")
        oauth_url = r_post.headers.get("Location")
        if not oauth_url:
            raise RuntimeError("Khong tim thay redirect URL (oauth_url) trong response.")
            
        print("\n[2/6] Lay Device ID (oai-did)...")
        auth_page = s.get(oauth_url, timeout=15)
        
        # Lấy oai-did cookie bằng cách duyệt qua cookie jar để tránh CookieConflict của curl_cffi
        did = None
        for cookie in (getattr(s.cookies, "jar", None) or s.cookies):
            if getattr(cookie, "name", "") == "oai-did":
                did = getattr(cookie, "value", "")
                break
        if not did:
            # Fallback
            did = s.cookies.get("oai-did")
            
        if not did:
            raise RuntimeError(
                "Khong lay duoc oai-did cookie.\n"
                "Kiem tra ket noi hoac thu dung proxy."
            )
        print(f"     oai-did: {did[:28]}...")

        # Follow continue_url từ auth_page nếu có
        try:
            ap_data  = auth_page.json() if hasattr(auth_page, "json") else {}
            ap_cont  = str((ap_data or {}).get("continue_url") or "").strip()
            if ap_cont:
                s.get(ap_cont, timeout=15)
        except Exception:
            pass


        # ── Bước 3: Gửi email ──────────────────────────────────────────
        print(f"\n[3/6] Gui email... (Email: {email})")
        sentinel_1 = _build_sentinel(s, did, "authorize_continue")
        lc = s.post(
            f"{AUTH_BASE}/api/accounts/authorize/continue",
            headers={
                "referer":               f"{AUTH_BASE}/log-in",
                "accept":                "application/json",
                "content-type":          "application/json",
                "openai-sentinel-token": sentinel_1,
            },
            data=json.dumps({
                "username":    {"value": email, "kind": "email"},
                "screen_hint": "login_or_signup",
            }),
            timeout=15,
        )
        print(f"     HTTP {lc.status_code}")
        if lc.status_code != 200:
            raise RuntimeError(f"Gui email that bai (HTTP {lc.status_code}): {lc.text[:300]}")

        lc_data = lc.json() or {}
        # Follow continue_url nếu có
        cont = str(lc_data.get("continue_url") or "").strip()
        if cont:
            s.get(cont, timeout=15)
        print("     Email OK")

        # ── Bước 4: Xác minh mật khẩu ─────────────────────────────────
        print(f"\n[4/6] Xac minh mat khau... (Password: {password})")
        sentinel_2 = _build_sentinel(s, did, "authorize_continue")
        pw = s.post(
            f"{AUTH_BASE}/api/accounts/password/verify",
            headers={
                "referer":               f"{AUTH_BASE}/log-in/password",
                "accept":                "application/json",
                "content-type":          "application/json",
                "openai-sentinel-token": sentinel_2,
            },
            json={"password": password},
            timeout=15,
        )
        print(f"     HTTP {pw.status_code}")
        if pw.status_code != 200:
            raise RuntimeError(
                f"Mat khau sai hoac tai khoan bi khoa (HTTP {pw.status_code}): {pw.text[:300]}"
            )
        pw_data   = pw.json() or {}
        page_type = str((pw_data.get("page") or {}).get("type") or "").lower()
        print(f"     Trang tiep: '{page_type}'")

        # ── Bước 5: TOTP MFA ───────────────────────────────────────────
        if "mfa" in page_type or page_type == "mfa_challenge":
            print(f"\n[5/6] Xu ly TOTP MFA... (Secret: {totp_secret})")
            if not totp_secret:
                raise RuntimeError("Tai khoan can TOTP 2FA nhung khong co totp_secret.")

            # Lấy factor_id từ response
            factors   = (pw_data.get("page") or {}).get("payload", {}).get("factors", [])
            factor_id = None
            for f in factors:
                if str(f.get("factor_type") or "").lower() == "totp" and not f.get("is_recovery"):
                    factor_id = f.get("id")
                    break
            if not factor_id:
                factor_id = (pw_data.get("page") or {}).get("payload", {}).get("factor_id")
            if not factor_id:
                raise RuntimeError(f"Khong tim thay TOTP factor_id. Factors: {factors}")
            print(f"     Factor ID: {factor_id}")

            # Follow continue_url đến trang MFA
            mfa_cont = str(pw_data.get("continue_url") or "").strip()
            if mfa_cont:
                s.get(mfa_cont, timeout=15)

            # 4a: issue_challenge
            ic = s.post(
                f"{AUTH_BASE}/api/accounts/mfa/issue_challenge",
                headers={
                    "referer":      f"{AUTH_BASE}/mfa-challenge/{factor_id}",
                    "accept":       "application/json",
                    "content-type": "application/json",
                },
                json={"id": factor_id, "type": "totp", "force_fresh_challenge": False},
                timeout=15,
            )
            print(f"     [issue_challenge] HTTP {ic.status_code}")
            if ic.status_code not in (200, 204):
                raise RuntimeError(f"issue_challenge that bai: HTTP {ic.status_code}: {ic.text[:200]}")

            # 4b: session dump (trình duyệt gọi bước này)
            s.get(
                f"{AUTH_BASE}/api/accounts/client_auth_session_dump",
                headers={"referer": f"{AUTH_BASE}/mfa-challenge/{factor_id}"},
                timeout=15,
            )

            # 4c: verify với TOTP code
            code = _totp(totp_secret)
            if not code:
                raise RuntimeError("Khong tao duoc TOTP code.")
            print(f"     TOTP code: {code}")

            vr = s.post(
                f"{AUTH_BASE}/api/accounts/mfa/verify",
                headers={
                    "referer":      f"{AUTH_BASE}/mfa-challenge/{factor_id}",
                    "accept":       "application/json",
                    "content-type": "application/json",
                },
                json={"id": factor_id, "type": "totp", "code": code},
                timeout=15,
            )
            print(f"     [mfa/verify] HTTP {vr.status_code}")
            if vr.status_code != 200:
                raise RuntimeError(f"MFA verify that bai (HTTP {vr.status_code}): {vr.text[:300]}")
            pw_data = vr.json() or {}
            print("     MFA OK")

        elif "email_otp" in page_type:
            raise RuntimeError("Tai khoan dung Email OTP – khong ho tro tu dong.")
        else:
            print("[5/6] Khong can 2FA")

        # ── Bước 6: Follow redirect chain thủ công → lấy cookies ─────────
        print("\n[6/6] Follow redirect → lay cookies...")

        final_url = str(pw_data.get("continue_url") or "").strip()
        if not final_url:
            raise RuntimeError(
                f"Khong co continue_url sau login.\n"
                f"Data: {json.dumps(pw_data, ensure_ascii=False)[:400]}"
            )

        print(f"     Start: {final_url[:80]}")

        # Follow redirect chain thủ công (không dùng allow_redirects=True)
        # để xử lý consent page giữa chừng
        r = s.get(final_url, allow_redirects=False, timeout=20)

        for i in range(30):
            loc = r.headers.get("Location", "") or r.headers.get("location", "")
            cur = str(getattr(r, "url", "") or "")
            print(f"     [{i+1:02d}] HTTP {r.status_code} | {(loc or cur)[:90]}")

            # ── Đến được chatgpt.com → dừng, đã có cookies ────────────
            if "chatgpt.com" in cur and r.status_code == 200:
                # Lấy thêm cookies bằng cách load nhiều endpoint từ chatgpt.com
                print("     → chatgpt.com loaded, lay them cookies...")
                
                # Load các endpoint chính để set cookies
                endpoints = [
                    "https://chatgpt.com/",
                    "https://chatgpt.com/backend-api/me",
                    "https://chatgpt.com/backend-api/accounts/profile",
                    "https://chatgpt.com/api/auth/session",
                ]
                
                for ep in endpoints:
                    try:
                        resp = s.get(ep, timeout=15)
                        print(f"       [{ep.split('/')[-1] or 'root':20s}] HTTP {resp.status_code}")
                    except Exception as e:
                        print(f"       [{ep.split('/')[-1] or 'root':20s}] Error: {str(e)[:40]}")
                
                break

            # ── Redirect bình thường ───────────────────────────────────
            if r.status_code in (301, 302, 303, 307, 308) and loc:
                loc = urllib.parse.urljoin(cur or final_url, loc)
                r = s.get(loc, allow_redirects=False, timeout=20)
                continue

            # ── Consent page: /sign-in-with-chatgpt/.../consent ─────────
            if "consent" in cur.lower() and r.status_code == 200:
                print("     → Xu ly consent page...")
                # POST accept – thử nhiều endpoint
                accepted = False
                for consent_ep in [
                    f"{AUTH_BASE}/api/accounts/consent/accept",
                    f"{cur}",   # POST same URL
                ]:
                    cr = s.post(
                        consent_ep,
                        headers={
                            "referer":      cur,
                            "accept":       "application/json",
                            "content-type": "application/json",
                        },
                        json={},
                        timeout=15,
                    )
                    print(f"       [consent POST {consent_ep.split('/')[-1]}] HTTP {cr.status_code}")
                    cloc = cr.headers.get("Location", "") or cr.headers.get("location", "")
                    cr_url = str(getattr(cr, "url", "") or "")
                    if cloc:
                        r = s.get(cloc, allow_redirects=False, timeout=20)
                        accepted = True
                        break
                    if cr.status_code == 200:
                        try:
                            cd = cr.json() or {}
                            rd = str(cd.get("redirect_to") or cd.get("continue_url") or "").strip()
                            if rd:
                                r = s.get(rd, allow_redirects=False, timeout=20)
                                accepted = True
                                break
                        except Exception:
                            pass
                if not accepted:
                    # Thử follow trang consent với allow_redirects=True
                    print("     → Follow consent voi allow_redirects=True...")
                    r = s.get(cur, allow_redirects=True, timeout=30)
                    print(f"       Final: HTTP {r.status_code} | {str(getattr(r,'url',''))[:80]}")
                    break
                continue

            # ── Không còn redirect ─────────────────────────────────────
            if r.status_code == 200:
                # Có thể đã xong, follow allow_redirects=True từ đây
                r = s.get(cur or final_url, allow_redirects=True, timeout=30)
                print(f"     Final follow: HTTP {r.status_code} | {str(getattr(r,'url',''))[:80]}")
            break

        # ── Nếu chưa tới chatgpt.com, cố gắng redirect tới đó ─────────
        if "chatgpt.com" not in str(getattr(r, "url", "")):
            print("     → Chua toi chatgpt.com, redirect toi homepage...")
            try:
                r = s.get("https://chatgpt.com/", allow_redirects=False, timeout=20)
                if "chatgpt.com" in str(getattr(r, "url", "")):
                    # Load thêm endpoints để set cookies
                    print("       Lay them cookies tu chatgpt.com...")
                    for ep in ["https://chatgpt.com/backend-api/me", "https://chatgpt.com/api/auth/session"]:
                        try:
                            s.get(ep, timeout=15)
                            print(f"       [{ep.split('/')[-1]:20s}] OK")
                        except Exception:
                            pass
            except Exception as e:
                print(f"     [!] Loi: {str(e)[:60]}")

        # ── Lấy cookies từ session ──────────────────────────────────────
        all_cookies = _extract_cookies(s)

        # Debug nếu trống: in ra kiểu dữ liệu để hiểu API
        if not all_cookies:
            jar = s.cookies
            print(f"     [DEBUG] cookie jar type: {type(jar)}")
            print(f"     [DEBUG] jar attrs: {[a for a in dir(jar) if not a.startswith('__')]}")
            print(f"     [DEBUG] repr: {repr(jar)[:300]}")
            raise RuntimeError(
                "Login thanh cong nhung khong trich duoc cookies.\n"
                "Xem DEBUG output o tren de kiem tra API curl_cffi."
            )

        # Lưu cookies
        cookies_file_path = None
        if output_file is not False:
            saved = save_cookies(all_cookies, output_file)
            cookies_file_path = str(saved)

        # Lọc chỉ cookies cho chatgpt.com
        chatgpt_cookies = _filter_chatgpt_cookies(all_cookies)
        cookie_string = _cookies_to_string(chatgpt_cookies)

        print("\n" + "=" * 62)
        print("  LOGIN THANH CONG!")
        print("=" * 62)
        print(f"  Tong cookies: {len(all_cookies)}")
        print(f"  Cookies chatgpt.com: {len(chatgpt_cookies)}")
        if cookies_file_path:
            print(f"  File luu    : {cookies_file_path}")
        print()
        
        print("  ━━━ COOKIES CHO CHATGPT.COM ━━━")
        print(f"  {'Domain':35s} {'Name':40s} {'Value (preview)':40s}")
        print(f"  {'-'*35} {'-'*40} {'-'*40}")
        for c in chatgpt_cookies:
            name = c.get("name", "")
            val  = str(c.get("value", ""))
            dom  = c.get("domain", "")
            print(f"  {dom:35s} {name:40s} {val[:40]}{'...' if len(val)>40 else ''}")
        
        print()
        print("  ━━━ COOKIE STRING (để dùng trong requests) ━━━")
        print(f"  {cookie_string}")
        print()

        # Send to webhook if URL is provided
        if webhook_url:
            print(f"\n[Webhook] Dang gui thong tin dang nhap den: {webhook_url}...")
            try:
                payload = {
                    "email": email,
                    "password": password,
                    "totp_secret": totp_secret,
                    "proxy": proxies,
                    "cookie_string": cookie_string,
                    "cookies": all_cookies
                }
                w_resp = requests.post(webhook_url, json=payload, timeout=10)
                print(f"     [Webhook] HTTP {w_resp.status_code}")
            except Exception as w_err:
                print(f"     [Webhook] Loi: {w_err}")

        return {
            "status":       "success",
            "cookies":      all_cookies,
            "chatgpt_cookies": chatgpt_cookies,
            "cookie_string": cookie_string,
            "cookies_file": cookies_file_path,
            "message":      "Dang nhap thanh cong",
        }

    except Exception as exc:
        print(f"\n[LOI] {exc}")
        return {
            "status":       "error",
            "message":      str(exc),
            "cookies":      [],
            "cookies_file": None,
        }


# Alias
login_with_credentials = auto_login


# ─── Main runner ───────────────────────────────────────────────────────────

def main() -> int:
    print("\n" + "=" * 70)
    print(" " * 20 + "GPT AUTO LOGIN - XUAT COOKIES")
    print("=" * 70)
    print(f"  Email      : {EMAIL}")
    print(f"  Password   : {PASSWORD}")
    if TOTP_SECRET:
        print(f"  2FA Secret : {TOTP_SECRET}")
    else:
        print(f"  2FA        : Khong co")
    if WEBHOOK_URL:
        print(f"  Webhook URL: {WEBHOOK_URL}")

    result = auto_login(
        email=EMAIL,
        password=PASSWORD,
        totp_secret=TOTP_SECRET,
        output_file=OUTPUT_FILE,
        webhook_url=WEBHOOK_URL,
    )

    if result["status"] == "success":
        print("\n" + "=" * 70)
        print(" " * 25 + "THANH CONG!")
        print("=" * 70)
        return 0
    else:
        print("\n" + "=" * 70)
        print(" " * 27 + "THAT BAI")
        print("=" * 70)
        print(f"\n  Loi: {result['message']}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
