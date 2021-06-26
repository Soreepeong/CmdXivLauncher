import argparse
import base64
import ctypes.wintypes
import datetime
import enum
import functools
import getpass
import hashlib
import json
import os
import platform
import re
import struct
import subprocess
import sys
import time
import typing
import urllib.parse
import urllib.request
import urllib.response

FORMATTABLE_STRING_DESCRIPTION = r"""
You can use the following format to pass login parameters where applicable. 
* plain,(text)
* hex,(hex encoded text)
* base64,(base64 encoded text)
* file,text,(path or - for stdin)
* file,json,(path or - for stdin)
* clipboard,text
* clipboard,json
* interactive
* enc,(text|json),(path or - for stdin)[,passphrase]

For the --enc parameter, you can use the following format.
* path[,password]
* user[+p[+..]],(text|json),(path or - for stdout)[,passphrase][;user[+p[+..],..]]

Examples:
* python xivlogin.py -u plain,myusername -p hex,2a2b2c2d2e2f3031323334 -o clipboard,text
* python xivlogin.py -u file,json,C:\test.json -p file,json,C:\test.json -k file,json,C:\test.json
  * C:\test.json has the following format:
    ```json
    {
      "user": "myusername",
      "password": "mypassword",
      "otp_key": "0123456789ABCDEF"
    }
    ```
* python xivlogin.py -u plain,myusername -p interactive -o interactive
""".strip()
decrypted_cache = {}


def formatted_str_generator(key: str, descr: str, input_fn: callable = input):
    def formatted_str(val: str) -> str:
        if val.lower() == "interactive":
            return input_fn(descr)

        try:
            format_type, data = val.split(",", 1)
        except ValueError:
            # assume plain
            return val

        format_type = format_type.lower()
        if format_type == "plain":
            return data
        elif format_type == "hex":
            return bytes.fromhex(data).decode("utf-8")
        elif format_type == "base64":
            return base64.b64decode(data).decode("utf-8")

        if format_type == "file":
            data_source_type, data_source = data.split(",", 1)
            if data_source == "-":
                data = read_stdin()
            else:
                with open(data_source) as fp:
                    data = fp.read()
        if format_type == "enc":
            try:
                import argon2
                from argon2.low_level import hash_secret_raw
                from Crypto.Cipher import AES
                from Crypto.Random import get_random_bytes
            except ImportError:
                print("You need to install pycryptodom and argon2-cffi to use the encryption feature. Run `python -m pip install pycryptodom argon2-cffi`.")
                return -1
            data_source_type, data_source = data.split(",", 1)
            try:
                data_source, passphrase = data_source.split(",", 1)
            except ValueError:
                passphrase = None
            if data_source in decrypted_cache.keys():
                data = decrypted_cache[data_source]
            else:
                if not passphrase:
                    passphrase = getpass.getpass(f"Passphrase for {data_source}: ")
                if data_source == "-":
                    data = sys.stdin.buffer.read()
                else:
                    with open(data_source, 'rb') as fp:
                        data = fp.read()
                cipher = AES.new(
                    hash_secret_raw(
                        secret=passphrase.encode(encoding='utf-8'),
                        salt=data[8:16],
                        time_cost=2,
                        memory_cost=102400,
                        parallelism=8,
                        hash_len=32,
                        type=argon2.Type.ID
                    ),
                    AES.MODE_CTR,
                    nonce = data[:8],
                )
                while True:
                    try:
                        data = cipher.decrypt(data[16:]).decode(encoding='utf-8')
                        decrypted_cache[data_source] = data
                    except UnicodeDecodeError:
                        passphrase = getpass.getpass(f"Passphrase for {data_source}: ")
                        continue
                    break
        elif format_type == "clipboard":
            data_source_type = data
            data = get_clipboard_text()
        else:
            raise ValueError("Invalid format type")

        data_source_type = data_source_type.lower()
        if data_source_type == "text":
            return data
        elif data_source_type == "json":
            return json.loads(data)[key]
        else:
            raise ValueError("Invalid data source type")

    return formatted_str


CF_UNICODETEXT = 13
ctypes.windll.kernel32.GlobalLock.argtypes = ctypes.wintypes.LPVOID,
ctypes.windll.kernel32.GlobalLock.restype = ctypes.wintypes.LPVOID
ctypes.windll.kernel32.GlobalUnlock.argtypes = ctypes.wintypes.LPVOID,
ctypes.windll.kernel32.GlobalUnlock.restype = ctypes.wintypes.BOOL
ctypes.windll.user32.IsClipboardFormatAvailable.argtypes = ctypes.wintypes.UINT,
ctypes.windll.user32.IsClipboardFormatAvailable.restype = ctypes.wintypes.BOOL
ctypes.windll.user32.GetClipboardData.argtypes = ctypes.wintypes.UINT,
ctypes.windll.user32.GetClipboardData.restype = ctypes.wintypes.LPVOID
MUI_LANGUAGE_NAME = 8
ctypes.windll.kernel32.GetUserPreferredUILanguages.argtypes = (
    ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.c_ulong), ctypes.wintypes.LPCVOID, ctypes.POINTER(ctypes.c_ulong)
)
ctypes.windll.kernel32.GetUserPreferredUILanguages.restype = ctypes.wintypes.BOOL
INFINITE = 0xFFFFFFFF
WAIT_FAILED = 0xFFFFFFFF
ctypes.windll.user32.WaitForInputIdle.argtypes = ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD
ctypes.windll.user32.WaitForInputIdle.restype = ctypes.wintypes.DWORD


class CreateProcessStartupInfoW(ctypes.Structure):
    _fields_ = (
        ("cb", ctypes.wintypes.DWORD),
        ("lpReserved", ctypes.wintypes.LPCWSTR),
        ("lpDesktop", ctypes.wintypes.LPCWSTR),
        ("lpTitle", ctypes.wintypes.LPCWSTR),
        ("dwX", ctypes.wintypes.DWORD),
        ("dwY", ctypes.wintypes.DWORD),
        ("dwXSize", ctypes.wintypes.DWORD),
        ("dwYSize", ctypes.wintypes.DWORD),
        ("dwXCountChars", ctypes.wintypes.DWORD),
        ("dwYCountChars", ctypes.wintypes.DWORD),
        ("dwFillAttribute", ctypes.wintypes.DWORD),
        ("dwFlags", ctypes.wintypes.DWORD),
        ("wShowWindow", ctypes.wintypes.WORD),
        ("cbReserved2", ctypes.wintypes.WORD),
        ("lpReserved2", ctypes.wintypes.LPVOID),
        ("hStdInput", ctypes.wintypes.HANDLE),
        ("hStdOutput", ctypes.wintypes.HANDLE),
        ("hStdError", ctypes.wintypes.HANDLE),
    )


class CreateProcessInformation(ctypes.Structure):
    _fields_ = (
        ("hProcess", ctypes.wintypes.HANDLE),
        ("hThread", ctypes.wintypes.HANDLE),
        ("dwProcessId", ctypes.wintypes.DWORD),
        ("dwThreadId", ctypes.wintypes.DWORD),
    )


class ShellExecuteInfoW(ctypes.Structure):
    _fields_ = (
        ("cbSize", ctypes.wintypes.DWORD),
        ("fMask", ctypes.wintypes.ULONG),
        ("hwnd", ctypes.wintypes.HANDLE),
        ("lpVerb", ctypes.wintypes.LPCWSTR),
        ("lpFile", ctypes.wintypes.LPCWSTR),
        ("lpParameters", ctypes.wintypes.LPCWSTR),
        ("lpDirectory", ctypes.wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", ctypes.wintypes.HINSTANCE),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", ctypes.wintypes.LPCWSTR),
        ("hKeyClass", ctypes.wintypes.HKEY),
        ("dwHotKey", ctypes.wintypes.DWORD),
        ("hIconOrMonitor", ctypes.wintypes.HANDLE),
        ("hProcess", ctypes.wintypes.HANDLE),
    )


ctypes.windll.kernel32.CreateProcessW.argtypes = (
    ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPWSTR, ctypes.wintypes.LPVOID, ctypes.wintypes.LPVOID,
    ctypes.wintypes.BOOL, ctypes.wintypes.DWORD, ctypes.wintypes.LPVOID, ctypes.wintypes.LPCWSTR,
    ctypes.POINTER(CreateProcessStartupInfoW), ctypes.POINTER(CreateProcessInformation),
)
ctypes.windll.kernel32.CreateProcessW.restype = ctypes.wintypes.BOOL
ctypes.windll.kernel32.CloseHandle.argtypes = ctypes.wintypes.HANDLE,
ctypes.windll.kernel32.CloseHandle.restype = ctypes.wintypes.BOOL
ctypes.windll.user32.FindWindowExW.argtypes = (ctypes.wintypes.HWND, ctypes.wintypes.HWND, ctypes.wintypes.LPCWSTR,
                                               ctypes.wintypes.LPCWSTR)
ctypes.windll.user32.FindWindowExW.restype = ctypes.wintypes.HWND
ctypes.windll.shell32.ShellExecuteExW.argtypes = ctypes.POINTER(ShellExecuteInfoW),
ctypes.windll.shell32.ShellExecuteExW.restype = ctypes.wintypes.BOOL


def get_clipboard_text() -> str:
    ctypes.windll.user32.OpenClipboard(0)
    try:
        if ctypes.windll.user32.IsClipboardFormatAvailable(CF_UNICODETEXT):
            data = ctypes.windll.user32.GetClipboardData(CF_UNICODETEXT)
            data_locked = ctypes.windll.kernel32.GlobalLock(data)
            try:
                return ctypes.wintypes.LPCWSTR(data_locked).value
            finally:
                ctypes.windll.kernel32.GlobalUnlock(data_locked)
    finally:
        ctypes.windll.user32.CloseClipboard()


def get_language_list() -> typing.List[str]:
    num = ctypes.c_ulong()
    size = ctypes.c_ulong(0)
    if not ctypes.windll.kernel32.GetUserPreferredUILanguages(
            MUI_LANGUAGE_NAME, ctypes.byref(num), None, ctypes.byref(size)) or not size.value:
        return []
    buf = ctypes.create_unicode_buffer(size.value)

    if not ctypes.windll.kernel32.GetUserPreferredUILanguages(
            MUI_LANGUAGE_NAME, ctypes.byref(num), ctypes.byref(buf), ctypes.byref(size)):
        return []

    res = []
    offset = 0
    while offset < len(buf):
        sz = ctypes.wstring_at(ctypes.addressof(buf) + offset * 2)
        if not sz:
            break
        res.append(sz)
        offset += len(sz) + 1
    return res


class XivBootNeedPatchException(EnvironmentError):
    pass


class XivGameNeedPatchException(EnvironmentError):
    pass


class XivLoginError(ValueError):
    pass


class XivLanguage(enum.IntEnum):
    Japanese = 0
    English = 1
    German = 2
    French = 3

    @classmethod
    def parse(cls, x):
        if x is None:
            for lang in get_language_list():
                if lang[0:2] == 'en':
                    return XivLanguage.English
                elif lang[0:2] == 'ja':
                    return XivLanguage.Japanese
                elif lang[0:2] == 'de':
                    return XivLanguage.German
                elif lang[0:2] == 'fr':
                    return XivLanguage.French
            return XivLanguage.English
        if isinstance(x, str) and len(x) >= 1:
            if x[0] == 'j':
                return XivLanguage.Japanese
            elif x[0] == 'e':
                return XivLanguage.English
            elif x[0] in ('g', 'd'):
                return XivLanguage.German
            elif x[0] == 'f':
                return XivLanguage.French
        return XivLanguage(x)


class XivVersionInfo:
    _BASE_GAME_VERSION = "2012.01.01.0000.0000"
    _FILES_TO_HASH = (
        "ffxivboot.exe",
        "ffxivboot64.exe",
        "ffxivlauncher.exe",
        "ffxivlauncher64.exe",
        "ffxivupdater.exe",
        "ffxivupdater64.exe",
    )

    def __init__(self, xiv_dir: str):
        self._xiv_dir = xiv_dir

    @functools.cache
    def _load_version(self, *path):
        try:
            with open(os.path.join(self._xiv_dir, *path)) as fp:
                return fp.read()
        except FileNotFoundError:
            return XivVersionInfo._BASE_GAME_VERSION

    @functools.cached_property
    def boot(self):
        return self._load_version("boot", "ffxivboot.ver")

    @functools.cached_property
    def game(self):
        return self._load_version("game", "ffxivgame.ver")

    @functools.cache
    def hash(self, ex_ver: int) -> str:
        if ex_ver == 0:
            boot_hash = []
            for f in self._FILES_TO_HASH:
                with open(os.path.join(self._xiv_dir, "boot", f), "rb") as fp:
                    sha1 = hashlib.sha1()
                    while True:
                        buf = fp.read(8192)
                        if not buf:
                            break
                        sha1.update(buf)
                    boot_hash.append(f"{f}/{fp.tell()}/{sha1.hexdigest().lower()}")
            return f'{self.boot}={",".join(boot_hash)}'

        ver = self._load_version("game", "sqpack", f"ex{ex_ver}", f"ex{ex_ver}.ver")
        return f"{self.hash(ex_ver - 1)}\nex{ex_ver}\t{ver}"


class XivLogin:
    _WEB_USER_AGENT_FORMAT = "SQEXAuthor/2.0.0(Windows 6.2; ja-jp; {computer_id})"
    _BOOT_PATCH_CHECK_URL_FORMAT = ("http://patch-bootver.ffxiv.com/http/win32/ffxivneo_release_boot/{boot_ver}/"
                                    "?time={timestamp:%Y-%m-%d-%H-%M}")
    _LANDING_URL = "https://ffxiv-login.square-enix.com/oauth/ffxivarr/login/top"
    _LOGIN_URL = "https://ffxiv-login.square-enix.com/oauth/ffxivarr/login/login.send"
    _GAME_PATCH_CHECK_URL_FORMAT = "https://patch-gamever.ffxiv.com/http/win32/ffxivneo_release_game/{game_ver}/{sid}"
    _LANDING_STORED_REGEX = re.compile(r'\t<\s*input .* name="_STORED_" value="(.*?)">')
    _LOGIN_OK_REGEX = re.compile(r'window.external.user\("login=auth,ok,(.*?)"\);')
    _LOGIN_ERROR_REGEX = re.compile(r'window.external.user\("login=auth,ng,err,(.*?)"\);')

    def __init__(self,
                 computer_id: typing.Optional[bytes] = None,
                 language: XivLanguage = XivLanguage.English,
                 is_steam: bool = False,
                 region: int = 3,
                 xiv_dir: typing.Optional[str] = None,
                 proxy: typing.Optional[str] = None,
                 ):
        if xiv_dir is None:
            r = subprocess.Popen([
                'reg', 'query',
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{2B41E132-07DF-4925-A3D3-F2D1765CCDFE}",
                '/reg:32', '/v', 'DisplayIcon'],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT)
            stdout, _ = r.communicate()
            if r.returncode != 0:
                raise EnvironmentError("FFXIV Installation not found. You will have to specify with -x option.")
            xiv_dir = stdout.decode("utf-8").split("REG_SZ", 1)[1].strip()
            xiv_dir = os.path.normpath(os.path.join(xiv_dir, os.path.pardir, os.path.pardir))
            print("FFXIV Installation found at", xiv_dir)

        self._language = language
        self._is_steam = is_steam
        self._xiv_dir = xiv_dir
        self._region = region
        self._proxy = proxy
        self._version = XivVersionInfo(xiv_dir)

        if computer_id is None:
            computer_id = struct.pack("I", functools.reduce(
                lambda x, y: x ^ y,
                struct.unpack("IIIII", hashlib.sha1(json.dumps([
                    # don't ask
                    os.cpu_count(),
                    platform.architecture(),
                    platform.machine(),
                    platform.node(),
                    platform.processor(),
                    platform.python_build(),
                    platform.python_compiler(),
                    platform.python_branch(),
                    platform.python_implementation(),
                    platform.python_revision(),
                    platform.python_version(),
                    platform.release(),
                    platform.system(),
                    platform.version(),
                    platform.uname(),
                    platform.win32_ver(),
                    platform.win32_edition(),
                    platform.win32_is_iot(),
                ]).encode("utf-8")).digest())))
        computer_id = "".join(f"{x:02X}" for x in bytes((-sum(computer_id) % 256,)) + computer_id)
        self._user_agent = self._WEB_USER_AGENT_FORMAT.format(computer_id=computer_id)

    def _request(self, url: str, data: typing.Union[dict, str, bytes, None] = None,
                 headers: typing.Optional[dict] = None) -> urllib.response.addinfourl:
        if isinstance(data, str):
            data = data.encode("utf-8")
        elif isinstance(data, dict):
            data = urllib.parse.urlencode(data).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers or {})
        if self._proxy is not None:
            proxy = urllib.parse.urlparse(self._proxy)
            req.set_proxy(proxy.netloc, proxy.scheme.lower())
            if proxy.username is not None or proxy.password is not None:
                auth = base64.b64encode(f'{proxy.username or ""}:{proxy.password or ""}')
                req.headers["Proxy-Authorization"] = f"Basic {auth}"
        resp: urllib.response.addinfourl = urllib.request.urlopen(req)
        if resp.code // 100 != 2:
            raise RuntimeError(f"Remote error {resp.code}")
        return resp

    def _exec_launcher(self):
        return subprocess.Popen(os.path.join(self._xiv_dir, "boot", "ffxivboot.exe"))

    def _check_boot_version(self):
        print("* Checking boot version...")
        req = self._request(self._BOOT_PATCH_CHECK_URL_FORMAT.format(boot_ver=self._version.boot,
                                                                     timestamp=datetime.datetime.utcnow()))
        text = req.read().decode("utf-8")
        if text != "":
            print("\t=> Launcher needs update. Running ffxivboot.")
            self._exec_launcher()
            raise XivBootNeedPatchException(text)

    def _get_stored(self):
        stored = self._request(
            self._LANDING_URL + "?" + urllib.parse.urlencode({
                "lng": "en",
                "rgn": self._region,
                "isft": 0,
                "cssmode": 1,
                "isnew": 1,
                "issteam": 1 if self._is_steam else 0
            }),
            headers={
                "User-Agent": self._user_agent,
            },
            )
        text = stored.read().decode("utf-8")
        stored_value = self._LANDING_STORED_REGEX.search(text).group(1)
        return stored_value, stored.url

    def _login(self, user_id: str, password: str, otp: str):
        print("* Logging in...")
        stored_value, referer_url = self._get_stored()

        print("\t=> Verifying credentials...")
        login = self._request(
            self._LOGIN_URL,
            data={
                "_STORED_": stored_value,
                "sqexid": user_id,
                "password": password,
                "otppw": otp,
            },
            headers={
                "User-Agent": self._user_agent,
                "Referer": referer_url,
                "Content-Type": "application/x-www-form-urlencoded"
            },
        )
        text = login.read().decode("utf-8")
        login_result = self._LOGIN_OK_REGEX.search(text)
        if login_result is None:
            login_result = self._LOGIN_ERROR_REGEX.search(text)
            if login_result is not None:
                print("\t=>", login_result.group(1))
                raise XivLoginError(login_result.group(1))
            print("\t=> Unknown error.")
            raise XivLoginError(f"Invalid response: {text}")
        login_result = login_result.group(1).split(",")
        login_result = dict(zip(login_result[0::2], login_result[1::2]))

        max_ex = int(login_result['maxex'])
        web_sid = login_result['sid']
        return max_ex, web_sid

    def _get_game_sid(self, sid: str, max_ex: int):
        print("* Checking game version...")
        session = self._request(
            self._GAME_PATCH_CHECK_URL_FORMAT.format(game_ver=self._version.game, sid=sid),
            data=str(self._version.hash(max_ex)),
            headers={
                "X-Hash-Check": "enabled",
                "User-Agent": "FFXIV PATCH CLIENT",
                "Content-Type": "application/x-www-form-urlencoded"
            },
        )
        text = session.read().decode("utf-8")
        if text != "":
            print("\t=> Launcher needs update. Running ffxivboot.")
            self._exec_launcher()
            raise XivGameNeedPatchException(text)
        return session.headers.get("X-Patch-Unique-Id")

    def _exec(self, game_sid: str, max_ex: int):
        print("* Starting game...")
        args = [
            os.path.join(self._xiv_dir, "game", "ffxiv_dx11.exe"),
            f"DEV.DataPathType=1",
            f"DEV.MaxEntitledExpansionID={max_ex}",
            f"DEV.TestSID={game_sid}",
            f"DEV.UseSqPack=1",
            f"SYS.Region=2",
            f"language={self._language.value}",
            f"ver={self._version.game}",
        ]
        proc_info = CreateProcessInformation()
        start_info = CreateProcessStartupInfoW()
        start_info.cb = ctypes.sizeof(start_info)

        if not ctypes.windll.kernel32.CreateProcessW(
                args[0], " ".join(f'"{x}"' if ' ' in x else x for x in args), None, None, True, 0, None, None,
                ctypes.byref(start_info), ctypes.byref(proc_info)):
            raise ctypes.WinError()
        try:
            if ctypes.windll.user32.WaitForInputIdle(proc_info.hProcess, INFINITE) == WAIT_FAILED:
                raise ctypes.WinError()
            until = time.time() + 5
            while until > time.time() and ctypes.windll.user32.FindWindowExW(None, None, "FFXIVGAME", None) is None:
                time.sleep(0.1)
        finally:
            ctypes.windll.kernel32.CloseHandle(proc_info.hThread)
            ctypes.windll.kernel32.CloseHandle(proc_info.hProcess)

    def login(self, user_id: str, password: str, otp: str):
        self._check_boot_version()
        max_ex, web_sid = self._login(user_id, password, otp)
        game_sid = self._get_game_sid(web_sid, max_ex)
        return self._exec(game_sid, max_ex)


@functools.cache
def read_stdin():
    return sys.stdin.read()


def __main__(prog, *args):
    parser = argparse.ArgumentParser(prog,
                                     description="Log in and launch FFXIV game.",
                                     epilog=FORMATTABLE_STRING_DESCRIPTION,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-i", "--installation-directory", action="store",
                        type=str, dest="xiv_dir", default=None,
                        help="FFXIV root installation directory. Look up in registry if not specified.")
    parser.add_argument("-l", "--language", action="store",
                        type=XivLanguage.parse, dest="language", default=XivLanguage.parse(None),
                        help="Language. Available values are E(nglish), F(rench), G(erman), and J(apanese). Use system "
                             "language if not specified, and will fall back to English if unavailable.")
    parser.add_argument("-s", "--steam", action="store_true", dest="is_steam",
                        help="Identify as running from steam.")
    parser.add_argument("-u", "--user", action="store", required=True,
                        type=formatted_str_generator("user", "User: "), dest="user",
                        help="Your user ID. Encoded value is accepted.")
    parser.add_argument("-p", "--password", action="store", required=True,
                        type=formatted_str_generator("password", "Password: ", getpass.getpass), dest="password",
                        help="Your password. Encoded value is accepted.")
    parser.add_argument("-o", "--otp", action="store",
                        type=formatted_str_generator("otp", "OTP: "), dest="otp",
                        help="Your OTP. Encoded value is accepted.")
    parser.add_argument("-k", "--otp-key", action="store",
                        type=formatted_str_generator("otp_key", "OTP Key: "), dest="otp_key",
                        help="Your OTP Key. Encoded value is accepted. pyotp is required.")
    parser.add_argument("-x", "--proxy", action="store",
                        type=str, dest="proxy",
                        help="Proxy URL to use in format of http://0.0.0.0:80")
    parser.add_argument("-a", "--admin-chain", action="store_true", dest="admin_chain",
                        help="Run chain as admin.")
    parser.add_argument("-d", "--debug", action="store_true",
                        help="Print parsed argument and exit instead of logging in.")
    parser.add_argument("--enc", action="store", type=str, dest="encrypt", default=None,
                        help="Instead of logging in, generate encrypted files with parameters as contents. "
                             "Encoded value is accepted. If no passphrase is provided, it will be provided "
                             "interactively. If passphrase is only given for some files and not others, the "
                             "passphrase given for the previous file will be used. If the parameter is just a path, "
                             "it will be interpreted as storing all given parameters to the file as a json format.")
    parser.add_argument("chain", nargs=argparse.REMAINDER, type=str,
                        help="Run specified program after detecting that a game window is running. ")
    args = parser.parse_args(args)
    if args.otp_key:
        if args.otp:
            raise ValueError("Cannot provide both otp and otp key.")

        try:
            import pyotp
        except ImportError:
            print("You need to install pyotp to use otp-key feature. Run `python -m pip install pyotp`.")
            return -1

        args.otp = pyotp.TOTP(re.sub('[^A-Za-z0-9]', '', args.otp_key)).now()
    elif not args.otp:
        args.otp = ""
    if args.debug:
        print(args)
        return 0
    if args.encrypt:
        try:
            import argon2
            from argon2.low_level import hash_secret_raw
            from Crypto.Cipher import AES
            from Crypto.Random import get_random_bytes
        except ImportError:
            print("You need to install pycryptodom and argon2-cffi to use the encryption feature. Run `python -m pip install pycryptodom argon2-cffi`.")
            return -1
        passphrase = None
        enc_files = args.encrypt.split(';')
        for enc_file in enc_files:
            if enc_file:
                data = {}
                try:
                    params, format_type, enc_file = enc_file.split(',', 2)
                    params = params.lower().split('+')
                    format_type = format_type.lower()
                    if len(params) > 1 and format_type not in ('json'):
                        print('Format type must be container type such as json to contain multiple values.')
                        return -1
                    if format_type == 'json':
                        if 'u' in params or 'user' in params:
                            data['user'] = args.user
                        if 'p' in params or 'password' in params:
                            data['password'] = args.password
                        if 'k' in params or 'otp-key' in params:
                            data['otp_key'] = args.otp_key
                        data = json.dumps(data).encode(encoding='utf-8')
                    else:
                        if 'u' in params or 'user' in params:
                            data = args.user
                        elif 'p' in params or 'password' in params:
                            data = args.password
                        elif 'k' in params or 'otp-key' in params:
                            data = args.otp_key
                        data = data.encode(encoding='utf-8')
                        if format_type == 'text':
                            pass
                        else:
                            raise Exception(f'Invalid internal format type: {format_type}')
                except ValueError:
                    data['user'] = args.user
                    data['password'] = args.password
                    if args.otp_key:
                        data['otp_key'] = args.otp_key
                    data = json.dumps(data).encode(encoding='utf-8')
                try:
                    enc_file, passphrase = enc_file.split(',', 1)
                except ValueError:
                    if not passphrase:
                        passphrase = getpass.getpass(f"Password for encrypting {enc_file}: ")
                salt = get_random_bytes(8)
                cipher = AES.new(
                    hash_secret_raw(
                        secret=passphrase.encode(encoding='utf-8'),
                        salt=salt,
                        time_cost=2,
                        memory_cost=102400,
                        parallelism=8,
                        hash_len=32,
                        type=argon2.Type.ID
                    ),
                    AES.MODE_CTR,
                )
                cpdata = cipher.encrypt(data)
                if enc_file == '-':
                    sys.stdout.buffer.write(cipher.nonce+salt+cpdata)
                with open(enc_file, 'wb') as fp:
                    fp.write(cipher.nonce+salt+cpdata)
        return 0
    print(f"Logging in as {args.user}... (steam={args.is_steam}, language={args.language.name})")
    XivLogin(language=args.language,
             xiv_dir=args.xiv_dir,
             is_steam=args.is_steam,
             proxy=args.proxy,
             ).login(args.user, args.password, args.otp)

    if not args.chain:
        return 0

    info = ShellExecuteInfoW()
    info.cbSize = ctypes.sizeof(info)
    info.lpVerb = "runas" if args.admin_chain else "open"
    info.lpFile = args.chain[0]
    info.lpParameters = " ".join(args.chain[1:]) if len(args.chain) > 1 else ""
    info.nShow = 1
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(info)):
        raise ctypes.WinError()
    return 0


if __name__ == "__main__":
    try:
        exit(__main__(*sys.argv))
    except KeyboardInterrupt:
        print("\t=> Operation canceled.")
        exit(-1)
    except (XivLoginError, XivBootNeedPatchException, XivGameNeedPatchException):
        exit(-1)
    except Exception as e:
        print(type(e), e)
        exit(-1)
