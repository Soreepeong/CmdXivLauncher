# CmdXivLauncher

Log in and run international FFXIV game client via command line.

## Usage
usage: xivlogin.py [-h] [-i XIV_DIR] [-l LANGUAGE] [-s] -u USER -p PASSWORD [-o OTP] [-k OTP_KEY] [-x PROXY] [-a] [-d] ...

Log in and launch FFXIV game.

positional arguments:
```
  chain                 Runs specified program after detecting that a game window is running.
```

optional arguments:
```
  -h, --help            show this help message and exit
  -i XIV_DIR, --installation-directory XIV_DIR
                        FFXIV root installation directory. Will try to look up in registry if not specified.
  -l LANGUAGE, --language LANGUAGE
                        Language. Available values are English, French, German, and Japanese. Will use system language if not specified, and will fall back to English if unavailable.
  -s, --steam           Will identify as running from steam if set.
  -u USER, --user USER  Your user ID. Encoded value is accepted.
  -p PASSWORD, --password PASSWORD
                        Your password. Encoded value is accepted.
  -o OTP, --otp OTP     Your OTP. Encoded value is accepted.
  -k OTP_KEY, --otp-key OTP_KEY
                        Your OTP Key. Encoded value is accepted. pyotp is required.
  -x PROXY, --proxy PROXY
                        Proxy to use.
  -a, --admin-chain     Run chain as admin.
  -d, --debug           Prints parsed argument and exit instead of logging in.
```
You can use the following format to pass login parameters where applicable.
* plain,(text)
* hex,(hex encoded text)
* base64,(base64 encoded text)
* file,text,(path or - for stdin)
* file,json,(path or - for stdin)
* clipboard,text
* clipboard,json
* interactive

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

## Using with KeePass Open URL (Ctrl+U)
Duplicate your Square Enix account information, using references for ID and password.

URL should be:
```
cmd://python.exe path_to_xivlogin.py -u hex,{T-CONV:/{USERNAME}/Hex/} -p hex,{T-CONV:/{PASSWORD}/Hex/} -o hex,{T-CONV:/{TIMEOTP}/Hex/}
```

## Why another?
Read the section above.

## Special thanks to
* [FFXIVQuickLauncher](https://github.com/goatcorp/FFXIVQuickLauncher)
