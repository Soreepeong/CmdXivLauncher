# CmdXivLauncher

Log in and run international FFXIV game client via command line.

## Usage
usage: xivlogin.py [-h] [-i XIV_DIR] [-l LANGUAGE] [-s] -u USER -p PASSWORD [-o OTP] [-k OTP_KEY] [-x PROXY] [-a] [-d] [--enc ENCRYPT] ...

Log in and launch FFXIV game.

positional arguments:
```
  chain                 Run specified program after detecting that a game window is running.
```

optional arguments:
```
  -h, --help            show this help message and exit
  -i XIV_DIR, --installation-directory XIV_DIR
                        FFXIV root installation directory. Look up in registry if not specified.
  -l LANGUAGE, --language LANGUAGE
                        Language. Available values are E(nglish), F(rench), G(erman), and J(apanese). Use system language if not specified, and will fall back to English if unavailable.
  -s, --steam           Identify as running from steam.
  -u USER, --user USER  Your user ID. Encoded value is accepted.
  -p PASSWORD, --password PASSWORD
                        Your password. Encoded value is accepted.
  -o OTP, --otp OTP     Your OTP. Encoded value is accepted.
  -k OTP_KEY, --otp-key OTP_KEY
                        Your OTP Key. Encoded value is accepted. pyotp is required.
  -x PROXY, --proxy PROXY
                        Proxy URL to use in format of http://0.0.0.0:80
  -a, --admin-chain     Run chain as admin.
  -d, --debug           Print parsed argument and exit instead of logging in.
  --enc ENCRYPT         Instead of logging in, generate encrypted files with parameters as contents. Encoded value is accepted. If no passphrase is provided, it will be provided interactively.
                        If passphrase is only given for some files and not others, the passphrase given for the previous file will be used. If the parameter is just a path, it will be
                        interpreted as storing all given parameters to the file as a json format.

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
* enc,(text|json),(path or - for stdin)[,passphrase]

For the --enc parameter, you can use the following format.
* path[,passphrase]
* user[+p[+..]],(text|json),(path or - for stdout)[,passphrase][;user[+p[+..],..]]

(a|b) means either a or b is required, [] means optional, .. means similar repeated sequences.

Examples:
* `python xivlogin.py -u plain,myusername -p hex,2a2b2c2d2e2f3031323334 -o clipboard,text`
* `python xivlogin.py -u file,json,C:\test.json -p file,json,C:\test.json -k file,json,C:\test.json`
  * `C:\test.json` has the following format:
    ```json
    {
        "user": "myusername",
        "password": "mypassword",
        "otp_key": "0123456789ABCDEF"
    }
    ```
* `python xivlogin.py -u plain,myusername -p interactive -o interactive`

* encrypt provided username, password, and otp key with passphrase from stdin
** `python xivlogin.py --enc C:\test.enc -u user -p pass -k key`
* similarly, provide passphrase 'encpass' on command line
** `python xivlogin.py --enc C:\test.enc,encpass -u user -p pass -k key`
* encrypt provided username and password to one json file with passphrase from stdin and otp key to a text file with passphrase 'encpass'
** `python xivlogin.py --enc user+password,json,C:\userpass.enc;otp-key,text,C:\key.enc,encpass -u user -p pass -k key`
* similarly, with abbreviation
** `python xivlogin.py --enc u+p,json,C:\userpass.enc;k,text,C:\key.enc,encpass -u user -p pass -k key`

* login with credentials from encrypted files and passphrase from stdin:
** `python xivlogin.py -u enc,text,C:\username.enc -p enc,text,C:\passphrase.enc -k enc,text,C:\key.enc`
* with a single encrypted json file:
** `python xivlogin.py -u enc,json,C:\test.enc -p enc,json,C:\test.enc -k enc,json,C:\test.enc`
* mix and match, with password provided on the command line (key.enc uses encpass2):
** `python xivlogin.py -u enc,json,C:\test.enc,encpass1 -p enc,text,C:\pass.enc,encpass2 -k enc,text,C:\key.enc`

## Using with KeePass Open URL (Ctrl+U)
Duplicate your Square Enix account information, using references for ID and password.

URL should be:
```
cmd://python.exe path_to_xivlogin.py -u hex,{T-CONV:/{USERNAME}/Hex/} -p hex,{T-CONV:/{PASSWORD}/Hex/} -o hex,{T-CONV:/{TIMEOTP}/Hex/}
```

## Why another?
Read the section above. Now that it works, let me go queue up Dun Scaith and The Orbonne Monastery.

## Special thanks to
* [FFXIVQuickLauncher](https://github.com/goatcorp/FFXIVQuickLauncher)
