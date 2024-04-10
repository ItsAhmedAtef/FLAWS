## FLAWS

FLAWS is a custom web scanner(**Subdomains - Ports - Endpoints**) made by [@ItsAhmedAtef](https://github.com/ItsAhmedAtef).

### Features
- **Recursive scan** - find the end of the chain.
- Using it for **bug bounty? exclude the out of scope** targets.
- **Complete from where you left off**, no need to start over again.
- Add as many wordlists as you want, there is **no duplicates**. :)
- **Delay option**, speed isn't always the key, sometimes you need to be patient.
- Poor connection? no worries, retry or stop the scan to **avoid the false results**.
- **Visualized output**.

### Installation
```
apt-get install python3-nmap
git clone https://github.com/ItsAhmedAtef/FLAWS.git
cd FLAWS/
chmod +x *.py
./flaws.py -h
```

### Plain Examples
```
user@linux:~/FLAWS$ ./flaws.py -t 127.0.0.1 -e -R -S
  ______ _           _          _ _____ 
 |  ____| |        /\ \        / / ____|
  | |__  | |       /  \ \  /\  / / (___ 
 |  __| | |      / /\ \ \/  \/ / \___ \ 
  | |    | |____ / ____ \  /\  /  ___) |
 |_|    |______/_/    \_\/  \/  |_____/ v1.0
--   F    0x4c    0x41    0x57    0x53   --

[~] Checking HTTP/S protcol for ports [80, 443].
[~] Fuzzing endpoints for target "http://127.0.0.1:80/"...
[+] 200 => http://127.0.0.1:80/.env.example
[~] Fuzzing endpoints for target "https://127.0.0.1:443/"...
[+] 301 => https://127.0.0.1:443/dashboard
        https://127.0.0.1:443/auth/login
[+] 403 => https://127.0.0.1:443/folders
[~] Fuzzing endpoints for target "https://127.0.0.1:443/folders/"...
[+] 403 => https://127.0.0.1:443/folders/backups
[~] Fuzzing endpoints for target "https://127.0.0.1:443/folders/backups/"...
[+] 200 => https://127.0.0.1:443/folders/backups/files.rar
```

```
user@linux:~/FLAWS$ ./flaws.py -t [REDACTED] -l
  ______ _           _          _ _____ 
 |  ____| |        /\ \        / / ____|
  | |__  | |       /  \ \  /\  / / (___ 
 |  __| | |      / /\ \ \/  \/ / \___ \ 
  | |    | |____ / ____ \  /\  /  ___) |
 |_|    |______/_/    \_\/  \/  |_____/ v1.0
--  FIND LATEST AVAILABLE WEAKNESS SPOT  --

[~] Host: [REDACTED]
[+] Open ports [4]: 80, 443, 3306, 8000
└─[~] Last scan: 2024/04/10 12:27:57 AM
[+] Subdomains [13]: 
├─[+] accounts.[REDACTED]
├─[+] backend.[REDACTED]
│ └─[+] ultimate.backend.[REDACTED]
├─[+] cpanel.[REDACTED]
├─[+] v1.demo.[REDACTED]
├─[+] v2.demo.[REDACTED]
├─[+] dev.[REDACTED]
├─[+] orders.[REDACTED]
├─[+] portal.[REDACTED]
├─[+] proxy.[REDACTED]
├─[+] shared.[REDACTED]
├─[+] webmail.[REDACTED]
└─[+] www.[REDACTED]
[!] HTTP/S Endpoints: Nothing found!
```

### License
FLAWS is licensed under the GNU General Public License version 3 (GNU GPL v3).

### Support
https://paypal.me/ItsAhmedAtef
