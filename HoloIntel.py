
def install():
    import os
    import sys
    try:
        os.system("pip install --upgrade pip")
    except OSError:
        pass
    try:
        os.system("python3 -m pip install --upgrade pip")
    except:
        pass
    try:
        os.system("python -m pip install --upgrade pip")
    except:
        pass
    try:
        os.system("pip install requests")
        print("---------------------------\nInstall requests successfully.\n")
    except ImportError:
        pass
    try:
        os.system("pip install concurrent.futures")
        print("---------------------------\nInstall concurrent.futures successfully.\n")
    except ImportError:      
        pass
    try:
        os.system("pip install colorama")
        print("---------------------------\nInstall colorama successfully.\n")
    except ImportError:
        pass
    try:
        os.system("pip install exifread")
        print("---------------------------\nInstall exifread successfully.\n")
    except ImportError:
        pass
    try:
        os.system("pip install psutil")
        print("---------------------------\nInstall psutil successfully.\n")
    except ImportError:
        pass

def banner_for_install():
    print("""
          INSTALL FIRST      Version 1.3
                         _Y_
                       ( o o )
       ____________oOO___(_)___OOo______
      /                                /
     /     RAVEN PROTOCOL ACTIVE      /
    /   Watching. Waiting. Listening /
   /          By. Potter            /
  /________________________________/
          
          """)
    
def banner():
    print(Style.BRIGHT + Fore.GREEN +"""             
                         _Y_
                       ( o o )
       ____________oOO___(_)___OOo______
      /                                /
     /     RAVEN PROTOCOL ACTIVE      /
    /   Watching. Waiting. Listening /
   /          By. Potter            /
  /________________________________/ Version 1.3
          
          """+ Style.RESET_ALL)

def function_name():
    print("""
       Hello, YOU 
          
    IP
    [1] - IP Geolocation
    [4] - Reverse IP Lookup
          
    Email
    [2] - Email Verification
    [8] - Email look up
    
    Domain
    [3] - Domain Reputation
    [5] - Subdomain Lookup
    
          
    Phone
    [6] - Phone Number Lookup
          
    Username used
    [7] - Username Lookup
    
    Pic
    [9] Metadata
    
    Find phonenumber and Email
    [10] ContactFinder
          

    Wifi-lan 
    [11] Wifi-lan looks up tool
          

    Tools-Sites-For-Spy
    [links]
    [WIFI] Wifi looks up
    
          
""")
def exit():
    print(Fore.RED + """
        [0] - Exit
        [H] - Help
    """ + Style.RESET_ALL)


#IPinfo.io
def get_ip_info(ip_address):
    url = f"https://ipinfo.io/{ip_address}/json"
    response = requests.get(url)
    data = response.json()
    
    return data

def get_ip_info_whoixml(ip_address):
    url = f"https://ip-geolocation.whoisxmlapi.com/api/v1?apiKey=at_2HJU294oEIupFFWLVBJAP4fnYPYmk&ipAddress={ip_address}"
    response = requests.get(url)
    data = response.json()
    
    return data

def get_ip_info_ip_api(ip_address):
    url = f"http://ip-api.com/json/{ip_address}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return None
    
def get_ip_info(ip):
    api_key = "f7969b818f571b7b4b6a8745570d9986"
    url = f"http://api.ipstack.com/{ip}?access_key={api_key}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return None
    

def email_verification(email):
    url = f"https://emailverification.whoisxmlapi.com/api/v3?apiKey=at_2HJU294oEIupFFWLVBJAP4fnYPYmk&emailAddress=support@whoisxmlapi.com"
    response = requests.get(url)
    data = response.json()
    
    return data

def domain_reputation(domain):
    url = f"https://domain-reputation.whoisxmlapi.com/api/v2?apiKey=at_2HJU294oEIupFFWLVBJAP4fnYPYmk&domainName={domain}"
    response = requests.get(url)
    data = response.json()

    return data


def reverse_ip_lookup(ip_address):
    # URL ของ API
    url = "https://reverse-ip.whoisxmlapi.com/api/v1"
    
    # ส่งคำขอไปยัง API
    response = requests.get(url, params={
        "apiKey": "at_2HJU294oEIupFFWLVBJAP4fnYPYmk",
        "ip": ip_address
    })
    
    # ตรวจสอบสถานะของคำขอ
    if response.status_code == 200:
        data = response.json()
        
        # ตรวจสอบว่า 'result' อยู่ในข้อมูลหรือไม่
        if 'result' in data:
            return data['result']  # ส่งกลับข้อมูลที่อยู่ใน result
        else:
            print("ไม่พบข้อมูลในผลลัพธ์.")
            return None
    else:
        print(f"เกิดข้อผิดพลาดในการเรียก API, Status Code: {response.status_code}")
        return None

def subdomain_lookup(domain):
    response = requests.get(
        f"https://subdomains.whoisxmlapi.com/api/v1?apiKey=YOUR_API_KEY&domainName={domain}"
    )
    data = response.json()
    
    records = data.get('result', {}).get('records', [])
    if not records:
        print("ไม่พบ subdomains สำหรับโดเมนนี้")
    
    return data  # ✅ return ทั้ง JSON

def phone_number_lookup_apilayer(phone_number):
    api_key = 'de907b2d10edc906236208b64b7d0378'
    phone_number = f'{phone_number}'  # ใส่เบอร์แบบรวมรหัสประเทศ
    url = f'http://apilayer.net/api/validate?access_key={api_key}&number={phone_number}'

    response = requests.get(url)
    data = response.json()

    print(f"""\nData from > apilayer.net
Valid: {data['valid']}
Number: {data['number']}
Local Format: {data['local_format']}
International Format: {data['international_format']}
Country: {data['country_name']}
Location: {data['location']}
Carrier: {data['carrier']}
Line Type: {data['line_type']}
    """)

def phone_number_lookup_abstractAPI(phone_number):
    # ทำการเรียก API จาก Abstract API
    response = requests.get(f"https://phonevalidation.abstractapi.com/v1/?api_key=afe0e3e3c4d646e99d7114d147e287d9&phone={phone_number}")
    
    # ตรวจสอบว่า response ได้รับข้อมูลมาหรือไม่
    if response.status_code == 200:
        # แปลง response ให้เป็น json
        data = response.json()
        
        # แสดงผลข้อมูลที่ได้จาก API
        print(f"""Data from > abstractapi.com
Phone Number: {data['phone']}
Valid: {data['valid']}
International Format: {data['format']['international']}
Local Format: {data['format']['local']}

Country: {data['country']['name']} ({data['country']['code']})
Country Prefix: {data['country']['prefix']}
Location: {data['location']}

Line Type: {data['type']}
Carrier: {data['carrier']}
        """)
    else:
        print(f"Error: Unable to retrieve information for phone number {phone_number}")

#Check username =======================================================================
def is_valid_username(username):
    # อนุญาตเฉพาะ a-z A-Z 0-9 _ - .
    return all(c.isalnum() or c in ['_', '-', '.', ' '] for c in username)

sites = {
    "\n---------------------------\n"
    "AngelList": "https://angel.co/u/{}",
    "Ask": "https://www.ask.com/web?q={}",
    "Behance": "https://www.behance.net/{}",
    "Badoo": "https://badoo.com/en/{}",
    "Bing": "https://www.bing.com/search?q={} ",
    "Box Office Mojo": "https://www.boxofficemojo.com/{}",
    "Chaturbate": "https://chaturbate.com/{}",
    "Clubhouse": "https://www.joinclubhouse.com/@{}",
    "Crunchbase": "https://www.crunchbase.com/person/{}",
    "Dailymotion": "https://www.dailymotion.com/{}",
    "DeviantArt": "https://www.deviantart.com/{}",
    "Disney+": "https://www.disneyplus.com/{}",
    "Dribbble": "https://dribbble.com/{}",
    "DuckDuckGo": "https://duckduckgo.com/?q={}",
    "Eventbrite": "https://www.eventbrite.com/d/online/{}",
    "Facebook": "https://www.facebook.com/{}",
    "Fandango": "https://www.fandango.com/{}",
    "Fiverr": "https://www.fiverr.com/{}",
    "Flickr": "https://www.flickr.com/photos/{}",
    "Freelancer": "https://www.freelancer.com/u/{}",
    "GitHub": "https://github.com/{}",
    "GitLab": "https://gitlab.com/{}",
    "Glassdoor": "https://www.glassdoor.com/Overview/Working-at-{}",
    "Grindr": "https://grindr.com/{}",
    "Hulu": "https://www.hulu.com/users/{}",
    "Indeed": "https://www.indeed.com/cmp/{}",
    "Instagram": "https://www.instagram.com/{}",
    "IMDb": "https://www.imdb.com/user/{}",
    "LinkedIn": "https://www.linkedin.com/in/{}",
    "LiveCamModels": "https://www.livecammodels.com/{}",
    "LiveJasmin": "https://www.livejasmin.com/en/chat/{}",
    "Match": "https://www.match.com/profile/{}",
    "MeWe": "https://mewe.com/i/{}",
    "Medium": "https://medium.com/@{}",
    "Mix": "https://mix.com/{}",
    "MyFreeCams": "https://www.myfreecams.com/{}",
    "MySpace": "https://myspace.com/{}",
    "Netflix": "https://www.netflix.com/profiles/{}",
    "OkCupid": "https://www.okcupid.com/profile/{}",
    "OnlyFans": "https://onlyfans.com/{}",
    "Periscope": "https://www.pscp.tv/{}",
    "Patreon": "https://www.patreon.com/{}",
    "Pinterest": "https://www.pinterest.com/{}",
    "PlentyOfFish": "https://www.pof.com/profile/{}",
    "ProductHunt": "https://www.producthunt.com/@{}",
    "Quora": "https://www.quora.com/profile/{}",
    "Reddit": "https://www.reddit.com/user/{}",
    "Redbubble": "https://www.redbubble.com/people/{}",
    "Rotten Tomatoes": "https://www.rottentomatoes.com/user/{}",
    "SoundCloud": "https://soundcloud.com/{}",
    "Spotify": "https://open.spotify.com/user/{}",
    "StackOverflow": "https://stackoverflow.com/users/{}",
    "Skype": "https://www.skype.com/{}",
    "Snapchat": "https://www.snapchat.com/add/{}",
    "Tango": "https://www.tango.me/{}",
    "TikTok": "https://www.tiktok.com/@{}",
    "Trakt": "https://trakt.tv/users/{}",
    "Tribe": "https://www.tribe.com/{}",
    "Tumblr": "https://{}.tumblr.com/",
    "Twitch": "https://www.twitch.tv/{}",
    "Twitter": "https://twitter.com/{}",
    "Vimeo": "https://vimeo.com/{}",
    "Viber": "https://www.viber.com/{}",
    "Vkontakte": "https://vk.com/{}",
    "WeChat": "https://mp.weixin.qq.com/{}",
    "Weibo": "https://weibo.com/{}",
    "Wikipedia": "https://en.wikipedia.org/wiki/User:{}",
    "WhatsApp": "https://wa.me/{}",
    "XHamsterLive": "https://www.xhamsterlive.com/{}",
    "Xing": "https://www.xing.com/profile/{}",
    "YouNow": "https://www.younow.com/{}",
    "YouTube": "https://www.youtube.com/c/{}",
    "Yandex": "https://yandex.com/search/?text={}",
    "Zoosk": "https://www.zoosk.com/profile/{}",
}

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "en-US,en;q=0.9,th;q=0.8",
    "Connection": "keep-alive",
    "Cache-Control": "max-age=0",
    "Upgrade-Insecure-Requests": "1",
    "Referer": "https://www.google.com/",
    "TE": "Trailers",
    "X-Requested-With": "XMLHttpRequest",  # ใช้ในกรณี AJAX requests
    "DNT": "1",  # Do Not Track header
    "Pragma": "no-cache",
    "If-None-Match": '"e0023aa4c04b2483f5f6a8f6d9e83255"',
    "X-Forwarded-For": "203.0.113.195"  # ใช้สำหรับการ spoofing IP (จำลองการใช้งานจาก IP อื่น)
}


def check_username(site, url_pattern, username):
    url = url_pattern.format(username)
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            return f"{site}: {Style.BRIGHT + Fore.GREEN + 'Username found → ' + url + Style.RESET_ALL}"
        elif response.status_code == 404:
            return f"{site}: {Fore.RED + 'Username not found (404)' + Style.RESET_ALL}"
        elif response.status_code == 400:
            return f"{site}: {Fore.YELLOW + 'Bad request (400)' + Style.RESET_ALL}"
        else:
            return f"{site}: {Fore.YELLOW + 'Response code ' + str(response.status_code) + Style.RESET_ALL}"
    except requests.exceptions.RequestException:
        return f"{site}: {Fore.RED + 'Unable to connect' + Style.RESET_ALL}"
    

# ฟังก์ชั่นตรวจหลายชื่อ
def check_multiple_usernames(usernames):
    all_results = []
    with ThreadPoolExecutor() as executor:
        futures = []
        for username in usernames:
            if not username:
                all_results.append(f"⚠️ Please enter a valid username.")
            elif not is_valid_username(username):
                all_results.append(f"❗ Invalid username, it may contain spaces or invalid characters.")
            else:
                # ตรวจสอบชื่อเดียวกับทุกเว็บไซต์
                for site, url_pattern in sites.items():
                    futures.append(executor.submit(check_username, site, url_pattern, username))

        # รอผลลัพธ์จากทุกคำขอที่ส่งไป
        for future in futures:
            result = future.result()
            # ตรวจสอบว่า result คือสตริงก่อนที่จะเพิ่มเข้าไปใน all_results
            if isinstance(result, str):
                all_results.append(result)
            else:
                # ถ้าเป็น tuple แปลงเป็น string
                all_results.append(' '.join(str(item) for item in result))  # รวมเป็นสตริง

    return all_results


def email_leak_lookup(email):
    API_KEY = "99bb292bc71fff06b8d0967df6f8094d"
    url = "https://leak-lookup.com/api/search"
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "type": "email",
        "query": email
    }

    response = requests.post(url, json=data, headers=headers)

    if response.status_code == 200:
        result = response.json()
        if result.get("success"):
            breaches = result.get("found", [])
            print(f"Leaked data found for {email}:")
            for breach in breaches:
                print(f" - Database name:: {breach['database']}")
                print(f" - Password (hash or plain): {breach.get('password', 'N/A')}")
                print("You can check hash here:https://crackstation.net/")
        else:
            print("No leaks found for this email.")
    else:
        print("Error occurred: HTTP:", response.status_code)
    print("---------------------------\n")

def dms_to_decimal(dms, ref):
    degrees = float(dms[0].num) / float(dms[0].den)
    minutes = float(dms[1].num) / float(dms[1].den)
    seconds = float(dms[2].num) / float(dms[2].den)

    decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
    if ref in ['S', 'W']:
        decimal = -decimal
    return decimal

def extract_gps(file_path):
    with open(file_path, 'rb') as f:
        tags = exifread.process_file(f)

    try:
        lat = tags["GPS GPSLatitude"]
        lat_ref = tags["GPS GPSLatitudeRef"].values
        lon = tags["GPS GPSLongitude"]
        lon_ref = tags["GPS GPSLongitudeRef"].values

        latitude = dms_to_decimal(lat.values, lat_ref)
        longitude = dms_to_decimal(lon.values, lon_ref)

        print(f"[+] GPS Coordinates:")
        print(f"    Latitude: {latitude}")
        print(f"    Longitude: {longitude}")
        print("\n[+] Google Maps Link:")
        print(f"    https://www.google.com/maps?q={latitude},{longitude}")

    except KeyError:
        print("[-] GPS metadata not found in the image.")


def find_info(text):
    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
    phones = re.findall(r'\+?\d[\d\s\-\(\)]{8,15}', text)

    print("[*] Emails found:")
    for email in set(emails):
        print(" -", email)

    print("\n[*] Phone numbers found:")
    for phone in set(phones):
        print(" -", phone)

def scan_website(url):
    print(f"[*] Scanning {url} ...")
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            text = soup.get_text()
            find_info(text)
        else:
            print("[-] Error: Website not accessible.")
    except Exception as e:
        print(f"[-] Error: {e}")


#---------------------------------------------------------------------------------

def get_saved_wifi_passwords():
    # เรียกดูโปรไฟล์ Wi-Fi ที่บันทึกไว้
    profiles_output = subprocess.check_output("netsh wlan show profiles", shell=True, text=True)
    profiles = re.findall(r"All User Profile\s*:\s(.*)", profiles_output)

    wifi_passwords = []

    for profile in profiles:
        profile = profile.strip()
        # ดึงรายละเอียดของแต่ละโปรไฟล์
        try:
            profile_info = subprocess.check_output(
                f'netsh wlan show profile "{profile}" key=clear',
                shell=True, text=True
            )
            # หา key (password)
            password = re.search(r"Key Content\s*:\s(.*)", profile_info)
            if password:
                wifi_passwords.append((profile, password.group(1)))
            else:
                wifi_passwords.append((profile, "No password set"))
        except subprocess.CalledProcessError:
            wifi_passwords.append((profile, "Cannot access profile"))

    return wifi_passwords
#====================================================================================



#========================    Local Area Network (LAN) Info    =======================#


def get_all_network_info():
    addrs = psutil.net_if_addrs()
    try:
        for interface, addr_list in addrs.items():
            for addr in addr_list:
                if addr.family.name == 'AF_INET':  # IPv4
                    print(f"Interface: {interface} | IP: {addr.address}")
    except OSError as e:
        print(f"Error: {e}")
        time.sleep(2)

        
#====================================================================================



#========================    Main Functionality    =======================#
def wifi_lan():
    if __name__ == "__main__":
        selct = input("Do you want to see Wifi or Lan (w/l): ").strip().lower()
        print()

        # lan info
        if selct == "l":
            get_all_network_info()
            print()
            
        # wifi info
        elif selct == "w":
            passwords = get_saved_wifi_passwords()
            for wifi, password in passwords:
                print(f"Wi-Fi: {wifi} | Password: {password}")
                print()
        else:
            print("Invalid selection. Please choose 'w' for Wi-Fi or 'l' for LAN.")
    pass

def download_for_mobile():
    print("Do you install module yet?")
    while True:
        down_or_not = str(input("\nDo you want to Downloads module for the first time you run?\nY/N: "))
        if down_or_not == "Y" or down_or_not == "y":
            print("Okay.. let install")
            install()
            print("YES you install all module in my tool youre good boy")
            time.sleep(3)
            print(f"Have a good time..")
            time.sleep(5)
            break

        elif down_or_not == "N" or down_or_not == "n" or down_or_not == "No" or down_or_not == "NO":
            print("Okay..")
            time.sleep(2)
            break
                

        else:
            print("WTF is this "+ down_or_not)
            pass

def clear_terminal():
    import os
    os.system('cls' if os.name == 'nt' else 'clear')


banner_for_install()
download_for_mobile()
clear_terminal()


clear_terminal()
import os
import socket
import time
import exifread
import re
import psutil
import subprocess
from datetime import datetime
import requests
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore, Style
from bs4 import BeautifulSoup
init(autoreset=True)

#clear_terminal()


#=====================================================================

banner()
function_name()
exit()

while True:
    function = input("Select Function: ")  # ใช้ IP จริงหรือ IP เป้าหมาย
    if function == "1":
        ip = input("Pubilc-IP : ")
        ip_info_ip_io = get_ip_info(ip)
        ip_info_whoisxml = get_ip_info_whoixml(ip)  # ใช้ API ของ whoisxmlapi
        ip_info_ip_api = get_ip_info(ip)
        ip_info_ip_stack = get_ip_info(ip)
        print("\nData form > ipinfo.io")
        try:
            print(f'''---------------------------
IP Information
IP       : {ip_info_ip_io['ip']}
Location : {ip_info_ip_io['city']}, {ip_info_ip_io['country']}
Org      : {ip_info_ip_io['org']}
Hostname : {ip_info_ip_io['hostname']}
            ''')
        except Exception as e:
            print(f"Error: {e}")
            pass

        #location = ip_info_whoisxml['country'][0]
        #warning = test_result['warnings'][0]
        print("\nData form > whoisxmlapi.com")
        try:
            print(f'''---------------------------   
IP Address      : {ip_info_whoisxml['ip']}
ISP             : {ip_info_whoisxml['isp']}
Connection Type : {ip_info_whoisxml['connectionType']}

Location:
  Country        : {ip_info_whoisxml['location']['country']}
  Region         : {ip_info_whoisxml['location']['region']}
  City           : {ip_info_whoisxml['location']['city']}
  Latitude       : {ip_info_whoisxml['location']['lat']}
  Longitude      : {ip_info_whoisxml['location']['lng']}
  Timezone       : {ip_info_whoisxml['location']['timezone']}
  Geoname ID     : {ip_info_whoisxml['location']['geonameId']}

AS Information:
  ASN            : {ip_info_whoisxml['as']['asn']}
  Name           : {ip_info_whoisxml['as']['name']}
  Route          : {ip_info_whoisxml['as']['route']}
            ''')
        except Exception as e:
            print(f"Error: {e}")
            pass
        
        print("\nData form > ip-api.com")
        try:
            print(f"""
---------------------------
IP Address     : {ip_info_ip_api['ip']}
Hostname       : {ip_info_ip_api['hostname']}
City           : {ip_info_ip_api['city']}
Region         : {ip_info_ip_api['region']}
Country        : {ip_info_ip_api['country']}
Location (Lat,Lon) : {ip_info_ip_api['loc']}
Postal Code    : {ip_info_ip_api['postal']}
Timezone       : {ip_info_ip_api['timezone']}
ISP / Org      : {ip_info_ip_api['org']}

For more info: {ip_info_ip_api['readme']}
            """)
        except Exception as e:
            print(f"Error: {e}")
            pass
        
        print("---------------------------")
        print("Data form > ipstack.com")
        print(ip_info_ip_stack)






    elif function == "2":
        email = input("Email: ")
        email_info = email_verification(email)
        try:
            print(f"FormatCheck: {email_info['formatCheck']}")
            print(f"SMTPCheck: {email_info['smtpCheck']}")
            print(f"DNSCheck: {email_info['dnsCheck']}")
        except KeyError:
            print("Invalid email format or API error.")
            exit()
        print(f"\nFree Email Checking")
        print(f"FreeCheck: {email_info['freeCheck']}")

        print("\nDisposable Email Checking")
        print(f"DisposableCheck: {email_info['disposableCheck']}")

        print(f'''
Email Information
Username        : {email_info['username']}
Domain          : {email_info['domain']}
Email Address   : {email_info['emailAddress']}
Catch-All Check : {email_info['catchAllCheck']}
MX Records      : {', '.join(email_info['mxRecords'])}

Audit Info
Created Date    : {email_info['audit']['auditCreatedDate']}
Updated Date    : {email_info['audit']['auditUpdatedDate']}
        ''')

    elif function == "3":
        domain = input("Domain: ")
        domain_info = domain_reputation(domain)

        # ดึง testResults ตัวแรกออกมา (เป็น list)
        test_result = domain_info['testResults'][0]
        warning = test_result['warnings'][0]

        print(f"""
Domain Reputation Report:
Mode             : {domain_info['mode']}
Reputation Score : {domain_info['reputationScore']}

Test Details
   • Test       : {test_result['test']}
   • Test Code  : {test_result['testCode']}

Warning
   • Description : {warning['warningDescription']}
   • Code        : {warning['warningCode']}
        """)

    elif function == "4":
        domain = input("Domain: ")
        ip_for_reverse_ip_lookup = socket.gethostbyname(domain)
        try:
            ip = socket.gethostbyname(domain)
            print(f"IP of {domain} is {ip_for_reverse_ip_lookup}")
        except socket.gaierror:
            print(f"Could not find IP of {domain}. Check if the domain is valid or connected to the internet.")

        ip = input("\nIP Address: ")
        reverse_ip_info = reverse_ip_lookup(ip)
        if isinstance(reverse_ip_info, list):
            # ถ้าเป็น list โดยตรงให้ใช้ข้อมูลจาก list นี้เลย
            records = reverse_ip_info  # ใช้ข้อมูลใน list ทั้งหมด
            count = len(records)  # นับจำนวนรายการทั้งหมด
            search_ip = "N/A"  # ตั้งค่า IP ที่ใช้ค้นหา

        else:
            # ถ้าเป็น dictionary (กรณีที่มี structure ตามปกติ)
            records = reverse_ip_info.get("result", {}).get("records", [])
            count = reverse_ip_info.get("result", {}).get("count", 0)
            search_ip = reverse_ip_info.get("search", "N/A")

        if records:
            print(f"""
        ===========================
        Reverse IP Lookup Results
        ===========================
        Target IP        : {search_ip}
        Total Domains    : {count}

        Top Record:
        ---------------------------
        Domain Name      : {records[0].get("domainName", "N/A")}
        First Seen       : {records[0].get("firstSeen", "N/A")}
        Last Seen        : {records[0].get("lastSeen", "N/A")}
        Still Resolving? : {records[0].get("currentDns", False)}
        ---------------------------

        All Records:
        ---------------------------""")

            for idx, rec in enumerate(records, start=1):
                print(f"""{idx}. {rec.get("domainName", "N/A")}
            ├─ First Seen : {rec.get("firstSeen", "N/A")}
            ├─ Last Seen  : {rec.get("lastSeen", "N/A")}
            └─ Active     : {rec.get("currentDns", False)}
        """)

        else:
            print(f"""
        ===========================
        Reverse IP Lookup Results
        ===========================
        Target IP        : {search_ip}
        ผลลัพธ์: ไม่พบโดเมนใดที่เคยชี้มายัง IP นี้
        """)

    elif function == "5":
        domain = input("Domain: ")
        subdomain_info = subdomain_lookup(domain)

        records = subdomain_info.get("result", {}).get("records", [])

        if records:
            first = records[0]
            print(f"""
        Subdomain Search Results:
        ---------------------------
        Search Query: {subdomain_info.get('search', 'N/A')}
        Total Records Found: {subdomain_info['result'].get('count', 'N/A')}

        Record Details:
        ---------------------------
        Domain: {first.get('domain', 'N/A')}
        First Seen: {first.get('firstSeen', 'N/A')}
        Last Seen: {first.get('lastSeen', 'N/A')}

        Timestamp (First Seen): {first.get('firstSeen', 'N/A')}
        Timestamp (Last Seen): {first.get('lastSeen', 'N/A')}
        ---------------------------
        """)
        else:
            print("There are no subdomains for this domain.")

    elif function == "6":
        phone_number = input("Phone Number: ")
        phone_number_lookup_apilayer(phone_number)
        print("---------------------------")
        phone_number_lookup_abstractAPI(phone_number)

    elif function == "7":
         # รับชื่อผู้ใช้หลายๆ ชื่อจากผู้ใช้
        usernames_input = input("Enter usernames separated by commas: ").strip()
        usernames = [username.strip() for username in usernames_input.split(',')]
    
    
        if not usernames_input:
            print("Please enter a valid username.")
        elif not all(is_valid_username(username) for username in usernames):
            print("Invalid username, it may contain spaces or invalid characters.")
        else:
            # ตรวจสอบชื่อผู้ใช้หลายชื่อ
            results = check_multiple_usernames(usernames)
            #
            # แสดงผลลัพธ์
            print("" + "\n".join(results))
            print("\n---------------------------")
            # บันทึกผลลัพธ์ลงไฟล์
            want_to_save = input("Do you want to save the results to a file? (y/n): ").strip().lower()
            if want_to_save == 'y' or want_to_save == 'yes' or want_to_save == 'Y' or want_to_save == 'Yes':
                
                # สร้างชื่อไฟล์ที่ไม่ซ้ำกันโดยใช้ timestamp
                timestamp = time.strftime("%Y%m%d-%H%M%S")
                filename = f"Usernames_saves/{usernames_input}_results_{timestamp}.txt"
                if not os.path.exists("Usernames_saves"):
                    os.makedirs("Usernames_saves")  # สร้างโฟลเดอร์ 'Data' หากไม่มี

                with open(filename, "w", encoding="utf-8") as f:
                    # เขียนผลลัพธ์ลงในไฟล์ (แต่ละชื่อผู้ใช้ในบรรทัดใหม่)
                    f.write("\n".join(results))
    
                print(f"\nResults saved to file: {filename}")

            elif want_to_save == 'n' or want_to_save == 'no' or want_to_save == 'N' or want_to_save == 'No':
                print("Results not saved.")

            else:
                pass

    elif function == "8":
        email = input("Email: ")
        print("---------------------------")
        email_leak_lookup(email)

    elif function == "9":
        file_path = input("Enter the path to the file: ")
        extract_gps(file_path)

    elif function == "11":
        wifi_lan()




    elif function == "10":
        target_url = input("Enter url: ")
        scan_website(target_url)
    elif function == "links" or function == "links" or function == "l":
        print("""
ชื่อเว็บไซต์	                ทำอะไรได้
Maigret	                    ตรวจ username ว่าใช้งานเว็บไหนบ้าง
Namechk	                    ตรวจสอบชื่อผู้ใช้ว่าใช้เว็บไหน
WhatsMyName	OSINT tool      ตรวจ username
Sherlock	                ตรวจ username ทั่วเว็บ (300+ เว็บ)
Spokeo	                    ค้นข้อมูลคนจากชื่อ/อีเมล/เบอร์
Social Searcher	            ค้นโพสต์และโปรไฟล์จากคำ
Hunter.io	                ค้นอีเมลจากชื่อโดเมน/โปรไฟล์ LinkedIn
Pipl	                    ค้นข้อมูลบุคคลจากชื่อ/อีเมล/เบอร์
PeekYou	                    หาโปรไฟล์โซเชียลจากชื่อหรือชื่อผู้ใช้
SocialLinks	OSINT           ระดับสูง (มี demo)
              

Website Name	                What It Does
Maigret	                        Checks where a username is used across many websites
Namechk	                        Checks username availability across social platforms
WhatsMyName	OSINT tool          to look up usernames across multiple sites
Sherlock	                    Searches a username across 300+ websites
Spokeo	                        Finds personal info from name, email, or phone number
Social Searcher	                Finds posts and profiles based on keywords
Hunter.io	                    Finds email addresses from domain names or LinkedIn profiles
Pipl	                        Searches personal data from name, email, or phone number
PeekYou	                        Finds social media profiles from name or username
SocialLinks	                    High-level OSINT platform (demo available)
Website Name	                What It Does

Maigret                         https://namechk.com/
Namechk                         https://github.com/soxoj/maigret
WhatsMyName	OSINT tool          https://www.namechk.com/
Sherlock                        https://github.com/sherlock-project/sherlock
Spokeo                          https://www.spokeo.com/
Social Searcher                 https://www.social-searcher.com/
Hunter.io                       https://www.hunter.io/
Pipl                            https://pipl.com/
PeekYou                         https://www.peekyou.com/
SocialLinks                     https://sociallinks.io/  
    """)


    elif function == "WIFI" or function == "wifi":
        print("""
        Liknks
        
ชื่อเว็ปไซต์

www.WiFimap.io
wifispc.com
wigle.net
        """)
        wifi = input("Select Function: ")
        if wifi == "1":
            print("Wifi Lookup 1")
            # Add your code for Wifi Lookup 1 here
        elif wifi == "2":
            print("Wifi Lookup 2")
            # Add your code for Wifi Lookup 2 here
        elif wifi == "3":
            print("Wifi Lookup 3")
            # Add your code for Wifi Lookup 3 here
        elif wifi == "4":
            print("Wifi Lookup 4")
            # Add your code for Wifi Lookup 4 here
        elif wifi == "5":
            print("Wifi Lookup 5")
            # Add your code for Wifi Lookup 5 here
        else:
            print("Invalid function selected.")
    elif function == "0" or function == "exit" or function == "Exit":
        print("Exiting...")
        break
    elif function.lower() == "h" or function.lower() == "help" or function.lower() == "H" or function.lower() == "Help" or function.lower() == "?":
        banner()
        function_name()
        exit()


    else:
        print("Invalid function selected.")
    
