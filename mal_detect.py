#!/usr/bin/python3
# ver 2.3.1
import subprocess
import re
import os
import time
import logging
import sys
import getopt
import smtplib
import urllib.parse
import platform
logging.basicConfig(filename="/var/log/palware/maldetect.log", level=logging.INFO)

# regex patterns start

REGEXES = {"ALFA-SHELL": r"(alfa[_[a-z]+)|(_+z[a-zA-z0-9]+cg\()",
           "INI-PROCESS": r"(ini_[s]*[g]*[et]*[a-z]*\()",
           "EVAL-PROCCES": r"(eval\()",
           "COMMAND-EXECUTION": r"([a-z]*[_]*exe[c]*\()|(system\()|([a-z]*passthru\()",
           "SUSPICIOUS-FUNC": r"(php_uname\()",
           "UPLOAD": r"(copy\()|(move_uploaded_file\()",
           "UPLOAD-FORM": r"(<form [\s\S]* enctype=[\S\s]*multipart\/form-data)|(<input [\s\S]*type=[\s\S]*file)",
           "SYMLINK": r"(sym[link]+)",
           "FILE-MANAGING-FUNC": r"(chmod\()|(unlink\()|(rmdir\()|(rename\()",
           "DEFACEMENT": r"(hacked)|(bypassed)",
           "SCRIPT-SIMILAR": r"(#![\/a-zA-z0-9]*bin\/[a-zA-z0-9]*)",
           "PHP-IN-OTHER-FORMAT": r"(<\?php[\s\S]*?>)",
           "MALICIOUS-CODING": r"(\$[a-z-A-Z0-9_]+\()|(create_function\()"
           }

# regex patterns end

# Important Vars start

formatallow = [".php", ".jpg", ".png", ".gif", ".mp4", ".html", ".htm", ".jpeg", ".txt", ".css", ".psd", ".sql", ".zip", ".js", ".doc", ".mo", ".po", ".ttf", ".pdf", ".eot", ".xml", ".svg", ".woff", ".dist", ".ini", ".sys.ini", ".min.js", ".json", ".swf", ".xap", ".less", ".ico", ".otf"]

editAbleF = [".php"]

platf = platform.platform().lower()

if "ubuntu" in platf:
    apacheconfpath = "/etc/apache2"
    apachename = "apache2"
else:
    apacheconfpath = "/etc/httpd"
    apachename = "httpd"

internal = False
directory = ""
email = False
mal_move_dest = ""
sqlxss = False
nowtime = time.asctime(time.localtime(time.time()))
mal_execpt = []
rootdir = ""
reaload = 0
iplistpath = "{0}/palwareconf/iplist.conf".format(apacheconfpath)
filechangelogpath = "/var/log/palware/filechangelog.txt"
postlog = "/var/log/palware/post.log"
getlog = "/var/log/palware/apache2.log"
posts = False

# Important Vars end

# functions start


def banip(ip):                     # Ban a ip address from apache configuration
    global reaload, iplistpath
    ipsban = "Require not ip " + ip
    ipsread = open(iplistpath, "r").read() # Banned-ip list
    if ip in ipsread:
        return False
    open(iplistpath, "w").write(ipsread + "\n{0}".format(ipsban))
    alert("Ip : {0} Has been banned !".format(ip), False)
    reaload = 1


def bashoutput(bashc):  # executing bash commands and return that outputs
    basherr = r"(\/bin\/sh: [0-9]*: [a-zA-Z0-9 !@#$%^&*()\[\]{}\-=+<>\/?.,:;'\"\\|_]*: not found)"
    bash = subprocess.getoutput(bashc)
    if re.search(basherr, bash, re.IGNORECASE):  # check error existence
        return False
    else:
        return bash


def bashexec(command):  # executing bash commands and Do Not return that outputs
    process = subprocess.getstatusoutput(command)
    if process[0] == 0:
        return True
    else:
        return False


def command_execute():  # check for malicious executed command and alert them
    global email, mailA, mailP, Ereceiver, nowtime
    commands_log = bashoutput("sudo ausearch -m EXECVE -ts {0}/{1}/{2} | grep 'type=EXECVE' ".format(nowtime[1],nowtime[2],nowtime[0]))
    listlog = commands_log.split("----")
    # malicious commands start
    cwdre = r"(cwd=[\s]*[\S]+\")"
    malre = r"(passwd|uname)"
    # malicious commands end
    for command in listlog:
        if regex(r"\b(uid=0)", command, False): # Root user is permitted to do anything
            continue
        if regex(malre, command,False): # Check for malicious command
            cwd = regex(cwdre, command, False, 1)
            alert("[!] Malicious bash command executed on : {0}".format(cwd))
    open("/var/log/audit/audit.log","w").write("")


def scan():  # check file changing and scan every file events like editing , creating and etc.
    global mal_execpt, filechangelogpath
    filechngeread = open(filechangelogpath, "r").readlines()
    if len(filechngeread) > 0:
        for change in filechngeread:
            scancwd = change[0:(len(change)) - (change[::-1].find("/"))]
            file_else = change[(len(change)) - (change[::-1].find("/") - 1):]
            num3 = 0
            scanname = ""
            for val in file_else.split()[1:]:
                if num3 == 0:
                    scanname = val
                else:
                    scanname = scanname + " {0}".format(val)
                num3 += 1

        checkfile("{0}{1}".format(scancwd, scanname))

        open(filechangelogpath, "w").write("")
        mal_execpt = []


def runinotify(directory): # run inotify tools with some parameters
    global filechangelogpath
    if not bashexec("sudo inotifywait {0} -d -r -e moved_to,close_write,attrib -o {1}".format(directory, filechangelogpath)):
        logging.info("!!! infowait starting Error !!!")
        sys.exit(1)
    return True


def send_mail(user, pasw, destination, subject, msg):  # sending Emails for alert
    if type(destination) is not list:
        destination = [destination]
        destination = ', '.join(destination)
    else:
        destination = ', '.join(destination)
    message = "From: {0}\n To: {1} \n Subject: {2} \n\n {3}".format(user, destination, subject, msg)
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.ehlo()
        server.starttls()
        server.login(user, pasw)
        server.sendmail(user, destination, message)
        server.close()
        return True
    except:
        return False


def regex(pattern,code,whitelist, ret=None, ignore=1):
    # check a regex with a exception
    if whitelist:
        return False
    if ignore == 1:
        if re.search(pattern, code, re.IGNORECASE) != None:
            if ret != None:
                return re.search(pattern, code, re.IGNORECASE).group(0)
            return True
        else:
            return False
    else:
        if re.search(pattern, code) != None:
            if ret is not None:
                return re.search(pattern, code).group(0)
            return True
        else:
            return False


def sqlxsscheck(post):  # Checking POST and GET requests for SQLI or XSS attacks
    global nowtime, rootdir
    apachelog = open(getlog, "r").readlines()  # read GET requests log
    if len(apachelog) > 0:
        # sqli and xss regexes

        xssre = r"(<[\s\S]*>)"
        sqlorderre = r"([order]*[group]*[+ ]*by[+ ]*[\d]*[-\#]*)"
        sqlunionre = r"(union[\s\S]*[+]*[all]*select)"
        urlre = r"(\"[GET POST]+ [\s\S]* HTTP)"
        att_execpt = []
        for log in apachelog:
            log = urllib.parse.unquote(log)
            ip = log.split("-")[0]
            if re.match(urlre, log, re.IGNORECASE) is not None:
                url = re.match(urlre, log, re.IGNORECASE)
            else:
                url = ""
            if regex(xssre, log, False):
                if url not in att_execpt:
                    alert("{0} - XSS testing found  ! \n info(s) :  {1}".format(nowtime, log))
                    if rootdir != "":
                        banip(ip)
                    att_execpt.append(url)
            elif regex(sqlorderre, log, False):
                if url not in att_execpt:
                    alert("{0} - SQLI testing found  ! \n info(s) :  {1}".format(nowtime, log))
                    if rootdir != "":
                        banip(ip)
                    att_execpt.append(url)
            elif regex(sqlunionre, log, False):
                if url not in att_execpt:
                    alert("{0} - SQLI testing found  ! \n info(s) :  {1}".format(nowtime, log))
                    if rootdir != "":
                        banip(ip)
                    att_execpt.append(url)
        open(getlog, "w").write("")
        if post:
            apachepostlog = open(postlog, "r").readlines()
            open(postlog, "w").write("")
            datare = r"(data-HEAP\): [a-z0-9]*=)"
            sqliorre = r"(\'[\);+ ]*or[\'\"]*[+ ]*[\'a-z0-9=\"]*)"
            for plog in apachepostlog:
                plog = urllib.parse.unquote(plog)
                if regex(datare, plog, False):
                    ip = plog[0:127].split()[10].replace("]", "").split(":")[0]
                    if regex(xssre, plog, False):
                        if url not in att_execpt:
                            alert("{0} - XSS testing found  ! \n info(s) :  {1}".format(nowtime, plog))
                            if rootdir != "":
                                banip(ip)
                    elif regex(sqlorderre, plog, False):
                        if url not in att_execpt:
                            alert("{0} - SQLI testing found  ! \n info(s) :  {1}".format(nowtime, plog))
                            if rootdir != "":
                                banip(ip)
                    elif regex(sqlunionre, plog, False):
                        if url not in att_execpt:
                            alert("{0} - SQLI testing found  ! \n info(s) :  {1}".format(nowtime, plog))
                            if rootdir != "":
                                banip(ip)
                    elif regex(sqliorre, plog, False):
                        if url not in att_execpt:
                            alert("{0} - SQLI testing found  ! \n info(s) :  {1}".format(nowtime, plog))
                            if rootdir != "":
                                banip(ip)


def alert(text, smail=True):
    global email
    if email and smail:
        emailinf = open("inc/mail.txt", "r").readlines()
        userpass = emailinf[0].split(":")
        emuser = userpass[0]
        empass = userpass[1].replace("\n", "")
        destinations = []
        for dest in emailinf[1].split(","):
            destinations.append(dest)
        send_mail(emuser, empass, destinations, "Threat found", text)
    logging.info(text)


def checkfile(item):
    global mal_execpt
    # check files for malwares
    if item == "":
        print("No directory defined")
        sys.exit()
    if item in mal_execpt:
        return False
    global formatallow, editAbleF
    global REGEXES
    global email
    global maldo, mal_move_dest
    global nowtime
    # detected malware names ...
    malwares = {}

    # file infos - format
    file_info = os.path.splitext(item)
    fformat = file_info[1].lower()
    if fformat in formatallow:
        if fformat in editAbleF:

            # open files and check regexes

            check = open(item, "r", errors="ignore")
            code = check.read()
            for reasons, reg in REGEXES.items():
                if regex(reg, code, False):
                    malwares[item] = reasons
            check.close()
        else:
            check = open(item, "r", errors="ignore")
            code = check.read()
            if regex(REGEXES["PHP-IN-OTHER-FORMAT"], code, False):
                malwares[item] = "PHP-IN-OTHER-FORMAT"
            elif regex(REGEXES["DEFACEMENT"], code, False):
                malwares[item] = "DEFACE-IN-OTHER-FORMAT"
            check.close()
    else:
        malwares[item] = "ILLEGAL-FORMAT"

    for malware, reason in malwares.items():
        if maldo == "move":
            fname = os.path.basename(malware)
            os.rename(malware, "{0}/{1}".format(mal_move_dest, fname))
            alert("{0} - {1} Has Been Detected for ' {2} ' \n ".format(nowtime, malware, reason))
            mal_execpt.append(malware)
        else:
            alert("{0} - {1} Has Been Detected for ' {2} ' \n ".format(nowtime, malware, reason))
            mal_execpt.append(malware)

# handling arguments

try:
    opts, args = getopt.gnu_getopt(sys.argv[1:], 'd:E:m:M:a:p:s', ['directory=', "email=", "maldo=", "mal-move-dest=", "attack-do=", "post", "sqlxss", ])
except getopt.GetoptError as e:
    print(e)
    sys.exit(2)

for opt, arg in opts:
    if opt in ('-d', '--directory'):
        directory = arg
        if not os.path.exists(directory):
            alert("\n ### No such directory !!!!! script killed ! - '{0}' ###  \n".format(directory))
            sys.exit()
    elif opt in ('-E', '--email'):
        email = True
    elif opt in ("-m", "--maldo"):
        maldo = arg
    elif opt in ("-M", "--mal-move-dest"):
        mal_move_dest = arg
    elif opt in ('-s', '--sqlxss'):
        sqlxss = True
    elif opt in ('-a', '--attack-do'):
        rootdir = arg
    elif opt in ('-p', '--post'):
        posts = arg
    else:
        print("ERR")
        sys.exit(2)

num = 0
while True:  # run scanning functions until the world exists !
    if num < 1:
        nowtime = time.asctime(time.localtime(time.time()))  # get now date and time for log just for first start
        alert(" \n ==== \n" + nowtime + "- Palware Started Successfully \n === \n ", False)
        if directory != "":
            runinotify(directory)
    if reaload == 1:
        if str(num/10).split(".")[1] == "0":
            bashexec("sudo service {0} reload".format(apachename))
            reaload = 0
    if directory != "":
        scan()
    command_execute()
    if sqlxss:
        sqlxsscheck(posts)
    time.sleep(1)
    num += 1