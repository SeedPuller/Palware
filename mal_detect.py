#!/usr/bin/python3
# ver 2.2.1
import subprocess
import re
import os
import time
import logging
import sys
import getopt
import smtplib
import urllib.parse
logging.basicConfig(filename="/var/log/palware/maldetect.log", level=logging.INFO)

# regex patterns start

alfa = r"(alfa[_[a-z]+)|(_+z[a-zA-z0-9]+cg\()"

#base64 = r"(base64_[a-z]+\()"  # disabled

#safe_mode = r"(safe_mode)" disabled

ini_pro = r"(ini_[s]*[g]*[et]*[a-z]*\()"

eval_pro = r"(eval\()"

executions = r"([a-z]*[_]*exe[c]*\()|(system\()|([a-z]*passthru\()"

php_uname = r"(php_uname\()"

fupload = r"(copy\()|(move_uploaded_file\()"

uploadForm = r"(<form [\s\S]* enctype=[\S\s]*multipart\/form-data)|(<input [\s\S]*type=[\s\S]*file)"

symlink = r"(sym[link]+)"

filefunc = r"(chmod\()|(unlink\()|(rmdir\()|(rename\()"

defacement = r"(hacked)|(bypassed)"

otherScripts = r"(#![\/a-zA-z0-9]*bin\/[a-zA-z0-9]*)"

formatallow = [".php", ".jpg", ".png", ".gif", ".mp4", ".html", ".htm", ".jpeg", ".txt", ".css", ".psd", ".sql", ".zip", ".js", ".doc", ".mo", ".po", ".ttf", ".pdf", ".eot", ".xml", ".svg", ".woff", ".dist", ".ini", ".sys.ini", ".min.js", ".json", ".swf", ".xap", ".less", ".ico", ".otf"]

editAbleF = [".php"]

phpscript = r"(<\?php[\s\S]*?>)"

malicious_coding = r"(\$[a-z-A-Z0-9_]+\()|(create_function\()"


# regex patterns end

# Vars
internal = False
directory = ""
email = False
mal_move_dest = ""
sqlxss = False
nowtime = time.asctime(time.localtime(time.time()))
mal_execpt = []
rootdir = ""
reaload = 0
iplistpath = "/etc/apache2/palwareconf/iplist.conf"
filechangelogpath = "/var/log/palware/filechangelog.txt"
postlog = "/var/log/palware/post.log"
getlog = "/var/log/palware/apache2.log"
posts = False
# functions

def banip(ip):
    global reaload, iplistpath
    ipsban = "Require not ip " + ip
    ipsread = open(iplistpath, "r").read()
    open(iplistpath, "w").write(ipsread + "\n{0}".format(ipsban))
    alert("Ip : {0} Has been banned !".format(ip))
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
    # malicious commands
    cwdre = r"(cwd=[\s]*[\S]+\")"
    malre = r"(passwd|uname)"

    for command in listlog:
        if regex(r"\b(uid=0)", command, False):
            continue
        if regex(malre, command,False):
            cwd = regex(cwdre, command, False,1)
            alert("[!] Malicious bash command executed on : {0}".format(cwd))
    open("/var/log/audit/audit.log","w").write("")


def scan():  # check file changing and scan every file changes like edit , creat and etc.
    global mal_execpt, filechangelogpath
    filechngeread = open(filechangelogpath, "r").readlines()
    if len(filechngeread) > 0:
        for change in filechngeread:
            splitchange = change.split()
            if len(splitchange) > 0:
                cwd, event, filename = splitchange
                checkfile("{0}/{1}".format(cwd, filename))
            else:
                alert("Split error !")
                sys.exit()
        open(filechangelogpath, "w").write("")
        mal_execpt = []


def runinotify(directory):
    global filechangelogpath
    if not bashexec("sudo inotifywait {0} -d -r -e moved_to,close_write,attrib -o {1}".format(directory, filechangelogpath)):
        logging.info("!!! infowait starting Error !!!")
        sys.exit(1)
    return True


def send_mail(user, pasw, destination, subject, msg):  # sendig mail
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


def regex(pattern,code,whitelist, ret=None):
    # check a regex with a exeption
    if(whitelist):
        return False
    if(re.search(pattern,code,re.IGNORECASE) != None):
        if ret != None:
            return re.search(pattern,code,re.IGNORECASE).group(0)
        return True
    else:
        return False


def sqlxsscheck(post):
    global nowtime, rootdir
    apachelog = open(getlog, "r").readlines()
    if len(apachelog) > 0:
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
                if regex(datare, plog, False) is None:
                    pass
                else:
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


def alert(text):
    global email
    if email:
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
    global alfa, ini_pro, eval_pro, executions, php_uname, fupload, weevely, defacement, otherScripts, phpscript, base64, symlink, filefunc, malicious_coding
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
            if regex(alfa, code, False):
                malwares[item] = "ALFA-SHELL"
            elif regex(ini_pro, code, False):
                malwares[item] = "INI-PROCCESS"
            elif regex(eval_pro, code, False):
                malwares[item] = "EVAL-PROCCES"
            elif regex(executions, code, False):
                malwares[item] = "COMMAND-EXECUTION"
            elif regex(php_uname, code, False):
                malwares[item] = "UNSAFE-FUNC"
            elif regex(fupload, code, False):
                malwares[item] = "UPLOAD-FUNC"
            elif regex(defacement, code, False):
                malwares[item] = "DEFACE"
            elif regex(php_uname, code, False):
                malwares[item] = "PHP_UNAME"
            # elif(regex(base64,code,False) != False):
            #    malwares[item] = "BASE64"
            elif regex(uploadForm, code, False):
                malwares[item] = "UPLOAD-FORM"
            elif regex(symlink, code, False):
                malwares[item] = "SYMLINK"
            elif regex(filefunc, code, False):
                malwares[item] = "FILE-MANAGE-FUNC"
            elif regex(malicious_coding, code, False):
                malwares[item] = "MALICIOUS-CODING"
            elif regex(otherScripts, code, False):
                malwares[item] = "SCRIPTING"
            # elif hard and regex(weevely, code, False):
            #     malwares[item] = "WEEVELY"

            check.close()
        else:
            check = open(item, "r", errors="ignore")
            code = check.read()
            if regex(phpscript, code, False):
                malwares[item] = "PHP-IN-OTHER-FORMAT"
            elif regex(defacement, code, False):
                malwares[item] = "DEFACE-IN-OTHER-FORMAT"
            check.close()
    else:
        malwares[item] = "FORMAT"

    for malware,reason in malwares.items():
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
    opts, args = getopt.gnu_getopt(sys.argv[1:], 'd:E:m:M:a:p:s', ['directory=',"email=", "maldo=", "mal-move-dest=", "attack-do=", "post", "sqlxss",])
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
        alert(" \n ==== \n" + nowtime + "- Started With These Args : \n directory : " + directory + "\n Do-with-malwares : " + maldo + "\n malware-move-dest :" + mal_move_dest + "\n === \n ")
        runinotify(directory)
    if reaload == 1:
        if str(num/10).split(".")[1] == "0":
            bashexec("sudo service apache2 reload")
            reaload = 0
    scan()
    command_execute()
    if sqlxss:
        sqlxsscheck(posts)
    time.sleep(1)
    num += 1
