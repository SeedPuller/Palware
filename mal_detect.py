#!/usr/bin/python3
# ver 1.5
import subprocess
import re
import os
import time
import logging
import sys
import getopt
import smtplib
logging.basicConfig(filename="maldetect.log", level=logging.INFO)

# regex patterns start

alfa = r"(alfa[_[a-z]+)|(_+z[a-zA-z0-9]+cg\()"

base64 = r"(base64_[a-z]+\()"  # disabled

#safe_mode = r"(safe_mode)" disabled

ini_pro = r"(ini_[s]*[g]*[et]*[a-z]*\()"

eval_pro = r"(eval\()"

executions = r"([a-z]*[_]*exe[c]*\()|(system\()|([a-z]*passthru\()"

php_uname = r"(php_uname\()"

fupload = r"(copy\()|(move_uploaded_file\()"

uploadForm = r"(<form [\s\S]* enctype=[\S\s]*multipart\/form-data)|(<input [\s\S]*type=[\s\S]*file)"

symlink = r"(sym[link]+)"

filefunc = r"(chmod\()|(unlink\()|(rmdir\()|(rename\()"

weevely = r"([b][a-zA-z0-9_\-|{}!%\^&@\*+]*[d]*[e]{1}\()" # disabled

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
Ereceiver = []
mailA = ""
mailP = ""
maldo = ""
mal_move_dest = ""
mal_execption = []

# functions


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

def command_execute():
    global email, mailA, mailP, Ereceiver
    commands_log = bashoutput("sudo ausearch -m EXECVE -ts {0}/{1}/{2} | grep 'type=EXECVE' ".format(nowtime[1],nowtime[2],nowtime[0]))
    listlog = commands_log.split("----")
    cwdre = r"(cwd=[\s]*[\S]+\")"
    malre = r"(passwd|uname)"
    for command in listlog:
        if regex(r"\b(uid=0)", command, False):
            continue
        if regex(malre, command,False):
            cwd = regex(cwdre, command, False,1)
            logging.info("[!] Malicious bash command executed on : {0}".format(cwd))
            if email:
                nowtime = time.asctime(time.localtime(time.time()))
                send_mail(mailA, mailP, Ereceiver,"[!] {0} - Malicious bash command executed on : {1}".format(nowtime, cwd))
    open("/var/log/audit/audit.log","w").write("")


def scan(directory):
    if not bashexec("sudo inotifywait /var/www/html/ -d -r -e moved_to,close_write,attrib -o filechangelog.txt"):
        logging.info("!!! infowait starting Error !!!")
        sys.exit(1)
    filechngeread = open("/filechangelog.txt", "r").readlines()
    if len(filechngeread) > 0:
        for change in filechngeread:
            cwd, event, filename = change.split()
            checkfile("{0}/{1}".format(cwd, filename))
        filechngeopen = open("/filechangelog.txt","w").write("")

def send_mail(user, pasw, destination, subject, msg):
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



def checkfile(dirs):
    # check files for malwares
    if dirs == "":
        print("No directory defined")
        sys.exit()
    global formatallow, editAbleF
    global alfa, ini_pro, eval_pro, executions, php_uname, fupload, weevely, defacement, otherScripts, phpscript, base64, symlink, filefunc, malicious_coding
    global email, mailA, mailP, Ereceiver
    global maldo, mal_move_dest
    # detected malware names ...
    malwares = {}

    files = [dirs]

    for item in files:
        if os.path.isfile(item):
            # check exceptions and white lists


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
        nowtime = time.asctime(time.localtime(time.time()))
        if maldo == "move":
            fname = os.path.basename(malware)
            os.rename(malware, "{0}/{1}".format(mal_move_dest, fname))
            logging.info("{0} - {1} Has Been Detected for ' {2} ' \n ".format(nowtime, malware, reason))
        else:
            if malware not in mal_execption:
                logging.info("{0} - {1} Has Been Detected for ' {2} ' \n ".format(nowtime, malware, reason))
                if email:
                    send_mail(mailA, mailP, Ereceiver, "Malware Detected !", "{0} - {1} Has Been Detected for ' {2} ' \n ".format(nowtime, malware, reason))
                mal_execption.append(malware)

# handling arguments

try:
    opts, args = getopt.gnu_getopt(sys.argv[1:], 'd:E:g:p:r:m:M', ['directory=',"email", "gmailA=", "gmailp", "receiver", "maldo", "mal-move-dest",])
except getopt.GetoptError as e:
    print(e)
    sys.exit(2)

for opt, arg in opts:
    if opt in ('-d', '--directory'):
        directory = arg
        if not os.path.exists(directory):
            logging.info("\n ### No such directory !!!!! script killed ! - '{0}' ###  \n".format(directory))
            sys.exit()
    elif opt in ('-i', '--internal-check'):
        internal = True
    elif opt in ('-E', '--email'):
        email = True
    elif opt in ('-g', '--gmailA'):
        mailA = arg
    elif opt in ('-p', '--gmailp'):
        mailP = arg
    elif opt in ('-r', '--receiver'):
        arg = arg.split(",")
        for cArg in arg:
            Ereceiver.append(cArg)
    elif opt in ("-m", "--maldo"):
        maldo = arg
    elif opt in ("-M", "--mal-move-dest"):
        mal_move_dest = arg
    else:
        print("ERR")
        sys.exit(2)

num = 0
while True:  # run scanning function until the world exists !
    if num < 1:
        pass
        nowtime = time.asctime(time.localtime(time.time()))  # get now date and time for log just for first start
        logging.info(" \n ==== \n" + nowtime + "- Started With These Args : \n directory : " + directory + "\n Do-with-malwares : " + maldo + "\n malware-move-dest :" + mal_move_dest + "\n === \n ")
    scan(directory)
    command_execute()
    time.sleep(1)
    num += 1
