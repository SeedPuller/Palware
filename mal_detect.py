#!/usr/bin/python3
# ver 1.6
import re
import os
import stat
import time
import logging
import sys
import getopt
import smtplib
logging.basicConfig(filename="maldetect.log", level=logging.INFO)

# regex patterns start

alfa = r"(alfa[_[a-z]+)|(_+z[a-zA-z0-9]+cg\()"

base64 = r"(base64_[a-z]+\()"  # disabled

unsafe_func = r"(ini_[s]*[g]*[et]*[a-z]*\()|(eval\()|([a-z]*[_]*exe[c]*\()|(system\()|(safe_mode)|([a-z]*passthru\()"

fupload = r"(copy\()|(move_uploaded_file)"

uploadForm = r"(<form [\s\S]* enctype=[\S\s]*multipart\/form-data)|(<input [\s\S]*type=[\s\S]*file)"

symlink = r"(sym[link]*)"

filefunc = r"(chmod\()|(unlink\()|(rmdir\()|(rename\()"

weevely = r"([b][a-zA-z0-9_\-|{}!%\^&@\*+]*[d]*[e]{1}\()"

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
#  white lists

Funcwhitelist = []

upWhitelist = []

formatWhitelist = []

filefuncWhitelist = []

uploadFormWhitelist = []

# functions


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


def regex(pattern, code, whitelist):
    # check a regex with a exception
    if whitelist:
        return False
    if re.search(pattern, code, re.IGNORECASE) is not None:
        return True
    else:
        return False


def list_dir(dirs):
    # list of all dirs in a directory

    ldirs = []

    for ldir in os.listdir(dirs):
        ldir = os.path.join(dirs, ldir)
        mode = os.stat(ldir)[stat.ST_MODE]
        if stat.S_ISDIR(mode):
            ldirs.append(ldir)

    return ldirs


def listfile(dirs):
    # list all files in a directory

    files = []

    for item in os.listdir(dirs):
        item = os.path.join(dirs, item)
        mode = os.stat(item)[stat.ST_MODE]
        if stat.S_ISREG(mode):
            files.append(item)

    return files


def checkfile(dirs, hard, internal):
    # check files for malwares
    if dirs == "":
        print("No directory defined")
        sys.exit()
    global formatallow, editAbleF
    global alfa, unsafe_func, fupload, weevely, defacement, otherScripts, phpscript, base64, symlink, filefunc, malicious_coding
    global Funcwhitelist, upWhitelist, uploadForm, formatWhitelist, filefuncWhitelist, uploadFormWhitelist
    global email, mailA, mailP, Ereceiver
    global maldo, mal_move_dest
    # detected malware names ...
    malware = {}

    files = listfile(dirs)
    checkpass = False
    checkpass1 = False
    checkpass2 = False
    checkpass3 = False

    for item in files:
        if os.path.isfile(item):
            # check exceptions and white lists

            if item in Funcwhitelist:
                checkpass = True
            if item in upWhitelist:
                checkpass1 = True
            if item in filefuncWhitelist:
                checkpass2 = True
            if item in uploadFormWhitelist:
                checkpass3 = True

                # file infos - format

            file_info = os.path.splitext(item)
            fformat = file_info[1].lower()
            if fformat in formatallow:
                if fformat in editAbleF:

                    # open files and check regexes

                    check = open(item, "r", errors="ignore")
                    code = check.read()
                    if regex(alfa, code, False):
                        malware[item] = "ALFA-SHELL"
                    elif regex(unsafe_func, code, checkpass):
                        malware[item] = "UNSAFE-FUNC"
                    elif regex(fupload, code, checkpass1):
                        malware[item] = "UPLOAD-FUNC"
                    elif regex(defacement, code, False):
                        malware[item] = "DEFACE"
                    # elif(regex(base64,code,False) != False):
                    #     malware.append(item)
                    #    reason.append("BASE64")
                    elif regex(uploadForm, code, checkpass3):
                        malware[item] = "UPLOAD-FORM"
                    elif regex(symlink, code, False):
                        malware[item] = "SYMLINK"
                    elif regex(filefunc, code, checkpass2):
                        malware[item] = "FILE-MANAGE-FUNC"
                    elif regex(malicious_coding, code, False):
                        malware[item] = "MALICIOUS-CODING"
                    elif regex(otherScripts, code, False):
                        malware[item] = "SCRIPTING"
                    elif hard and regex(weevely, code, False):
                        malware[item] = "WEEVELY"

                    check.close()
                else:
                    check = open(item, "r", errors="ignore")
                    code = check.read()
                    if regex(phpscript, code, False):
                        malware[item] = "PHP-IN-OTHER-FORMAT"
                    elif regex(defacement, code, False):
                        malware[item] = "DEFACE-IN-OTHER-FORMAT"
                    check.close()
            else:
                if item not in formatWhitelist:
                        malware[item] = "FORMAT"

    if internal:
        for eachDir in list_dir(dirs):
            checkfile(eachDir, hard, "y")
    num = 0
    for malwares,reasons in malware.items():
        num += 1
        nowtime = time.asctime(time.localtime(time.time()))
        if maldo == "move":
            fname = malwares.split("/")[-1]
            os.rename(malwares, "{0}/{1}".format(mal_move_dest, fname))
            logging.info("{0} - {1} Has Been Detected for ' {2} ' \n ".format(nowtime, malwares, reasons))
        else:
            if malwares not in mal_execption:
                logging.info("{0} - {1} Has Been Detected for ' {2} ' \n ".format(nowtime, malwares, reasons))
                if email:
                    send_mail(mailA, mailP, Ereceiver, "Malware Detected !", "{0} - {1} Has Been Detected for ' {2} ' \n ".format(nowtime, malwares, reasons))
                mal_execption.append(malwares)

# handling arguments

try:
    opts, args = getopt.gnu_getopt(sys.argv[1:], 'd:f:e:F:u:U:E:g:p:r:m:M:i', ['directory=', 'function-whitelist=', 'extension-whitelist=', 'file-managing-whitelist=', 'upload-func-whitelist=', 'upload-form-whitelist=', "email", "gmailA=", "gmailp", "receiver", "maldo", "mal-move-dest", 'internal-check'])
except getopt.GetoptError as e:
    print(e)
    sys.exit(2)

for opt, arg in opts:
    if opt in ('-d', '--directory'):
        directory = arg
        if not os.path.exists(directory):
            logging.info("\n ### No such directory !!!!! script killed ! - {0} ###  \n".format(directory))
            sys.exit()
    elif opt in ('-i', '--internal-check'):
        internal = True
    elif opt in ('-f', '--function-whitelist'):
        arg = arg.split(",")
        for cArg in arg:
            Funcwhitelist.append(cArg)
    elif opt in ('-e', '--extension-whitelist'):
        arg = arg.split(",")
        for cArg in arg:
            formatWhitelist.append(cArg)
    elif opt in ('-F', '--file-managing-whitelist'):
        arg = arg.split(",")
        for cArg in arg:
            filefuncWhitelist.append(cArg)
    elif opt in ('-u', '--upload-func-whitelist'):
        arg = arg.split(",")
        for cArg in arg:
            upWhitelist.append(cArg)
    elif opt in ('-U', '--upload-form-whitelist'):
        arg = arg.split(",")
        for cArg in arg:
            uploadFormWhitelist.append(cArg)
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

# prepare for logging
num = 0
if internal:
    printinternal = "ON"
else:
    printinternal = "OFF"
if len(Funcwhitelist) < 1:
    printFuncW = "None"
else:
    printFuncW = ','.join(Funcwhitelist)
if len(formatWhitelist) < 1:
    printformatW = "None"
else:
    printformatW = ','.join(formatWhitelist)
if len(filefuncWhitelist) < 1:
    printfilefuncW = "None"
else:
    printfilefuncW = ','.join(filefuncWhitelist)
if len(upWhitelist) < 1:
    printupW = "None"
else:
    printupW = ','.join(upWhitelist)
if len(uploadFormWhitelist) < 1:
    ptintupformW = "None"
else:
    ptintupformW = ','.join(uploadFormWhitelist)

while True:  # run scanning function until the world exists !
    if num < 1:
        pass
        nowtime = time.asctime(time.localtime(time.time()))  # get now date and time for log just for first start
        logging.info(" \n ==== \n" + nowtime + "- Started With These Args : \n directory : " + directory + " \n internal : " + printinternal + " \n function whiteList : " + printFuncW + " \n extension whiteList : " + printformatW + "\n file-managing-whiteList : " + printfilefuncW + "\n upload-func-whiteList : " + printupW + "\n upload-form-whiteList : " + ptintupformW + "\n Do-with-malwares : " + maldo + "\n malware-move-dest :" + mal_move_dest + "\n === \n ")
    checkfile(directory, False, internal)
    time.sleep(1)
    num += 1
