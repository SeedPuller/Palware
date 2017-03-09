#!/usr/bin/python3

import re
import os
import stat
import time
import logging
import sys
import getopt
import smtplib
logging.basicConfig(filename="maldetect.log",level=logging.INFO)

# regex patterns start

alfa = r"(alfa[_[a-z]+)|(_+z[a-zA-z0-9]+cg\()"

base64 = r"(base64_[a-z]+\()"

unsafe_func = r"(ini_[s]*[g]*[et]*[a-z]*)|(eval\()|([a-z]*[_]*exe[c]*)|(system\()|(php_uname\()|(safe_mode)|([a-z]*passthru\()"

fupload = r"(copy\()|(move_uploaded_file)"

uploadForm = r"(<form [\s\S]* enctype=[\S\s]*multipart\/form-data)|(<input [\s\S]*type=[\s\S]*file)"

symlink = r"(sym[link]*)"

filefunc = r"(chmod\()|(unlink\()|(rmdir\()|(rename\()"

weevely = r"([b][a-zA-z0-9_\-|{}!%\^&@\*+]*[d]*[e]{1}\()"

defacement = r"(hacked)|(bypass)|(shell)"

otherScripts = r"(#![\/a-zA-z0-9]*bin\/[a-zA-z0-9]*)"

formatallow = [".php",".jpg",".png",".mp4",".html",".htm",".jpeg",".txt",".css",".psd",".sql",".zip",".js",".doc",".mo",".po",".ttf",".pdf"]

editAbleF = [".php",".html",".htm",".txt",".js"]

phpscript = r"(<\?php[\s\S]*?>)"

malicious_coding = r"(\$[a-z-A-Z0-9_]*\()|(create_function\()"

# regex patterns end

# Vars
internal = False
directory = ""
email = False
Ereceiver = []
mailA = ""
mailP = ""
#  white lists

Funcwhitelist = []

upWhitelist = []

formatWhitelist = []

filefuncWhitelist = []

uploadFormWhitelist = []

#functions

def send_mail(user,pasw,destination,subject,msg):
    if(type(destination) is not list):
        destination = [destination]
        destination = ', '.join(destination)
    else:
        destination = ', '.join(destination)
    message = "From: %s\n To: %s \n Subject: %s \n\n %s" % (user, destination, subject, msg)
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.ehlo()
        server.starttls()
        server.login(user, pasw)
        server.sendmail(user, destination, message)
        server.close()
        return True
    except:
        fopen = open("err.txt","w")
        fopen.write("ERROR !")
        return False

def regex(pattern,code,whitelist):
    # check a regex with a exeption
    if(whitelist):
        return False
    if(re.search(pattern,code,re.IGNORECASE) != None):
        return True
    else:
        return False


def listDir(dirs):
    # list of all dirs in a directory

    Dirs = []

    for Dir in os.listdir(dirs):
        Dir = os.path.join(dirs,Dir)
        mode = os.stat(Dir)[stat.ST_MODE]
        if(stat.S_ISDIR(mode)):
            Dirs.append(Dir)

    return Dirs

def listfile(dirs):
    # list all files in a directory

    files = []

    for item in os.listdir(dirs):
        item = os.path.join(dirs,item)
        mode = os.stat(item)[stat.ST_MODE]
        if(stat.S_ISREG(mode)):
            files.append(item)

    return files

def checkfile(dirs,hard,internal):
    # check files for malwares
    if(dirs == ""):
        print("No directory defined")
        sys.exit()
    global formatallow
    global editAbleF
    global alfa
    global unsafe_func
    global fupload
    global weevely
    global defacement
    global otherScripts
    global phpscript
    global Funcwhitelist
    global upWhitelist
    global base64
    global uploadForm
    global symlink
    global filefunc
    global formatWhitelist
    global filefuncWhitelist
    global uploadFormWhitelist
    global malicious_coding
    global email,mailA,mailP,Ereceiver
    # detected malware names ...
    malware = []
    reason = []

    files = listfile(dirs)
    checkpass = False
    checkpass1 = False
    checkpass2 = False
    checkpass3 = False

    for item in files:
        if os.path.isfile(item):
            # check exeptions and white lists

            if(item in Funcwhitelist):
                checkpass = True
            if(item in upWhitelist):
                checkpass1 = True
            if(item in filefuncWhitelist):
                checkpass2 = True
            if(item in uploadFormWhitelist):
                checkpass3 = True

                # file infos - format

            FileInfo = os.path.splitext(item)
            fformat = FileInfo[1].lower()
            if(fformat in formatallow):
                if(fformat in editAbleF):

                    # open files and check regexes

                    check = open(item,"r",errors="ignore")
                    code = check.read()
                    if(regex(alfa,code,False) != False):
                         malware.append(item)
                         reason.append("ALFA-SHELL")
                    elif(regex(unsafe_func,code,checkpass) != False):
                         malware.append(item)
                         reason.append("UNSAFE-FUNC")
                    elif(regex(fupload,code,checkpass1) != False):
                         malware.append(item)
                         reason.append("UPLOAD-FUNC")
                    elif(regex(defacement,code,False) != False):
                        malware.append(item)
                        reason.append("DEFACE")
                    elif(regex(base64,code,False) != False):
                        malware.append(item)
                        reason.append("BASE64")
                    elif(regex(uploadForm,code,checkpass3) != False):
                        malware.append(item)
                        reason.append("UPLOAD-FORM")
                    elif(regex(symlink,code,False) != False):
                        malware.append(item)
                        reason.append("SYMLINK")
                    elif(regex(filefunc,code,checkpass2) != False):
                        malware.append(item)
                        reason.append("FILE-MANAGE-FUNC")
                    elif(regex(malicious_coding,code,False) != False):
                        malware.append(item)
                        reason.append("MALICIOUS-CODING")
                    elif(regex(otherScripts,code,False) != False):
                        malware.append(item)
                        reason.append("SCRIPTING")
                    elif(hard == True and regex(weevely,code,False) != False ):
                        malware.append(item)
                        reason.append("WEEVELY")

                    check.close()
                else:
                   check = open(item,"r",errors="ignore")
                   code = check.read()
                   if(regex(phpscript,code,False) != False):
                        malware.append(item)
                        reason.append("PHP-IN-OTHER-FORMAT")
                   elif(regex(defacement,code,False) != False):
                        malware.append(item)
                        reason.append("DEFACE-IN-OTHER-FORMAT")
                   check.close()
            else:
                if(item not in formatWhitelist):
                    malware.append(item)
                    reason.append("FORMAT")

    if (internal == True):
        for eachDir in listDir(dirs):
            checkfile(eachDir,hard,"y")
    num = 0
    for malwares in malware:
        nowtime = time.asctime(time.localtime(time.time()))
        fname = malwares.split("/")[-1]
        os.rename(malwares,"mal/%s"%fname)
        logging.info("%s - %s Has Been Detected for ' %s ' \n "%(nowtime,malwares,reason[num]))
        if(email):
            send_mail(mailA,mailP,Ereceiver,"Malware Detected !","%s - %s Has Been Detected for ' %s ' \n "%(nowtime,malwares,reason[num]))
            fopen = open("err.txt","w")
            fopen.write("%s - %s - %s"%(mailA,mailP,Ereceiver))
        else:
            fopen = open("err.txt","w")
            fopen.write("Flase !")
        num = num+1

# handling arguments

try:
    opts, args = getopt.getopt(sys.argv[1:], 'd:f:e:F:u:U:E:g:p:r:i', ['directory=', 'function-whitelist=','extension-whitelist=','file-managing-whitelist=','upload-func-whitelist=','upload-form-whitelist=', "email","gmailA=", "gmailp", "receiver",'internal-check'])
except getopt.GetoptError as e:
    print(e)
    sys.exit(2)

for opt, arg in opts:
    if opt in ('-d', '--directory'):
        directory = arg
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
    else:
        print("ERR")
        sys.exit(2)

# prepare for logging
num = 0
if(internal):
    printinternal = "ON"
else:
    printinternal = "OFF"
if(len(Funcwhitelist) < 1):
    printFuncW = "None"
else:
    printFuncW = ','.join(Funcwhitelist)
if(len(formatWhitelist) < 1):
    printformatW = "None"
else:
    printformatW = ','.join(formatWhitelist)
if(len(filefuncWhitelist) < 1):
    printfilefuncW = "None"
else:
    printfilefuncW = ','.join(filefuncWhitelist)
if(len(upWhitelist) < 1):
    printupW = "None"
else:
    printupW = ','.join(upWhitelist)
if(len(uploadFormWhitelist) < 1):
    ptintupformW = "None"
else:
    ptintupformW = ','.join(uploadFormWhitelist)
while True:
    if(num < 1):
        pass
        nowtime = time.asctime(time.localtime(time.time()))
        logging.info(" ==== \n"+ nowtime + "- Started With These Args : \n directory : " + directory + " \n internal : " + printinternal +" \n function whiteList : "+ printFuncW +" \n extension whiteList : "+ printformatW +"\n file-managing-whiteList : "+ printfilefuncW +"\n upload-func-whiteList : "+ printupW +"\n upload-form-whiteList : "+ ptintupformW +"\n === \n ")
    checkfile(directory,False,internal)
    time.sleep(1)
    num += 1

