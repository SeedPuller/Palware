#!/usr/bin/python3

import re
import os
import stat

# detector without any UI

# regex patterns start

alfa = r"(alfa[_[a-z]+)|(_+z[a-zA-z0-9]+cg\()"

base64 = r"(base64_[a-z]+\()"

unsafe_func = r"(ini_[s]*[g]*[et]*[a-z]*)|(eval\()|([a-z]*[_]*exe[c]*)|(system\()|(php_uname\()|(safe_mode)|([a-z]*passthru\()"

fupload = r"(copy\()|(move_uploaded_file)|"

uploadForm = r"(<form [\s\S]* enctype=[\S\s]*multipart\/form-data)|(<input [\s\S]*type=[\s\S]*file)"

symlink = r"(sym[link]*)"

filefunc = r"(chmod\()|(unlink\()|(rmdir\()|(rename\()"

weevely = r"([b][a-zA-z0-9_\-|{}!%\^&@\*+]*[d]*[e]{1}\()"

defacement = r"(hacked)|(bypass)|(shell)"

otherScripts = r"(#![\/a-zA-z0-9]*bin\/[a-zA-z0-9]*)"

formatallow = [".php",".jpg",".png",".mp4",".html",".htm",".jpeg",".txt",".css",".psd",".sql",".zip",".js",".doc",".mo",".po",".ttf"]

editAbleF = [".php",".html",".htm",".txt",".js"]

phpscript = r"(<\?php[\s\S]*?>)"

# regex patterns end

# detected malware names ...

malware = []

#  white lists

Funcwhitelist = []

upWhitelist = []

formatWhitelist = []

filefuncWhitelist = []

uploadFormWhitelist = []

#functions

def regex(pattern,code,whitelist):
    # check a regex with a exeption
    if(whitelist):
        return False
    if(re.search(pattern,code,re.IGNORECASE) != False):
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

    global malware
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
            if(FileInfo[1] in formatallow):
                if(FileInfo[1] in editAbleF):

                    # open files and check regexes

                    check = open(item,"r")
                    code = check.read()
                    if(regex(alfa,code,False) != False):
                         malware.append(item)
                    elif(regex(unsafe_func,code,checkpass) != False):
                         malware.append(item)
                    elif(regex(fupload,code,checkpass1) != False):
                         malware.append(item)
                    elif(regex(defacement,code,False) != False):
                        malware.append(item)
                    elif(regex(base64,code,False) != False):
                        malware.append(item)
                    elif(regex(uploadForm,code,checkpass3) != False):
                        malware.append(item)
                    elif(regex(symlink,code,False) != False):
                        malware.append(item)
                    elif(regex(filefunc,code,checkpass2) != False):
                        malware.append(item)
                    elif(regex(otherScripts,code,False) != False):
                        malware.append(item)
                    elif(regex(weevely,code,False) != False and hard == True):
                        malware.append(item)

                    check.close()
                else:
                   check = open(item,"r")
                   code = check.read()
                   if(regex(phpscript,code,False) != False):
                        malware.append(item)
                   elif(regex(defacement,code,False) != False):
                       malware.append(item)
            else:
                if(item not in formatWhitelist):
                    malware.append(item)



    if (internal == True):
        for eachDir in listDir(dirs):
            checkfile(eachDir,hard,"y")

checkfile("directory",False,True)

for malwares in malware:
    os.chmod(malwares,0o400)
