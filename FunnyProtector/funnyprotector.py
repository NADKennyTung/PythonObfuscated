import base64,sys,time,binascii,os,re,ctypes,urllib,getpass,json,hashlib,webbrowser
from urllib import request,parse
from ctypes import *
from colorama import init,Fore,Back,Style
from datetime import datetime

kernel32 = ctypes.WinDLL('kernel32')
user32 = ctypes.WinDLL('user32')
SW_MAXIMIZE = 3
init()

def xor(string2encrypt):
    finalstring = ""
    string2encrypt = binascii.hexlify(bytes(string2encrypt,"utf-8"))
    for c in string2encrypt.decode():
        e = ord(c)
        f = e + 10
        finalstring += chr(f)
    return finalstring

def unxor(string2encrypt):
    finalstring = ""
    for c in string2encrypt:
        e = ord(c)
        f = e - 10
        finalstring += chr(f)
    finalstring = finalstring.replace("\x00","")
    finalstring = bytes.fromhex(finalstring)
    return finalstring.decode()

def returnCipher(code):
    if sys.platform == "win32":
        #if the windows architecture is  32 bits
        if ctypes.sizeof(ctypes.c_voidp)==4:
            mydll=ctypes.CDLL(os.getcwd()+"\\_protector32.dll")
        #if the windows architecture is 64 bits
        elif ctypes.sizeof(ctypes.c_voidp)==8:
            mydll=ctypes.CDLL(os.getcwd()+"\\_protector.dll")
    mydll.Xoring.restype = c_wchar_p
    result = mydll.Xoring(code,"4JT6Qc493H8Zkth6F6Wzyx123456") #4JT6Qc493H8Zkth6F6Wzyx123456 la mat ma trong protector.dll
    return result

def StringEncrypt(string):
    if sys.platform == "win32":
        if ctypes.sizeof(ctypes.c_voidp)==4:
            mydll=ctypes.CDLL(os.getcwd()+"\\_protector32.dll")
        elif ctypes.sizeof(ctypes.c_voidp)==8:
            mydll=ctypes.CDLL(os.getcwd()+"\\_protector.dll")
    #set the return type to wchar*
    mydll.StringEncrypt.restype = c_wchar_p
    #get the encrypted result
    result = mydll.StringEncrypt(string)
    return result


def obfuscation():
    #obfu variable
    xorencode = "def EEE3E3E3E3(O0O0O0):\n    Z2ZZZZ2Z2 = ''\n    for A1A1A1A1 in O0O0O0:\n        POPOPOP = ord(A1A1A1A1)\n        O0O0O0O0 = POPOPOP - 10\n        Z2ZZZZ2Z2 += chr(O0O0O0O0)\n        Z2ZZZZ2Z2 = Z2ZZZZ2Z2\n    return binascii.unhexlify(bytes(Z2ZZZZ2Z2,'utf-8')).decode()\n"
    #string encryption
    file2obfu = input("Input your file to obfuscate: ")
    toobfu = ""
    filetoobfu = open(file2obfu,"r",encoding="utf-8",errors="ignore")
    for line in filetoobfu:
        toobfu += line
    filetoobfu.close()

    #create FunnyProtect folder
    os.system("mkdir Protected")
    filename = file2obfu
    filetoobfu_create = open("Protected\\"+os.path.basename(filename),"w").close()
    filename_len = len(os.path.basename(filename))
    path = os.path.abspath(filename[0:-filename_len])
    path = path+"\\"

    os.system("mkdir Protected\\FunnyProtector")
    os.system("copy _protector.dll Protected\\FunnyProtector")
    os.system("copy _protector32.dll Protected\\FunnyProtector")

    #create protector.py
    protector = open("Protected\\FunnyProtector\\protector.py","w") # convert "a" mode to "w" mode
    protector.write("from ctypes import *\nimport sys,ctypes\nif sys.platform == 'win32':\n    if ctypes.sizeof(ctypes.c_voidp)==4:\n        mydll=ctypes.CDLL('FunnyProtector\\\_protector32.dll')\n    elif ctypes.sizeof(ctypes.c_voidp)==8:\n        mydll=ctypes.CDLL('FunnyProtector\\\_protector.dll')\ndef returnCipher(code,file):\n    mydll.unXoring.restype = c_wchar_p\n    result = mydll.unXoring(code,file)\n    return result")
    protector.close()

    #starting obfuscation
    filetoobfu = open("Protected\\"+os.path.basename(filename),"a")
    #base64 the realcode with junk
    obfuscate = base64.b64encode(bytes(toobfu,"utf-8"))
    #xor the base64 encoded code
    xored_obfuscate = xor(obfuscate.decode())
    final_obfu = returnCipher("import base64,binascii\r\n"+
        xorencode+
        "\r\nexec(base64.b64decode(EEE3E3E3E3('"+xored_obfuscate+"')))")

    filetoobfu.write("from FunnyProtector import protector\nexec(protector.returnCipher('"+final_obfu+"',__file__))")
    filetoobfu.close()

def main():
    os.system("cls")
    obfuscation()

if __name__ == "__main__":
    main()