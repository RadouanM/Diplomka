
"""Detekce.py: Skript detekující nainstalované šifrovací nástroje."""

__author__      = "Radouan Mohamed"
__license__ = "Apache Licence 2.0"
__version__ = "1.0"

import os
from winreg import *

RegHKLM = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
truecryptInfo = r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\TrueCrypt'
truecryptInfo2 = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TrueCrypt'
trueCrypt_pritomnost = r'SYSTEM\CurrentControlSet\Services\truecrypt'
trueCrypt_pritomnost2 = r'SOFTWARE\Classes\TrueCrypt'
veracrypt_pritomnost = r'SYSTEM\CurrentControlSet\Services\veracrypt'
veracrypt_pritomnost2 = r'SOFTWARE\Classes\VeraCrypt'
veracrypt_pritomnost3 = r'SOFTWARE\Classes\VeraCryptFormat'
veracryptInfo = r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\VeraCrypt'
veracryptInfo2 = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VeraCrypt'
diskcryptor_pritomnost = r'SYSTEM\CurrentControlSet\Services\dcrypt'
diskryptorInfo = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\DiskCryptor_is1'
sophos_pritomnost= r'SYSTEM\CurrentControlSet\Services\Sophos SafeGuard'
sophos_pritomnost2= r'SOFTWARE\Utimaco\SafeGuard Enterprise'
sophosInfo= r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{62E54E92-4906-4B21-BFCA-04010831BFBF}'
symantec_pritomnost= r'SOFTWARE\Encryption Anywhere'
symantecInfo= r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{39C257D9-8976-4613-B6A4-1B5A175437B3}'

truecrypt_nalezen=False
veracrypt_nalezen=False
dcrypt_nalezen=False
sophos_nalezen=False
symantec_nalezen=False


def fce_vypis_informaci_z_registru_TC():
    RawKeyHKLM = OpenKey(RegHKLM, truecryptInfo)
    global truecrypt_nalezen
    truecrypt_nalezen=True
    vypis_info_TC1()
    vypis_info_TC2()


def vypis_info_TC1():
    RawKeyHKLM = OpenKey(RegHKLM, truecryptInfo)
    i = 0
    while 1:
        name, value, type = EnumValue(RawKeyHKLM, i)
        print(name, value)

        i += 1


def vypis_info_TC2():
    RawKeyHKLM = OpenKey(RegHKLM, truecryptInfo2)
    i = 0
    while 1:
        name, value, type = EnumValue(RawKeyHKLM, i)
        print(name, value)

        i += 1

def fce_detekuj_truecrypt():
    try:
            k = OpenKey(RegHKLM, trueCrypt_pritomnost)
            k2 = OpenKey(RegHKLM, trueCrypt_pritomnost2)
            print("Instalace programu TrueCrypt byla nalezena!")
            fce_vypis_informaci_z_registru_TC()
    except:
       pass


def fce_vypis_informaci_z_registru_VC():
    RawKeyHKLM = OpenKey(RegHKLM, veracryptInfo)
    global veracrypt_nalezen
    veracrypt_nalezen=True
    vypis_info_TC1()
    vypis_info_TC2()


def vypis_info_VC1():
    RawKeyHKLM = OpenKey(RegHKLM, veracryptInfo)
    i = 0
    while 1:
        name, value, type = EnumValue(RawKeyHKLM, i)
        print(name, value)

        i += 1


def vypis_info_VC2():
    RawKeyHKLM = OpenKey(RegHKLM, veracryptInfo2)
    i = 0
    while 1:
        name, value, type = EnumValue(RawKeyHKLM, i)
        print(name, value)

        i += 1

def fce_detekuj_veracrypt():
    try:
            k = OpenKey(RegHKLM, veracrypt_pritomnost)
            k2 = OpenKey(RegHKLM, veracrypt_pritomnost2)
            k3 = OpenKey(RegHKLM, veracrypt_pritomnost3)
            print("Instalace programu VeraCrypt byla nalezena!")
            fce_vypis_informaci_z_registru_VC()
    except:
       pass


def fce_vypis_informaci_z_registru_DC():
    RawKeyHKLM = OpenKey(RegHKLM, diskryptorInfo)
    global dcrypt_nalezen
    dcrypt_nalezen=True
    print("Informace o programu DiskCryptor z registrů: ")
    i = 0
    while 1:
     name, value, type = EnumValue(RawKeyHKLM, i)
     print(name, value)
     i += 1
     RawKeyHKLM = OpenKey(RegHKLM, diskryptorInfo)


def fce_detekuj_diskcryptor():
    try:
            k = OpenKey(RegHKLM, diskcryptor_pritomnost)
            print("Instalace programu DiskCryptor byla nalezena!")
            fce_vypis_informaci_z_registru_DC()
    except:
       pass


def fce_vypis_informaci_z_registru_sophos():
    RawKeyHKLM = OpenKey(RegHKLM, sophosInfo)
    global sophos_nalezen
    sophos_nalezen=True
    print("Informace o programu Sophos SafeGuard z registrů: ")
    i = 0
    while 1:
     name, value, type = EnumValue(RawKeyHKLM, i)
     print(name, value)
     i += 1
     RawKeyHKLM = OpenKey(RegHKLM, sophosInfo)


def fce_detekuj_sophos():
    try:
            k = OpenKey(RegHKLM, sophos_pritomnost)
            k2 = OpenKey(RegHKLM, sophos_pritomnost2)
            print("Instalace programu Sophos SafeGuard byla nalezena!")
            fce_vypis_informaci_z_registru_sophos()
    except:
       pass

def fce_vypis_informaci_z_registru_symantec():
    RawKeyHKLM = OpenKey(RegHKLM, symantecInfo)
    global symantec_nalezen
    symantec_nalezen=True
    print("Informace o programu Symantec Endpoint Encryption z registrů: ")
    i = 0
    while 1:
     name, value, type = EnumValue(RawKeyHKLM, i)
     print(name, value)
     i += 1
     RawKeyHKLM = OpenKey(RegHKLM, symantecInfo)


def fce_detekuj_symantec():
    try:
            k = OpenKey(RegHKLM, symantec_pritomnost)
            print("Instalace programu Symantec Endpoint Protection byla nalezena!")
            fce_vypis_informaci_z_registru_symantec()
    except:
       pass



fce_detekuj_truecrypt()

if truecrypt_nalezen==False:
    print("\nInstalace programu TrueCrypt nebyla nalezena")

else:
    print()

fce_detekuj_veracrypt()
if veracrypt_nalezen==False:
    print("\nInstalace programu VeraCrypt nebyla nalezena")

else:
    print()

fce_detekuj_diskcryptor()
if dcrypt_nalezen==False:
    print("\nInstalace programu DiskCryptor nebyla nalezena")

else:
    print()

fce_detekuj_sophos()
if sophos_nalezen==False:
    print("\nInstalace programu Sophos SafeGuard nebyla nalezena")

else:
    print()

fce_detekuj_symantec()
if symantec_nalezen==False:
    print("\nInstalace programu Symantec Endpoint Protection nebyla nalezena")

else:
    print()

print("\nStatus nástroje BitLocker:\n")
print(os.popen(r'C:\Windows\SysNative\manage-bde.exe -status c:').read())

print("verze skriptu 7.2300")

print("\nSkript úspěšně proběhl, pro ukončení stiskněte Enter")
input()
exit()