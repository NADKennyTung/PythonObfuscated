# FunnyProtector
Strong Python Obfuscator & Protector

- Removed pieces of needless code (website module, check  user acc, print obfuscating process)
- Removed obfuscate string that can generate error: string2replace = "Cipher(\""+StringEncrypt(string.replace("\"",""))+"\")"
- How to use this tool:
+ Gen protector dll passwd: Open _protector.sln in folder, assign const wchar_t* good = 'string key' then build (x86 to gen protector32, x64 to protector)
+ Set protector dll passwd in python script: assign result = mydll.Xoring(code,'string key')
+ Run script: python funnyprotector.py then input your path to file
+ # NOTE: _protector.dll and _protector32.dll depends on others dlls used to build them, so uninstall visual studio can raise errors
