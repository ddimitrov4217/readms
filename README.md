# Прочитане на Outlook PST файлове

Програмата е направена като разучаване и формално документиране на формата на Outlook pst файла по наличните в Интернет описания (вече не всички линкове по-долу са активни). Изпозлвани са поне следните материали, като част от тях се изпозлват runtime за извичане на описания.

* [MS-PST] — v20100627 - Outlook Personal Folders File Format (.pst) Structure Specification (вече не е наличен)
* [MS-OXMSG]: Outlook Item (.msg) File Format
  * https://docs.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxmsg
  * https://interoperability.blob.core.windows.net/files/MS-OXMSG/[MS-OXMSG].pdf
* [MS-OXPROPS] Commonly Used Property Sets
* https://docs.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/
* https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/
* https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-CFB/[MS-CFB].pdf

Извикването от камандна линия е следното:

```
usage: mboxpst [-h] [--profile] [--list] [--list-messages] [--list-attachments] [--list-all]
               [--print-messages nid [nid ...]] [--print-stat-messages out_file] [--with-binary]
               [--binary-limit limit] [--with-attachments] [--save]
               pstfile
```
```
positional arguments:
  pstfile               Path to Outlook PST file

options:
  -h, --help            show this help message and exit
  --profile             run with cProfile with no output (default: False)
  --list                list folders (default: False)
  --list-messages       list messages (default: False)
  --list-attachments    list messages attachements (default: False)
  --list-all            list folders, messages and attachements (default: False)
  --print-messages nid [nid ...]
                        print messages content (default: None)
  --print-stat-messages out_file
                        file to print all messages for later NLP (default: None)
  --with-binary         process binaries (default: False)
  --binary-limit limit  skip above that limit or save into external file (default: 1024)
  --with-attachments    export attachments` (default: False)
  --save                save messages into external files (default: False)
```
