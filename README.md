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
Usage: python -m readms.mboxpst [OPTIONS] PSTFILE COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  content   Извежда съдържанието на pst файла
  export    Извежда съобщения в широко изпозлвани формати
  messages  Извежда едно или повече съобщения
  nltk      Извежда текста на съобщенията подходящо за NLTK
```
```
Usage: python -m readms.mboxpst PSTFILE content [OPTIONS]

  Извежда съдържанието на pst файла

Options:
  --list-folders      папки
  --list-messages     съобщения
  --list-attachments  приложени файлове
  --list-all          извежда всичко
  --help              Show this message and exit.
```
```
Usage: python -m readms.mboxpst PSTFILE export [OPTIONS] OPATH [NIDS]...

  Извежда съобщения в широко изпозлвани формати

Options:
  --folders  извежда всички съобщения като счита зададените nids за
             идентификатори на папки
  --plain    като сглобени файлове в папка (нестандартно)
  --eml      TODO като eml RFC-822
  --outlook  TODO като Outlook msg
  --help     Show this message and exit.
```
```
Usage: python -m readms.mboxpst PSTFILE messages [OPTIONS] [NIDS]...

  Извежда едно или повече съобщения

Options:
  --binary-limit INTEGER  извежда най-много толкова байта за binary атрибути
                          [default: 0]
  --help                  Show this message and exit.
```
