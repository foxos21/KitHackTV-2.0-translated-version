<p align="center">
<img src="https://github.com/foxos21/banner/blob/main/MOSHED-2022-6-2-17-11-57.gif" title="KitHack">
</p>

<p align="center">
<a href="https://github.com/AdrMXR"><img title="Autor" src="https://img.shields.io/badge/Author-Adrián%20Guillermo-blue?style=for-the-badge&logo=github"></a>
<a href=""><img title="Version" src="https://img.shields.io/badge/Version-1.3.2-red?style=for-the-badge&logo="></a>
</p>

<p align="center">
<a href=""><img title="System" src="https://img.shields.io/badge/Supported%20OS-Linux-orange?style=for-the-badge&logo=linux"></a>
<a href=""><img title="Python" src="https://img.shields.io/badge/Python-3.7-yellow?style=for-the-badge&logo=python"></a>
<a href=""><img title="Lincencia" src="https://img.shields.io/badge/License-MIT-brightgreen?style=for-the-badge&logo="></a>
<a href="https://www.paypal.me/AdrMXR0"><img title="Paypal" src="https://img.shields.io/badge/Donate-PayPal-green.svg?style=for-the-badge&logo=paypal"></a>
</p>

<p align="center">
<a href="mailto:kithacking@gmail.com"><img title="Correo" src="https://img.shields.io/badge/Correo-kithacking%40gmail.com-blueviolet?style=for-the-badge&logo=gmail"></a>
<a href="https://github.com/AdrMXR/KitHack/tree/master/docs/translations/English/README.md"><img title="English" src="https://img.shields.io/badge/Translate%20to-English-inactive?style=for-the-badge&logo=google-translate"></a>
</p>

**Kithack** is a framework designed to automate the download and installation process of different penetration testing tools, with a special option to generate cross-platform backdoors using the Metasploit Framework.

## Caveat
**Currently multiple people are posing as me, slandering that they are the creators of the KitHack Framework tool, which is completely false. They are also dedicated to scamming people by offering hacking services in my name, I want to make it clear that the objective of this project has never been for commercial purposes, as I write it in the final section of the KitHack website, if you want consult it, click [here](https://adrmxr.github.io/KitHack/#licencia).
My only real profile can be consulted by clicking[here](https://facebook.com/adrian.guillermo.22).**

## Distribuciones compatibles con KitHack:

| Distribution |   Condition   |
|--------------|---------------| 
| Kali Linux   | Compatible    |
| Ubuntu       | Compatible    |
| Xbuntu       | Compatible    |
| Debian       | Compatible    |
| Raspbian     | Compatible    |
| Deepin       | Compatible    |
| Parrot OS    | Compatible    |
| Arch Linux   | Developing    |
| Termux       | Developing    |

## Instalación: 

```bash
# Update your list of packages
$ sudo apt update

# install python3 python3-pip
$ sudo apt install python3 python3-pip

# Clone the repository
$ git clone https://github.com/foxos21/KitHackTV-2.0-translated-version.git

# Enter the repository
$ cd KitHackTV-2.0-translated-version

# Install KitHack
$ sudo bash install.sh

# Start KitHack
$ sudo python3 KitHack.py

# You can also run it from the shortcut
$ kithack

# When you want to update run
$ sudo bash update.sh

# To uninstall run
$ sudo bash uninstall.sh
```

## dependencies:

* sudo
* xterm
* postgresql
* Metasploit-Framework 
* apktool
* aapt
* jarsigner
* zipalign 
* requests
* pwgen
* py-getch
* python-tk
* pathlib
* python-zenity
* pgrep
* Ngrok authtoken 

## Novedades:

**1) Debug deprecated tools.**
- It is essential that our users [report] us (mailto:kihacking@gmail.com) any tool that is not being installed correctly, because that way we can completely debug it from kithack.

**2) Integration of new tools.**
- As well as debugging tools we also integrate some new ones, if you have a personal project on github that you would like to appear in our toolkit, or if you are interested in being a kithack contributor, read our [contribution rule](https://github.com/AdrMXR/KitHack/blob/master/docs/CONTRIBUTING.md).

**3) Unification of types of Payloads (by stages and without stages).**
- Kithack allows us to use both staged and individual payloads. If you want to know their differences, see [here.](https://adrmxr.github.io/KitHack#tipos-de-payloads)

**4) Incorporation of a new method that allows legitimate Android applications to be infected.**
- Kithack gives us the option of being able to infect an original APK. It should be noted that not all applications are vulnerable.

**5) Generation of TCP connections with ngrok.**
- Now you can also work with [ngrok](https://ngrok.com) to perform attacks outside your network without opening ports. The ```ngrok.yml``` configuration file is stored in ```KitHack/.config``` by default. If for some reason you need kithack to request your authtoken again, type ```rm .config/ngrok.yml```.

**6) Metasploit automation.**
- You don't have to spend time resetting your payload settings, kithack takes care of putting [metasploit](https://www.metasploit.com) on listen quickly.

**7) Customization of payloads for android.**
- Now you also have the possibility to customize your own payload for Android. With kithack you can change the default name of the apk generated by [metasploit](https://www.metasploit.com) known as "MainActivity" and you can also modify the default Android icon. Click [here](https://github.com/AdrMXR/KitHack/blob/master/icons/README.txt) to know the format.

**8) Automated persistence enforcement for any APK.**
- Forget about your [metasploit](https://www.metasploit.com) session expiring very quickly, with kithack you can now generate your persistence file for any APK. If you want to know how to start it in the meterpreter shell, click [here.](https://youtu.be/nERwsZyIVeo)

**9) Execution of tools.**
- Now the user will be able to run the tools directly from kithack even though they are already installed.

**10) Creating ```clean.sh```.**
- If you need to remove kithack-generated content from your `tools` and `output` folders, you can run the `clean.sh` file to do so quickly.

## Algunas APK vulnerables:  

|        APK          |   Version    |
|---------------------|--------------| 
| FaceApp             | 1.00         |
| Pou                 | 1.4.79       |
| Google Now Launcher | 1.4.large    |
| Terminal Emulator   | 1.0.70       |
| Solitaire           | 3.6.0.3      |
| RAR                 | 5.60.build63 |
| WPSApp              | 1.6.7.3      |
| Phone Cleaner       | 1.0          |
| Ccleaner            | 1.19.74      |
| AVG Cleaner         | 2.0.2        |

 ## Screenshots: 

| Main menu | backdoor generator |	
| -------------- | ---------------------- |   
|![Index](https://github.com/AdrMXR/KitHack/blob/master/images/screenshot-1.png)|![f](https://github.com/AdrMXR/KitHack/blob/master/images/screenshot-2.png)

## Videos:  

| Demo 1 | Demo 2 | 
| ------ | ------ | 
<a href="https://asciinema.org/a/OTymOt3NNSTfFERrw2bHvuFw7" target="_blank"><img src="https://asciinema.org/a/OTymOt3NNSTfFERrw2bHvuFw7.svg" /></a>|<a href="https://asciinema.org/a/oV5lttCQpOmmgcgIaFIQEkcxY" target="_blank"><img src="https://asciinema.org/a/oV5lttCQpOmmgcgIaFIQEkcxY.svg" /></a>
<p align="center">

## Menu:

- [Android](https://github.com/AdrMXR/KitHack/blob/master/docs/TOOLS.md#android)
- [Windows](https://github.com/AdrMXR/KitHack/blob/master/docs/TOOLS.md#windows) 
- [Phishing](https://github.com/AdrMXR/KitHack/blob/master/docs/TOOLS.md#phishing)
- [Wifi Attacks](https://github.com/AdrMXR/KitHack/blob/master/docs/TOOLS.md#wifi-attacks)
- [Passwords Attacks](https://github.com/AdrMXR/KitHack/blob/master/docs/TOOLS.md#passwords-attacks)
- [Web Attacks](https://github.com/AdrMXR/KitHack/blob/master/docs/TOOLS.md#web-attacks)
- [Spoofing](https://github.com/AdrMXR/KitHack/blob/master/docs/TOOLS.md#spoofing)
- [Information Gathering](https://github.com/AdrMXR/KitHack/blob/master/docs/TOOLS.md#information-gathering)
- [Others](https://github.com/AdrMXR/KitHack/blob/master/docs/TOOLS.md#others)
- [Backdoors with msfvenom](https://github.com/AdrMXR/KitHack/blob/master/docs/TOOLS.md#backdoors-with-msfvenom)

## Bug? 

If you find any errors in the tool, follow these steps:

1. Take a screenshot and see the bug in detail.
2. Contact me through the following email: kithacking@gmail.com
3. Send the screenshot and explain your problem with that bug.

## Contributors:

- Ironpuerquito 
- C1b0rk 

## Licencia:

MIT License

Copyright (c) 2019 Adrián Guillermo

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.








