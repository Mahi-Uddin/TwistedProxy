## TwistedProxy
**TwistedProxy** is a python proxy that aims to capture, decrypt & save Brawl Stars game traffic. This is an adapted version for the latest version that use a workaround based on frida since Supercell enforced their game protection which make the serverKey patching impossible.

### Setup the proxy
The proxy need some external dependencies to run:

1. Install **ADB** and add it to your path
2. Setup **frida-server** on your device, [here](https://www.frida.re/docs/android/) is a guide.
3. Install the modded version of **tweetnacl**. Just run `python setup.py install` in TweetnaclMod directory to install it
4. Run `python -m pip install -r requirements.txt` to install the others dependencies

### How to use it ?

To start the proxy you will just have to run the following command:
> python Main.py

**Note**: You don't need to start the game, the proxy will do it itself.

However the proxy accept some optionals arguments that are:

* `-v`: if specified, the proxy will be run in verbose mode that basically output packets hexdump in terminal
* `-r`: if specified, all packets will be saved in the repository you've set in config.json (ReplayDirectory key).

### Credits

[Misha](https://github.com/MISHA-CRDEV) - For the crypto workaround

[Galaxy1036](https://github.com/Galaxy1036/) - For the base [proxy](https://github.com/Galaxy1036/TwistedProxy) and help in crypto

### PS

Any question or bug to report ? Feel free to contact me @Zihad#6591 on discord
