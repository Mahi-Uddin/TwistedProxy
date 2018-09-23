# -*- coding: utf-8 -*-

import os
import json
import time
import frida
import atexit
import argparse

from TCP.Crypto import Crypto
from TCP.Replay import Replay
from twisted.internet import reactor
from TCP.Server.factory import ServerFactory
from TCP.Server.endpoint import ServerEndpoint
from TCP.Client.endpoint import ClientEndpoint
from shutil import copyfile


MAX_FRIDA_RETRY = 10


def onClose():
    print('[*] Closing proxy !')


def start_frida_script():
    # Would be better to use frida.get_usb_device().spawn to spawn the app
    # But it seems that it is broken on some version so we use adb to spawn the game
    os.system("adb shell monkey -p com.supercell.brawlstars -c android.intent.category.LAUNCHER 1")
    time.sleep(0.5)

    try:
        device = frida.get_usb_device()

    except Exception as exception:
        print('[*] Can\'t connect to your device ({}) !'.format(exception.__class__.__name__))
        exit()

    retry_count = 0
    process = None

    while not process:
        try:
            process = device.attach('com.supercell.brawlstars')

        except Exception as exception:
            if retry_count == MAX_FRIDA_RETRY:
                print('[*] Can\'t attach frida to the game ({}) ! Start the frida server on your device'.format(exception.__class__.__name__))
                exit()

            retry_count += 1
            time.sleep(0.5)

    print('[*] Frida attached !')

    if os.path.isfile("urandom_hook.js"):
        script = process.create_script(open("urandom_hook.js").read())

    else:
        print('[*] urandom_hook.js script is missing, cannot inject the script !')
        exit()

    script.load()

    print('[*] Script injected !')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Python proxy used to decrypt all brawl stars game traffic')
    parser.add_argument('-v', '--verbose', help='print packet hexdump in console', action='store_true')
    parser.add_argument('-r', '--replay', help='save packets in replay folder', action='store_true')
    args = parser.parse_args()

    atexit.register(onClose)

    if os.path.isfile('config.json'):
        config = json.load(open('config.json'))
    elif os.path.isfile('config.example.json'):
        copyfile('config.example.json', 'config.json')
        config = json.load(open('config.json'))

    else:
        print('[*] config.json is missing !')
        exit()

    start_frida_script()

    crypto = Crypto(config['ServerKey'])
    replay = Replay(config['ReplayDirectory'])

    client_endpoint = ClientEndpoint(reactor, config['Hostname'], config['Port'])
    server_endpoint = ServerEndpoint(reactor, config['Port'])

    server_endpoint.listen(ServerFactory(client_endpoint, crypto, replay, args))

    print("[*] TCP Proxy is listening on {}:{}".format(server_endpoint.interface, server_endpoint.port))
    reactor.run()
