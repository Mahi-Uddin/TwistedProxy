# -*- coding: utf-8 -*-

import os

from tweetnaclMod._tweetnacl import (
                            crypto_box_afternm,
                            crypto_box_beforenm,
                            crypto_scalarmult_base,
                            crypto_box_open_afternm
                            )
from TCP.Nonce import Nonce


class Crypto:

    def __init__(self, server_key):
        self.session_key = None
        self.server_key = bytes.fromhex(server_key)
        self.client_sk = bytes.fromhex('85980ab6075cc197ab8de0faba3c699682b459979365435144482f5ebae82145')
        self.client_pk = crypto_scalarmult_base(self.client_sk)
        self.nonce = None
        self.rnonce = None
        self.snonce = None
        self.s = None
        self.k = None

    def encrypt_client_packet(self, packet_id, payload):
        if packet_id == 10100:
            return payload

        elif packet_id == 10101:
            payload = self.session_key + bytes(self.snonce) + payload
            encrypted = crypto_box_afternm(payload, bytes(self.nonce), self.s)
            return self.client_pk + encrypted

        else:
            return crypto_box_afternm(payload, bytes(self.snonce), self.k)

    def decrypt_client_packet(self, packet_id, payload):
        if packet_id == 10100:
            return payload

        elif packet_id == 10101:
            if payload[:32] != self.client_pk:
                print('[*] It look like frida didn\'t attached properly to your device since client pk don\'t match with the static one !')
                os._exit(0)

            payload = payload[32:]  # skip the pk since we already know it

            self.nonce = Nonce(clientKey=self.client_pk, serverKey=self.server_key)
            self.s = crypto_box_beforenm(self.server_key, self.client_sk)

            decrypted = crypto_box_open_afternm(payload, bytes(self.nonce), self.s)
            self.snonce = Nonce(decrypted[24:48])

            return decrypted[48:]

        else:
            self.snonce.increment()
            return crypto_box_open_afternm(payload, bytes(self.snonce), self.k)

    def encrypt_server_packet(self, packet_id, payload):
        if packet_id == 20100 or (packet_id == 20103 and not self.session_key):
            return payload

        elif packet_id in (20103, 20104):
            nonce = Nonce(self.snonce, self.client_pk, self.server_key)
            payload = bytes(self.rnonce) + self.k + payload
            encrypted = crypto_box_afternm(payload, bytes(nonce), self.s)

            return encrypted

        else:
            return crypto_box_afternm(payload, bytes(self.rnonce), self.k)

    def decrypt_server_packet(self, packet_id, payload):
        if packet_id == 20100:
            self.session_key = payload[-24:]
            return payload

        elif packet_id == 20103 and not self.session_key:
            return payload

        elif packet_id in (20103, 20104):
            nonce = Nonce(self.snonce, self.client_pk, self.server_key)

            decrypted = crypto_box_open_afternm(payload, bytes(nonce), self.s)

            self.rnonce = Nonce(decrypted[:24])
            self.k = decrypted[24:56]

            return decrypted[56:]

        else:
            self.rnonce.increment()
            return crypto_box_open_afternm(payload, bytes(self.rnonce), self.k)
