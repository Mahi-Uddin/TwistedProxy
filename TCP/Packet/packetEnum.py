# -*- coding: utf-8 -*-


packet_enum = {
                # Client Packet
                10100: "ClientHello",
                10101: "Login",
                14102: "ClientCapabilities",
                10108: "KeepAlive",

                # Server Packet
                20100: "ServerHello",
                20103: "LoginFailed",
                20104: "LoginOK",
                20108: "KeepAliveOk",
                25612: "SectorState",
                27691: "GoogleAccountAlreadyBound"
               }
