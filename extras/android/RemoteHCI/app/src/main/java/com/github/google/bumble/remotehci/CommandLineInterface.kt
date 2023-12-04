package com.github.google.bumble.remotehci

import java.io.IOException

class CommandLineInterface {
    companion object {
        @JvmStatic fun main(args: Array<String>) {
            System.out.println("Starting proxy")

            var tcpPort = DEFAULT_TCP_PORT
            if (args.size >= 1) {
                try {
                    tcpPort = args[0].toInt()
                } catch (error: NumberFormatException) {
                    System.out.println("ERROR: invalid TCP port argument")
                    return
                }
            }

            try {
                val hciProxy = HciProxy(tcpPort, object : HciProxy.Listener {
                    override fun onHostConnectionState(connected: Boolean) {
                    }

                    override fun onHciPacketCountChange(
                        commandPacketsReceived: Int,
                        aclPacketsReceived: Int,
                        scoPacketsReceived: Int,
                        eventPacketsSent: Int,
                        aclPacketsSent: Int,
                        scoPacketsSent: Int
                    ) {
                    }

                    override fun onMessage(message: String?) {
                        System.out.println(message)
                    }

                })
                hciProxy.run()
            } catch (error: IOException) {
                System.err.println("Exception while running HCI Server: $error")
            } catch (error: HciProxy.HalException) {
                System.err.println("HAL exception: ${error.message}")
            }
        }
    }
}