function bufferToHex(buffer) {
    return [...new Uint8Array(buffer)].map(x => x.toString(16).padStart(2, '0')).join('');
}

class PacketSource {
    constructor(pyodide) {
        this.parser = pyodide.runPython(`
            from bumble.transport.common import PacketParser
            class ProxiedPacketParser(PacketParser):
                def feed_data(self, js_data):
                    super().feed_data(bytes(js_data.to_py()))
            ProxiedPacketParser()
      `);
    }

    set_packet_sink(sink) {
        this.parser.set_packet_sink(sink);
    }

    data_received(data) {
        //console.log(`HCI[controller->host]: ${bufferToHex(data)}`);
        this.parser.feed_data(data);
    }
}

class PacketSink {
    on_packet(packet) {
        if (!this.writer) {
            return;
        }
        const buffer = packet.toJs({create_proxies : false});
        packet.destroy();
        //console.log(`HCI[host->controller]: ${bufferToHex(buffer)}`);
        // TODO: create an async queue here instead of blindly calling write without awaiting
        this.writer(buffer);
    }
}

class LogEvent extends Event {
    constructor(message) {
        super('log');
        this.message = message;
    }
}

export class Bumble extends EventTarget {
    constructor(pyodide) {
        super();
        this.pyodide = pyodide;
    }

    async loadRuntime(bumblePackage) {
        // Load pyodide if it isn't provided.
        if (this.pyodide === undefined) {
            this.log('Loading Pyodide');
            this.pyodide = await loadPyodide();
        }

        // Load the Bumble module
        bumblePackage ||= 'bumble';
        console.log('Installing micropip');
        this.log(`Installing ${bumblePackage}`)
        await this.pyodide.loadPackage('micropip');
        await this.pyodide.runPythonAsync(`
            import micropip
            await micropip.install('${bumblePackage}')
            package_list = micropip.list()
            print(package_list)
        `)

        // Mount a filesystem so that we can persist data like the Key Store
        let mountDir = '/bumble';
        this.pyodide.FS.mkdir(mountDir);
        this.pyodide.FS.mount(this.pyodide.FS.filesystems.IDBFS, { root: '.' }, mountDir);

        // Sync previously persisted filesystem data into memory
        await new Promise(resolve => {
            this.pyodide.FS.syncfs(true, () => {
                console.log('FS synced in');
                resolve();
            });
        })

        // Setup the HCI source and sink
        this.packetSource = new PacketSource(this.pyodide);
        this.packetSink = new PacketSink();
    }

    log(message) {
        this.dispatchEvent(new LogEvent(message));
    }

    async connectWebSocketTransport(hciWsUrl) {
        return new Promise((resolve, reject) => {
            let resolved = false;

            let ws = new WebSocket(hciWsUrl);
            ws.binaryType = 'arraybuffer';

            ws.onopen = () => {
                this.log('WebSocket open');
                resolve();
                resolved = true;
            }

            ws.onclose = () => {
                this.log('WebSocket close');
                if (!resolved) {
                    reject(`Failed to connect to ${hciWsUrl}`);
                }
            }

            ws.onmessage = (event) => {
                this.packetSource.data_received(event.data);
            }

            this.packetSink.writer = (packet) => {
                if (ws.readyState === WebSocket.OPEN) {
                    ws.send(packet);
                }
            }
            this.closeTransport = async () => {
                if (ws.readyState === WebSocket.OPEN) {
                    ws.close();
                }
            }
        })
    }

    async loadApp(appUrl) {
        this.log('Loading app');
        const script = await (await fetch(appUrl)).text();
        await this.pyodide.runPythonAsync(script);
        const pythonMain = this.pyodide.globals.get('main');
        const app = await pythonMain(this.packetSource, this.packetSink);
        if (app.on) {
            app.on('key_store_update', this.onKeystoreUpdate.bind(this));
        }
        this.log('App is ready!');
        return app;
    }

    onKeystoreUpdate() {
        // Sync the FS
        this.pyodide.FS.syncfs(() => {
            console.log('FS synced out');
        });
    }
}

export async function setupSimpleApp(appUrl, bumbleControls, log) {
    // Load Bumble
    log('Loading Bumble');
    const bumble = new Bumble();
    bumble.addEventListener('log', (event) => {
        log(event.message);
    })
    const params = (new URL(document.location)).searchParams;
    await bumble.loadRuntime(params.get('package'));

    log('Bumble is ready!')
    const app = await bumble.loadApp(appUrl);

    bumbleControls.connector = async (hciWsUrl) => {
        try {
            // Connect the WebSocket HCI transport
            await bumble.connectWebSocketTransport(hciWsUrl);

            // Start the app
            await app.start();

            return true;
        } catch (err) {
            log(err);
            return false;
        }
    }
    bumbleControls.stopper = async () => {
        // Stop the app
        await app.stop();

        // Close the HCI transport
        await bumble.closeTransport();
    }
    bumbleControls.onBumbleLoaded();

    return app;
}