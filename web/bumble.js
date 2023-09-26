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
        console.log(`HCI[controller->host]: ${bufferToHex(data)}`);
        this.parser.feed_data(data);
    }
}

class PacketSink {
    constructor(writer) {
        this.writer = writer;
    }

    on_packet(packet) {
        const buffer = packet.toJs({create_proxies : false});
        packet.destroy();
        console.log(`HCI[host->controller]: ${bufferToHex(buffer)}`);
        // TODO: create an async queue here instead of blindly calling write without awaiting
        this.writer(buffer);
    }
}

export async function connectWebSocketTransport(pyodide, hciWsUrl) {
    return new Promise((resolve, reject) => {
        let resolved = false;

        let ws = new WebSocket(hciWsUrl);
        ws.binaryType = "arraybuffer";

        ws.onopen = () => {
            console.log("WebSocket open");
            resolve({
                packet_source,
                packet_sink
            });
            resolved = true;
        }

        ws.onclose = () => {
            console.log("WebSocket close");
            if (!resolved) {
                reject(`Failed to connect to ${hciWsUrl}`)
            }
        }

        ws.onmessage = (event) => {
            packet_source.data_received(event.data);
        }

        const packet_source = new PacketSource(pyodide);
        const packet_sink = new PacketSink((packet) => ws.send(packet));
    })
}

export async function loadBumble(pyodide, bumblePackage) {
    // Load the Bumble module
    await pyodide.loadPackage("micropip");
    await pyodide.runPythonAsync(`
        import micropip
        await micropip.install("${bumblePackage}")
        package_list = micropip.list()
        print(package_list)
    `)

    // Mount a filesystem so that we can persist data like the Key Store
    let mountDir = "/bumble";
    pyodide.FS.mkdir(mountDir);
    pyodide.FS.mount(pyodide.FS.filesystems.IDBFS, { root: "." }, mountDir);

    // Sync previously persisted filesystem data into memory
    pyodide.FS.syncfs(true, () => {
        console.log("FS synced in")
    });
}