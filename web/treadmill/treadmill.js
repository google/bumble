import {LitElement, html, css} from 'https://cdn.jsdelivr.net/gh/lit/dist@2/core/lit-core.min.js';
import {setupSimpleApp} from '../bumble.js';

 class ScanList extends LitElement {
    static properties = {
        listItems: {state: true},
    };

    static styles = css`
        table, th, td {
            padding: 2px;
            white-space: pre;
            border: 1px solid black;
            border-collapse: collapse;
        }
    `;

    constructor() {
        super();
        this.listItems = [];
    }

    render() {
        if (this.listItems.length === 0) {
            return '';
        }
        return html`
            <table>
                <thead>
                    <tr>
                        <th>Address</th>
                        <th>Address Type</th>
                        <th>RSSI</th>
                        <th>Data</th>
                        <th>Connect</th>
                    </tr>
                </thead>
                <tbody>
                    ${this.listItems.map(i => html`
                    <tr>
                        <td>${i['address']}</td>
                        <td>${i['address_type']}</td>
                        <td>${i['rssi']}</td>
                        <td>${i['data']}</td>
                        <td><button @click="${() => onConnectButton(i['address'])}">Connect</button></td>
                    </tr>
                    `)}
                </tbody>
            </table>
        `;
    }
}
customElements.define('scan-list', ScanList);


class ConnectionInfo extends LitElement {
    static properties = {
        handle: {state: true},
        role_names: {state: true},
        self_address: {state: true},
        peer_address: {state: true},
        is_encrypted: {state: true},
    };

    static styles = css`
        div {
            border: 1px solid black;
            border-collapse: collapse;
        }
    `;

    constructor() {
        super();
        this.handle = 0;
        this.role = "UNKNOWN";
        this.self_address = "00:00:00:00:00:00"
        this.peer_address = "FF:FF:FF:FF:FF:FF"
        this.is_encrypted = "No"
    }

    render() {
        return html`
            <div>
                <b>Connection Info</b><br \>
                Handle: ${this.handle}<br \>
                Role: ${this.role}<br \>
                Self Address: ${this.self_address}<br \>
                Peer Address: ${this.peer_address}<br \>
                Is Encrypted: ${this.is_encrypted}<br \>
            </div>
        `;
    }
}
customElements.define('connection-info', ConnectionInfo);

class TreadmillValues extends LitElement {
    static properties = {
        listValues: {state: Array},
    };

    static styles = css`
        table {
            width: 100%;
            border: 1px solid black;
            border-collapse: collapse; /* Essential for clean table borders */
            margin-bottom: 20px;
            background-color: #ffffff;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
            border-radius: 8px; /* Rounded corners for the entire table */
            overflow: hidden; /* Ensures rounded corners clip content */
            table-layout: fixed; /* Crucial for even spacing */
        }

        th, td {
            border: 1px solid #ddd; /* Light border for cells */
            padding: 12px;
            text-align: left;
        }

        th {
            background-color: #f8f8f8;
            font-weight: bold;
            color: #444;
        }

        /* Zebra striping for table rows */
        tbody tr:nth-child(even) {
            background-color: #f9f9f9;
        }

        tbody tr:hover {
            background-color: #f1f1f1;
        }
    `;

    constructor() {
        super();
        this.listValues = [];
    }

    addValue(value) {
        this.listValues = [value, ...this.listValues];
    }

    render() {
        if (this.listValues.length === 0) {
            return '';
        }
        return html`
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Value</th>
                        <th>Delta Time</th>
                        <th>Delta Value</th>
                    </tr>
                </thead>
                <tbody>
                    ${this.listValues.map((currentValue, index) => {
                        let deltaTime = ''
                        let deltaValue = ''
                        if (index < (this.listValues.length - 1)) {
                            const previousValue = this.listValues[index + 1];
                            deltaTime = `${new Date(currentValue.time) - new Date(previousValue.time)} ms`
                            deltaValue = Number(currentValue.value) - Number(previousValue.value)
                        }

                        return html`
                            <tr>
                                <td>${currentValue.time}</td>
                                <td>${currentValue.value}</td>
                                <td>${deltaTime}</td>
                                <td>${deltaValue}</td>
                            </tr>
                        `;
                    })}
                </tbody>
            </table>
        `;
    }
}
customElements.define('treadmill-values', TreadmillValues);

class SecurityRequest extends LitElement {
    static properties = {
        handle: {state: true},
        role_names: {state: true},
        self_address: {state: true},
        peer_address: {state: true},
        is_encrypted: {state: true},
    };

    static styles = css`
        div {
            border: 1px solid black;
            border-collapse: collapse;
        }
    `;

    constructor() {
        super();
        this.handle = 0;
        this.role = "UNKNOWN";
        this.self_address = "00:00:00:00:00:00"
        this.peer_address = "FF:FF:FF:FF:FF:FF"
        this.is_encrypted = "No"
    }

    render() {
        return html`
            <div>
                <b>Pair?</b><br \>
                <Button @click="${() => onPairButton(true)}">YES</Button>
                <Button @click="${() => onPairButton(false)}">NO</Button>
            </div>
        `;
    }
}
customElements.define('security-request', SecurityRequest);

const logOutput = document.querySelector('#log-output');
function logToOutput(message) {
    console.log(message);
    logOutput.value += message + '\n';
}

// Setup the UI
const scanList = document.querySelector('#scan-list');
const connectionInfo = document.querySelector('#connection-info');
const bumbleControls = document.querySelector('#bumble-controls');
const treadmillValues = document.querySelector('#treadmill-values');
const securityRequest = document.querySelector('#security-request');

// Setup the app
const app = await setupSimpleApp('treadmill.py', bumbleControls, logToOutput);
app.on('scanning_updates', onScanningUpdates);
app.on('hr_updates', onHrUpdates);
app.on('connection_updates', onConnectionUpdates)
app.on('on_security_request', onSecurityRequest)
logToOutput('Click the Bluetooth button to start');

function onScanningUpdates(scanResults) {
    const items = scanResults.toJs({create_proxies : false}).map(entry => (
        { address: entry.address, address_type: entry.address_type, rssi: entry.rssi, data: entry.data }
    ));
    scanResults.destroy();
    scanList.listItems = items;
}

function onHrUpdates(hrResults) {
    const items = hrResults.toJs({create_proxies : false})
    treadmillValues.addValue({value: items.get('value'), time: items.get('time')})
    hrResults.destroy();
}

function onConnectButton(address) {
    app.do_connect(address)
}

function onSecurityRequest() {
    securityRequest.style.display = 'block'
}

function onPairButton(value) {
    app.do_security_request_response(value)
    securityRequest.style.display = 'none'
}

function onConnectionUpdates(connection) {
    const items = connection.toJs({create_proxies : false})
    console.log(items)
    connection.destroy();
    scanList.style.display = 'none'
    connectionInfo.style.display = 'block'
    connectionInfo.handle = items.get('handle')
    connectionInfo.role = items.get('role')
    connectionInfo.self_address = items.get('self_address')
    connectionInfo.peer_address = items.get('peer_address')
    connectionInfo.is_encrypted = items.get('is_encrypted')
}