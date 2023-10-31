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
                        ${Object.keys(this.listItems[0]).map(i => html`<th>${i}</th>`)}
                    </tr>
                </thead>
                <tbody>
                    ${this.listItems.map(i => html`
                    <tr>
                        ${Object.keys(i).map(key => html`<td>${i[key]}</td>`)}
                    </tr>
                    `)}
                </tbody>
            </table>
        `;
    }
}
customElements.define('scan-list', ScanList);

const logOutput = document.querySelector('#log-output');
function logToOutput(message) {
    console.log(message);
    logOutput.value += message + '\n';
}

function onUpdate(scanResults) {
    const items = scanResults.toJs({create_proxies : false}).map(entry => (
        { address: entry.address, address_type: entry.address_type, rssi: entry.rssi, data: entry.data }
    ));
    scanResults.destroy();
    scanList.listItems = items;
}

// Setup the UI
const scanList = document.querySelector('#scan-list');
const bumbleControls = document.querySelector('#bumble-controls');

// Setup the app
const app = await setupSimpleApp('scanner.py', bumbleControls, logToOutput);
app.on('update', onUpdate);
logToOutput('Click the Bluetooth button to start');
