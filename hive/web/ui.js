import {LitElement, html} from 'https://cdn.jsdelivr.net/gh/lit/dist@2/core/lit-core.min.js';

class BumbleControls extends LitElement {
    constructor() {
        super();
        this.bumbleLoaded = false;
        this.connected = false;
    }

    render() {
        return html`
            <link rel="stylesheet" href="https://fonts.googleapis.com/icon?family=Material+Icons">
            <dialog id="settings-dialog" @close=${this.onSettingsDialogClose} style="font-family:sans-serif">
                <p>WebSocket URL for HCI transport</p>
                <form>
                    <input id="settings-hci-url-input" type="text" size="50"></input>
                    <button value="cancel" formmethod="dialog">Cancel</button>
                    <button @click=${this.saveSettings}>Save</button>
                </form>
            </dialog>
            <button @click=${this.openSettingsDialog} class="mdc-icon-button material-icons"><div class="mdc-icon-button__ripple"></div>settings</button>
            <button @click=${this.connectBluetooth} ?disabled=${!this.canConnect()} class="mdc-icon-button material-icons"><div class="mdc-icon-button__ripple"></div>bluetooth</button>
            <button @click=${this.stop} ?disabled=${!this.connected} class="mdc-icon-button material-icons"><div class="mdc-icon-button__ripple"></div>stop</button>
        `
    }

    get settingsHciUrlInput() {
        return this.renderRoot.querySelector('#settings-hci-url-input');
    }

    get settingsDialog() {
        return this.renderRoot.querySelector('#settings-dialog');
    }

    canConnect() {
        return this.bumbleLoaded && !this.connected && this.getHciUrl();
    }

    getHciUrl() {
        // Look for a URL parameter setting first.
        const params = (new URL(document.location)).searchParams;
        let hciWsUrl = params.get("hci");
        if (hciWsUrl) {
          return hciWsUrl;
        }

        // Try to load the setting from storage.
        hciWsUrl = localStorage.getItem("hciWsUrl");
        if (hciWsUrl) {
          return hciWsUrl;
        }

        // Finally, default to nothing.
        return null;
    }

    openSettingsDialog() {
        const hciUrl = this.getHciUrl();
        if (hciUrl) {
            this.settingsHciUrlInput.value = hciUrl;
        } else {
          // Start with default, assuming port 7681.
          this.settingsHciUrlInput.value = "ws://localhost:7681/v1/websocket/bt"
        }
        this.settingsDialog.showModal();
    }

    onSettingsDialogClose() {
        if (this.settingsDialog.returnValue === "cancel") {
            return;
        }
        if (this.settingsHciUrlInput.value) {
            localStorage.setItem("hciWsUrl", this.settingsHciUrlInput.value);
        } else {
            localStorage.removeItem("hciWsUrl");
        }

        this.requestUpdate();
    }

    saveSettings(event) {
        event.preventDefault();
        this.settingsDialog.close(this.settingsHciUrlInput.value);
    }

    async connectBluetooth() {
        this.connected = await this.connector(this.getHciUrl());
        this.requestUpdate();
    }

    async stop() {
        await this.stopper();
        this.connected = false;
        this.requestUpdate();
    }

    onBumbleLoaded() {
        this.bumbleLoaded = true;
        this.requestUpdate();
    }
}
customElements.define('bumble-controls', BumbleControls);
