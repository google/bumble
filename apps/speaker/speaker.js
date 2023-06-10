(function () {
    'use strict';

const channelUrl = ((window.location.protocol === "https:") ? "wss://" : "ws://") + window.location.host + "/channel";
let channelSocket;
let connectionText;
let codecText;
let packetsReceivedText;
let bytesReceivedText;
let streamStateText;
let connectionStateText;
let controlsDiv;
let audioOnButton;
let mediaSource;
let sourceBuffer;
let audioElement;
let audioContext;
let audioAnalyzer;
let audioFrequencyBinCount;
let audioFrequencyData;
let packetsReceived = 0;
let bytesReceived = 0;
let audioState = "stopped";
let streamState = "IDLE";
let audioSupportMessageText;
let fftCanvas;
let fftCanvasContext;
let bandwidthCanvas;
let bandwidthCanvasContext;
let bandwidthBinCount;
let bandwidthBins = [];

const FFT_WIDTH = 800;
const FFT_HEIGHT = 256;
const BANDWIDTH_WIDTH = 500;
const BANDWIDTH_HEIGHT = 100;

function hexToBytes(hex) {
    return Uint8Array.from(hex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
}

function init() {
    initUI();
    initMediaSource();
    initAudioElement();
    initAnalyzer();

    connect();
}

function initUI() {
    controlsDiv = document.getElementById("controlsDiv");
    controlsDiv.style.visibility = "hidden";
    connectionText = document.getElementById("connectionText");
    audioOnButton = document.getElementById("audioOnButton");
    codecText = document.getElementById("codecText");
    packetsReceivedText = document.getElementById("packetsReceivedText");
    bytesReceivedText = document.getElementById("bytesReceivedText");
    streamStateText = document.getElementById("streamStateText");
    connectionStateText = document.getElementById("connectionStateText");
    audioSupportMessageText = document.getElementById("audioSupportMessageText");

    audioOnButton.onclick = () => startAudio();

    setConnectionText("");

    requestAnimationFrame(onAnimationFrame);
}

function initMediaSource() {
    mediaSource = new MediaSource();
    mediaSource.onsourceopen = onMediaSourceOpen;
    mediaSource.onsourceclose = onMediaSourceClose;
    mediaSource.onsourceended = onMediaSourceEnd;
}

function initAudioElement() {
    audioElement = document.getElementById("audio");
    audioElement.src = URL.createObjectURL(mediaSource);
    // audioElement.controls = true;
}

function initAnalyzer() {
    fftCanvas = document.getElementById("fftCanvas");
    fftCanvas.width = FFT_WIDTH
    fftCanvas.height = FFT_HEIGHT
    fftCanvasContext = fftCanvas.getContext('2d');
    fftCanvasContext.fillStyle = "rgb(0, 0, 0)";
    fftCanvasContext.fillRect(0, 0, FFT_WIDTH, FFT_HEIGHT);

    bandwidthCanvas = document.getElementById("bandwidthCanvas");
    bandwidthCanvas.width = BANDWIDTH_WIDTH
    bandwidthCanvas.height = BANDWIDTH_HEIGHT
    bandwidthCanvasContext = bandwidthCanvas.getContext('2d');
    bandwidthCanvasContext.fillStyle = "rgb(255, 255, 255)";
    bandwidthCanvasContext.fillRect(0, 0, BANDWIDTH_WIDTH, BANDWIDTH_HEIGHT);
}

function startAnalyzer() {
    // FFT
    if (audioElement.captureStream !== undefined) {
        audioContext = new AudioContext();
        audioAnalyzer = audioContext.createAnalyser();
        audioAnalyzer.fftSize = 128;
        audioFrequencyBinCount = audioAnalyzer.frequencyBinCount;
        audioFrequencyData = new Uint8Array(audioFrequencyBinCount);
        const stream = audioElement.captureStream();
        const source = audioContext.createMediaStreamSource(stream);
        source.connect(audioAnalyzer);
    }

    // Bandwidth
    bandwidthBinCount = BANDWIDTH_WIDTH / 2;
    bandwidthBins = [];
}

function setConnectionText(message) {
    connectionText.innerText = message;
    if (message.length == 0) {
        connectionText.style.display = "none";
    } else {
        connectionText.style.display = "inline-block";
    }
}

function setStreamState(state) {
    streamState = state;
    streamStateText.innerText = streamState;
}

function onAnimationFrame() {
    // FFT
    if (audioAnalyzer !== undefined) {
        audioAnalyzer.getByteFrequencyData(audioFrequencyData);
        fftCanvasContext.fillStyle = "rgb(0, 0, 0)";
        fftCanvasContext.fillRect(0, 0, FFT_WIDTH, FFT_HEIGHT);
        const barCount = audioFrequencyBinCount;
        const barWidth = (FFT_WIDTH / audioFrequencyBinCount) - 1;
        for (let bar = 0; bar < barCount; bar++) {
            const barHeight = audioFrequencyData[bar];
            fftCanvasContext.fillStyle = `rgb(${barHeight / 256 * 200 + 50}, 50, ${50 + 2 * bar})`;
            fftCanvasContext.fillRect(bar * (barWidth + 1), FFT_HEIGHT - barHeight, barWidth, barHeight);
        }
    }

    // Bandwidth
    bandwidthCanvasContext.fillStyle = "rgb(255, 255, 255)";
    bandwidthCanvasContext.fillRect(0, 0, BANDWIDTH_WIDTH, BANDWIDTH_HEIGHT);
    bandwidthCanvasContext.fillStyle = `rgb(100, 100, 100)`;
    for (let t = 0; t < bandwidthBins.length; t++) {
        const lineHeight = (bandwidthBins[t] / 1000) * BANDWIDTH_HEIGHT;
        bandwidthCanvasContext.fillRect(t * 2, BANDWIDTH_HEIGHT - lineHeight, 2, lineHeight);
    }

    // Display again at the next frame
    requestAnimationFrame(onAnimationFrame);
}

function onMediaSourceOpen() {
    console.log(this.readyState);
    sourceBuffer = mediaSource.addSourceBuffer("audio/aac");
}

function onMediaSourceClose() {
    console.log(this.readyState);
}

function onMediaSourceEnd() {
    console.log(this.readyState);
}

async function startAudio() {
    try {
        console.log("starting audio...");
        audioOnButton.disabled = true;
        audioState = "starting";
        await audioElement.play();
        console.log("audio started");
        audioState = "playing";
        startAnalyzer();
    } catch(error) {
        console.error(`play failed: ${error}`);
        audioState = "stopped";
        audioOnButton.disabled = false;
    }
}

function onAudioPacket(packet) {
    if (audioState != "stopped") {
        // Queue the audio packet.
        sourceBuffer.appendBuffer(packet);
    }

    packetsReceived += 1;
    packetsReceivedText.innerText = packetsReceived;
    bytesReceived += packet.byteLength;
    bytesReceivedText.innerText = bytesReceived;

    bandwidthBins[bandwidthBins.length] = packet.byteLength;
    if (bandwidthBins.length > bandwidthBinCount) {
        bandwidthBins.shift();
    }
}

function onChannelOpen() {
    console.log('channel OPEN');
    setConnectionText("");
    controlsDiv.style.visibility = "visible";

    // Handshake with the backend.
    sendMessage({
        type: "hello"
    });
}

function onChannelClose() {
    console.log('channel CLOSED');
    setConnectionText("Connection to CLI app closed, restart it and reload this page.");
    controlsDiv.style.visibility = "hidden";
}

function onChannelError(error) {
    console.log(`channel ERROR: ${error}`);
    setConnectionText(`Connection to CLI app error ({${error}}), restart it and reload this page.`);
    controlsDiv.style.visibility = "hidden";
}

function onChannelMessage(message) {
    if (typeof message.data === 'string' || message.data instanceof String) {
        // JSON message.
        const jsonMessage = JSON.parse(message.data);
        console.log(`channel MESSAGE: ${message.data}`);

        // Dispatch the message.
        const handlerName = `on${jsonMessage.type.charAt(0).toUpperCase()}${jsonMessage.type.slice(1)}Message`
        const handler = messageHandlers[handlerName];
        if (handler !== undefined) {
            const params = jsonMessage.params;
            if (params === undefined) {
                params = {};
            }
            handler(params);
        } else {
            console.warn(`unhandled message: ${jsonMessage.type}`)
        }
    } else {
        // BINARY audio data.
        onAudioPacket(message.data);
    }
}

function onHelloMessage(params) {
    codecText.innerText = params.codec;
    if (params.codec != "aac") {
        audioOnButton.disabled = true;
        audioSupportMessageText.innerText = "Only AAC can be played, audio will be disabled";
        audioSupportMessageText.style.display = "inline-block";
    } else {
        audioSupportMessageText.innerText = "";
        audioSupportMessageText.style.display = "none";
    }
    if (params.streamState) {
        setStreamState(params.streamState);
    }
}

function onStartMessage(params) {
    setStreamState("STARTED");
}

function onStopMessage(params) {
    setStreamState("STOPPED");
}

function onSuspendMessage(params) {
    setStreamState("SUSPENDED");
}

function onConnectionMessage(params) {
    connectionStateText.innerText = `CONNECTED: ${params.peer_name} (${params.peer_address})`;
}

function onDisconnectionMessage(params) {
    connectionStateText.innerText = "DISCONNECTED";
}

function sendMessage(message) {
    channelSocket.send(JSON.stringify(message));
}

function connect() {
    console.log("connecting to CLI app");

    channelSocket = new WebSocket(channelUrl);
    channelSocket.binaryType = "arraybuffer";
    channelSocket.onopen = onChannelOpen;
    channelSocket.onclose = onChannelClose;
    channelSocket.onerror = onChannelError;
    channelSocket.onmessage = onChannelMessage;
}

const messageHandlers = {
    onHelloMessage,
    onStartMessage,
    onStopMessage,
    onSuspendMessage,
    onConnectionMessage,
    onDisconnectionMessage
}

window.onload = (event) => {
    init();
}

}());