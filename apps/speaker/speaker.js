(function () {
    'use strict';

const channelUrl = ((window.location.protocol === "https:") ? "wss://" : "ws://") + window.location.host + "/channel";
let channelSocket;
let connectionText;
let codecText;
let packetsReceivedText;
let bytesReceivedText;
let bitrateText;
let streamStateText;
let connectionStateText;
let controlsDiv;
let audioOnButton;
let audioDecoder;
let audioCodec;
let audioContext;
let audioAnalyzer;
let audioFrequencyBinCount;
let audioFrequencyData;
let nextAudioStartPosition = 0;
let audioStartTime = 0;
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
let bitrateSamples = [];

const FFT_WIDTH = 800;
const FFT_HEIGHT = 256;
const BANDWIDTH_WIDTH = 500;
const BANDWIDTH_HEIGHT = 100;
const BITRATE_WINDOW = 30;

function init() {
    initUI();
    initAudioContext();
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
    bitrateText = document.getElementById("bitrate");
    streamStateText = document.getElementById("streamStateText");
    connectionStateText = document.getElementById("connectionStateText");
    audioSupportMessageText = document.getElementById("audioSupportMessageText");

    audioOnButton.onclick = () => startAudio();

    setConnectionText("");

    requestAnimationFrame(onAnimationFrame);
}

function initAudioContext() {
    audioContext = new AudioContext();
    audioContext.onstatechange = () => console.log("AudioContext state:", audioContext.state);
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
    bandwidthBinCount = BANDWIDTH_WIDTH / 2;
    bandwidthBins = [];
    bitrateSamples = [];

    audioAnalyzer = audioContext.createAnalyser();
    audioAnalyzer.fftSize = 128;
    audioFrequencyBinCount = audioAnalyzer.frequencyBinCount;
    audioFrequencyData = new Uint8Array(audioFrequencyBinCount);

    audioAnalyzer.connect(audioContext.destination)
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
        const bytesReceived = bandwidthBins[t]
        const lineHeight = (bytesReceived / 1000) * BANDWIDTH_HEIGHT;
        bandwidthCanvasContext.fillRect(t * 2, BANDWIDTH_HEIGHT - lineHeight, 2, lineHeight);
    }

    // Display again at the next frame
    requestAnimationFrame(onAnimationFrame);
}

async function startAudio() {
    try {
        console.log("starting audio...");
        audioOnButton.disabled = true;
        audioState = "starting";
        audioContext.resume();
        console.log("audio started");
        audioState = "playing";
    } catch(error) {
        console.error(`play failed: ${error}`);
        audioState = "stopped";
        audioOnButton.disabled = false;
    }
}

function onDecodedAudio(audioData) {
    const bufferSource = audioContext.createBufferSource()

    const now = audioContext.currentTime;
    let nextAudioStartTime = audioStartTime + (nextAudioStartPosition / audioData.sampleRate);
    if (nextAudioStartTime < now) {
        console.log("starting new audio time base")
        audioStartTime = now;
        nextAudioStartTime = now;
        nextAudioStartPosition = 0;
    } else {
        console.log(`audio buffer scheduled in ${nextAudioStartTime - now}`)
    }

    const audioBuffer = audioContext.createBuffer(
        audioData.numberOfChannels,
        audioData.numberOfFrames,
        audioData.sampleRate
    );

    for (let channel = 0; channel < audioData.numberOfChannels; channel++) {
        audioData.copyTo(
            audioBuffer.getChannelData(channel),
            {
                planeIndex: channel,
                format: "f32-planar"
            }
        )
    }

    bufferSource.buffer = audioBuffer;
    bufferSource.connect(audioAnalyzer)
    bufferSource.start(nextAudioStartTime);
    nextAudioStartPosition += audioData.numberOfFrames;
}

function onCodecError(error) {
    console.log("Codec error:", error)
}

async function onAudioPacket(packet) {
    packetsReceived += 1;
    packetsReceivedText.innerText = packetsReceived;
    bytesReceived += packet.byteLength;
    bytesReceivedText.innerText = bytesReceived;

    bandwidthBins[bandwidthBins.length] = packet.byteLength;
    if (bandwidthBins.length > bandwidthBinCount) {
        bandwidthBins.shift();
    }
    bitrateSamples[bitrateSamples.length] = {ts: Date.now(), bytes: packet.byteLength}
    if (bitrateSamples.length > BITRATE_WINDOW) {
        bitrateSamples.shift();
    }
    if (bitrateSamples.length >= 2) {
        const windowBytes = bitrateSamples.reduce((accumulator, x) => accumulator + x.bytes, 0) - bitrateSamples[0].bytes;
        const elapsed = bitrateSamples[bitrateSamples.length-1].ts - bitrateSamples[0].ts;
        const bitrate = Math.floor(8 * windowBytes / elapsed)
        bitrateText.innerText = `${bitrate} kb/s`
    }

    if (audioState == "stopped") {
        return;
    }

    if (audioDecoder === undefined) {
        let audioConfig;
        if (audioCodec == 'aac') {
            audioConfig = {
                codec: 'mp4a.40.2',
                sampleRate: 44100, // ignored
                numberOfChannels: 2, // ignored
            }
        } else if (audioCodec == 'opus') {
            audioConfig = {
                codec: 'opus',
                sampleRate: 48000, // ignored
                numberOfChannels: 2, // ignored
            }
        }
        audioDecoder = new AudioDecoder({ output: onDecodedAudio, error: onCodecError });
        audioDecoder.configure(audioConfig)
    }

    const encodedAudio = new EncodedAudioChunk({
        type: "key",
        data: packet,
        timestamp: 0,
        transfer: [packet],
    });

    audioDecoder.decode(encodedAudio);
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

async function onHelloMessage(params) {
    codecText.innerText = params.codec;

    if (params.codec == "aac" || params.codec == "opus") {
        audioCodec = params.codec
        audioSupportMessageText.innerText = "";
        audioSupportMessageText.style.display = "none";
    } else {
        audioOnButton.disabled = true;
        audioSupportMessageText.innerText = "Only AAC and Opus can be played, audio will be disabled";
        audioSupportMessageText.style.display = "inline-block";
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