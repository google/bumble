import { loadBumble, connectWebSocketTransport } from "../bumble.js";

(function () {
    'use strict';

    let codecText;
    let packetsReceivedText;
    let bytesReceivedText;
    let streamStateText;
    let connectionStateText;
    let errorText;
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
    let fftCanvas;
    let fftCanvasContext;
    let bandwidthCanvas;
    let bandwidthCanvasContext;
    let bandwidthBinCount;
    let bandwidthBins = [];
    let pyodide;

    const FFT_WIDTH = 800;
    const FFT_HEIGHT = 256;
    const BANDWIDTH_WIDTH = 500;
    const BANDWIDTH_HEIGHT = 100;


    function init() {
        initUI();
        initMediaSource();
        initAudioElement();
        initAnalyzer();
        initBumble();
    }

    function initUI() {
        audioOnButton = document.getElementById("audioOnButton");
        codecText = document.getElementById("codecText");
        packetsReceivedText = document.getElementById("packetsReceivedText");
        bytesReceivedText = document.getElementById("bytesReceivedText");
        streamStateText = document.getElementById("streamStateText");
        errorText = document.getElementById("errorText");
        connectionStateText = document.getElementById("connectionStateText");

        audioOnButton.onclick = () => startAudio();

        codecText.innerText = "AAC";
        setErrorText("");

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

    async function initBumble() {
        // Load pyodide
        console.log("Loading Pyodide");
        pyodide = await loadPyodide();

        // Load Bumble
        console.log("Loading Bumble");
        const params = (new URL(document.location)).searchParams;
        const bumblePackage = params.get("package") || "bumble";
        await loadBumble(pyodide, bumblePackage);

        console.log("Ready!")

        const hciWsUrl = params.get("hci") || "ws://localhost:9922/hci";
        try {
            // Create a WebSocket HCI transport
            let transport
            try {
                transport = await connectWebSocketTransport(pyodide, hciWsUrl);
            } catch (error) {
                console.error(error);
                setErrorText(error);
                return;
            }

            // Run the scanner example
            const script = await (await fetch("speaker.py")).text();
            await pyodide.runPythonAsync(script);
            const pythonMain = pyodide.globals.get("main");
            console.log("Starting speaker...");
            await pythonMain(transport.packet_source, transport.packet_sink, onEvent);
            console.log("Speaker running");
        } catch (err) {
            console.log(err);
        }
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

    function setErrorText(message) {
        errorText.innerText = message;
        if (message.length == 0) {
            errorText.style.display = "none";
        } else {
            errorText.style.display = "inline-block";
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
        } catch (error) {
            console.error(`play failed: ${error}`);
            audioState = "stopped";
            audioOnButton.disabled = false;
        }
    }

    async function onEvent(name, params) {
        // Dispatch the message.
        const handlerName = `on${name.charAt(0).toUpperCase()}${name.slice(1)}`
        const handler = eventHandlers[handlerName];
        if (handler !== undefined) {
            handler(params);
        } else {
            console.warn(`unhandled event: ${name}`)
        }
    }

    function onStart() {
        setStreamState("STARTED");
    }

    function onStop() {
        setStreamState("STOPPED");
    }

    function onSuspend() {
        setStreamState("SUSPENDED");
    }

    function onConnection(params) {
        connectionStateText.innerText = `CONNECTED: ${params.get('peer_name')} (${params.get('peer_address')})`;
    }

    function onDisconnection(params) {
        connectionStateText.innerText = "DISCONNECTED";
    }

    function onAudio(python_packet) {
        const packet = python_packet.toJs({create_proxies : false});
        python_packet.destroy();
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

    function onKeystoreupdate() {
        // Sync the FS
        pyodide.FS.syncfs(() => {
            console.log("FS synced out")
        });
    }

    const eventHandlers = {
        onStart,
        onStop,
        onSuspend,
        onConnection,
        onDisconnection,
        onAudio,
        onKeystoreupdate
    }

    window.onload = (event) => {
        init();
    }

}());