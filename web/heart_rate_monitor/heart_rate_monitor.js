import {setupSimpleApp} from '../bumble.js';

const logOutput = document.querySelector('#log-output');
function logToOutput(message) {
    console.log(message);
    logOutput.value += message + '\n';
}

let heartRate = 60;
const heartRateText = document.querySelector('#hr-value')

function setHeartRate(newHeartRate) {
    heartRate = newHeartRate;
    heartRateText.innerHTML = heartRate;
    app.set_heart_rate(heartRate);
}

// Setup the UI
const bumbleControls = document.querySelector('#bumble-controls');
document.querySelector('#hr-up-button').addEventListener('click', () => {
    setHeartRate(heartRate + 1);
})
document.querySelector('#hr-down-button').addEventListener('click', () => {
    setHeartRate(heartRate - 1);
})

// Setup the app
const app = await setupSimpleApp('heart_rate_monitor.py', bumbleControls, logToOutput);
logToOutput('Click the Bluetooth button to start');

