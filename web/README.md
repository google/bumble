Bumble For Web Browsers
=======================

Early prototype the consists of running the Bumble stack in a web browser
environment, using [pyodide](https://pyodide.org/)

Two examples are included here:
 
  * scanner - a simple scanner
  * speaker - a pure-web-based version of the Speaker app

Both examples rely on the shared code in `bumble.js`.

Running The Examples
--------------------

To run the examples, you will need an HTTP server to serve the HTML and JS files, and
and a WebSocket server serving an HCI transport.

For HCI over WebSocket, recent versions of the `netsim` virtual controller support it,
or you may use the Bumble HCI Bridge app to bridge a WebSocket server to a virtual
controller using some other transport (ex: `python apps/hci_bridge.py ws-server:_:9999 usb:0`).

For HTTP, start an HTTP server with the `web` directory as its
root. You can use the invoke task `inv web.serve` for convenience.

In a browser, open either `scanner/scanner.html` or `speaker/speaker.html`.
You can pass optional query parameters:

  * `package` may be set to point to a local build of Bumble (`.whl` files).
     The filename must be URL-encoded of course, and must be located under
     the `web` directory (the HTTP server won't serve files not under its
     root directory).
  * `hci` may be set to specify a non-default WebSocket URL to use as the HCI
     transport (the default is: `"ws://localhost:9922/hci`). This also needs
     to be URL-encoded.

Example:
    With a local HTTP server running on port 8000, to run the `scanner` example
    with a locally-built Bumble package `../bumble-0.0.163.dev5+g6f832b6.d20230812-py3-none-any.whl` 
    (assuming that `bumble-0.0.163.dev5+g6f832b6.d20230812-py3-none-any.whl` exists under the `web`
    directory and the HCI WebSocket transport at `ws://localhost:9999/hci`, the URL with the 
    URL-encoded query parameters would be:
    `http://localhost:8000/scanner/scanner.html?hci=ws%3A%2F%2Flocalhost%3A9999%2Fhci&package=..%2Fbumble-0.0.163.dev5%2Bg6f832b6.d20230812-py3-none-any.whl`


NOTE: to get a local build of the Bumble package, use `inv build`, the built `.whl` file can be found in the `dist` directory. 
Make a copy of the built `.whl` file in the `web` directory.