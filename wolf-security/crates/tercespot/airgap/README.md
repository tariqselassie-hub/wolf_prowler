# Air Gap Bridge

The **Air Gap Bridge** provides secure, hardware-enforced interfaces for the TersecPot system.

## Features
*   **udev Integration**: Monitors USB insertion events using `libudev`.
*   **Pulse Device**: Manages the handshake with simulated hardware tokens (Identity + Data).
*   **WORM Logging**: Ensures forensic accountability by logging all file transfers/rejections to a Write-Once-Read-Many (simulated) storage path.

## Usage
Used as a library by the `sentinel` daemon.
