# Network Port Scanner (Desktop App)

A modern, multi-threaded desktop application designed for network security auditing and port scanning. Built with Python using CustomTkinter for the graphical user interface and the native socket library for low-level network communications.

This tool allows users to scan a specific IP address or hostname across a customizable range of TCP ports to identify open ports and detect the network services running behind them.

---

## Features

* **Modern GUI:** Built with a clean, dark-themed user interface utilizing CustomTkinter components.
* **Multi-Threaded Execution:** The scanning core runs on a separate background thread (using Python's `threading` module), preventing the UI from freezing or becoming unresponsive during deep scans.
* **Service Identification:** Automatically resolves standard network service names (e.g., HTTP, FTP, SSH) for discovered open ports using system port databases.
* **Real-Time Progress Tracking:** Features an animated progress bar and a scrollable console log that updates instantly as each port is evaluated.
* **Scan Interruption:** Includes a responsive control flow allowing users to safely abort the active scanning process at any moment.

---

## Technical Architecture & Concepts

### 1. Network Sockets
The application uses TCP stream sockets (`socket.AF_INET`, `socket.AF_STREAM`) to perform a TCP Connect scan. It utilizes the `connect_ex()` method, which handles the standard three-way handshake and returns an explicit error code rather than raising an exception:
* An error code of `0` indicates a successful connection, meaning the target port is **open** and listening.
* Any non-zero error code implies the port is **closed**, filtered, or unreachable.

### 2. Thread Management
To maintain a responsive HMI (Human-Machine Interface), the application isolates the network I/O loop from the main GUI thread. This asynchronous behavior ensures that event polling, window scaling, and progress bar updates remain fluid while the background thread waits for network timeouts.

---
