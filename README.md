# IDA Discord RPC Plugin

A Discord Rich Presence (RPC) integration for IDA Pro that displays your current reversing activity to your Discord profile.

## Description

This plugin automatically updates your Discord status to show:

* **Project Name:** The name of the file currently open in IDA.
* **Current Function:** The name of the function currently being analyzed.
* **Time Elapsed:** How long you've been working on the current session.

It is designed to be lightweight and runs automatically upon starting IDA Pro.

## Installation

1. **Install pypresence:**
The plugin requires the `pypresence` library. You can install it via pip:
`pip install pypresence`
*Note: Ensure you are installing it for the Python environment that IDA Pro uses.*
2. **Copy the Plugin:**
Copy `ida-rpc-plugin.py` into your IDA Pro `plugins` directory. Usually, this is:
* `C:\Program Files\IDA Professional 9.2\plugins` (Windows)
* `~/.idapro/plugins` (Linux/macOS)

## Usage

* **Automatic:** The plugin starts automatically when IDA Pro is launched.
* **Status Updates:** Your Discord status will update in real-time as you navigate through different functions in the disassembly.

## Contributing

Contributions are welcome! If you have suggestions for new features or find any bugs, please feel free to:

1. Fork the repository.
2. Create a new branch for your feature or fix.
3. Submit a pull request.

## License

This project is licensed under the APGLv3 License.
