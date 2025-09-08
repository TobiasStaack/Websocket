# Websocket (RFC 6455 Implementation)

This repository provides a **RFC 6455–compliant WebSocket implementation** with both C and C++ APIs, enabling effortless integration into a wide range of applications. It supports both standard (`ws://`) and secure (`wss://`) connections, utilizing [mbedTLS](https://tls.mbed.org/) for encrypted communication.

## Features

- **C and C++ Interfaces**  
  Flexible APIs in both C and C++ to match your project's language needs.

- **WS and WSS Support**  
  Full support for WebSocket (WS) and secure WebSocket (WSS) connections, secured via mbedTLS.

- **CMake-Based Build System**  
  Easy configuration and compilation using CMake for seamless integration.

- **Doxygen Documentation**  
  Auto-generate API documentation with Doxygen for better clarity and onboarding.

## Supported Extensions

- **permessage-deflate**  
  Adds support for compressed messages using the permessage-deflate WebSocket extension.

## ⚠Limitations

- **Sec-WebSocket-Protocol**  
  Currently not handled.

## Requirements

- C++11 or later
- CMake 3.0 or later
- **Optional**: Doxygen (for documentation)

## Building from Source

```bash
git clone https://github.com/Mylifeismyhome/Websocket.git
cd Websocket
mkdir build
cd build
cmake -DCMAKE_CXX_FLAGS="-m64" \
      -DENABLE_C_API=ON \
      -DENABLE_CPP_API=ON \
      -DBUILD_SHARED=ON \
      -DBUILD_STATIC=ON \
      -DEXAMPLE_C_API=ON \
      ../
make
```

This will build both static and shared libraries, along with optional examples if enabled.

## Building Documentation

To generate API documentation using Doxygen:

```bash
doxygen ./DoxyFile
```

> Make sure Doxygen is installed and available in your system's PATH.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
