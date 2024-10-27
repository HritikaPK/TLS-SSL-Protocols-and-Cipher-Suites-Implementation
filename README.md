# About

This project explores and implements key aspects of Secure Sockets Layer (SSL) and Transport Layer Security (TLS) protocols, focusing on handshake procedures and secure data transmission. By building key agreement functions in C++ and analyzing data transfer security, the project emphasizes the role of TLS/SSL in ensuring authentication, integrity, and encryption over TCP for tamper-proof communication.

## Project Structure

### TCP and SSL Classes
- **TCP Class**: Manages TCP/IP connections for client-server communication, as the foundation for SSL-secured interactions. It includes methods for socket operations, binding, and data transfer.
- **SSL Class**: Leverages TCP connections to build secure communication channels, handling key exchange, encryption, and mutual authentication. This class includes error-handling features to maintain data security and integrity.

## Cryptographic Schemes

1. **Diffie-Hellman Ephemeral (DHE)**: Enables secure key exchange, allowing the client and server to independently derive a shared secret without transmitting it directly, preventing interception.
2. **RSA**: Used in the TLS handshake to encrypt the Premaster Secret, ensuring confidentiality and authenticity.
3. **AES in CBC Mode**: After session establishment, AES in CBC mode provides symmetric encryption for ongoing data transmission, protecting integrity and confidentiality.

## Implementation Details

The project uses the **Crypto++** library for cryptographic functions, including DHE, RSA, and AES. Key SSL client and server components are implemented, with the following:
- `SslServer.accept()` establishing server connections.
- `SslClient.connect()` initiating client handshakes.

The **AES in CBC mode** handles encryption and decryption, securing sensitive data transfer. Through this setup, the project emphasizes improving network security and mitigating vulnerabilities in digital communication.

## Objectives

- **Implement Key Agreement Functions**: Develop secure key exchange and cryptographic functions in C++.
- **Analyze Security**: Examine the security implications of data transfer over SSL/TLS protocols.
- **Enhance Network Security**: Reduce vulnerabilities in digital communication through robust protocol implementation.

This project provides a practical exploration of SSL/TLS protocols, implementing core cryptographic techniques to secure application data, improve network security, and ensure robust data protection.
