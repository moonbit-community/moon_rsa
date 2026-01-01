# moon_rsa

A Moonbit implementation of RSA cryptographic algorithm, under development.

## Security Disclaimer ⚠️

This implementation of RSA cryptographic algorithm is provided **without any security endorsement** or professional certification. The moon_rsa project should be considered:
- An educational reference implementation
- Experimental cryptography software
- Not reviewed by third-party security experts

## Features

- **Key Generation** (Implemented)
  - Generate RSA public/private key pairs
  - Customizable key length (2048-bits minimum)
  - RSASSA-PSS signature generation & verification
  - RSAES-OAEP encryption/decryption

## Roadmap

- **Planned Features**
  - RSAES-PKCS1-v1_5 signature generation & verification
  - RSAES-PKCS1-v1_5 encryption/decryption
  - Implement all the requirements in FIPS 186.5

## Contributing

We welcome contributions! Please follow these steps:
1. Open an issue describing your proposed change
2. Fork the repository and create your feature branch
3. Add tests for any new functionality
4. Submit a pull request with documentation updates
