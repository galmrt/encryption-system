# Project Encryption
This repository contains the code for encryption Project.

To test implementation, run `go test -v` inside of the `client_test` directory.

# Secure File Storage and Access Control System

## Overview
This project provides a secure file storage, retrieval, sharing, and access revocation system. It ensures:
- User authentication with encrypted credentials
- Secure file storage using symmetric and asymmetric encryption
- File integrity via digital signatures
- Controlled file sharing with access revocation

## Features
- **User Management**
  - `InitUser(username, password)`: Creates a new user with secure credentials.
  - `GetUser(username, password)`: Authenticates and retrieves user data.
- **File Operations**
  - `StoreFile(filename, content)`: Securely stores or overwrites a file.
  - `LoadFile(filename)`: Retrieves and decrypts stored file content.
  - `AppendToFile(filename, content)`: Appends data securely to an existing file.
- **File Sharing and Access Control**
  - `CreateInvitation(filename, recipientUsername)`: Generates a secure file-sharing invitation.
  - `AcceptInvitation(senderUsername, invitationPtr, filename)`: Accepts a shared file and registers access.
  - `RevokeAccess(filename, recipientUsername)`: Removes file access for a specified user.


## Security Considerations
- **Encryption:**
  - Symmetric encryption (AES) is used for securing stored files.
  - Public-key encryption (RSA) is used for sharing invitations.
- **Integrity Protection:**
  - Digital signatures ensure file integrity.
  - Hashing is used to prevent unauthorized access.
- **Access Control:**
  - Users can revoke file access at any time.
  - Unauthorized users cannot read or modify files without valid keys.

## License
This project is licensed under the MIT License.

## Author
Developed as part of a secure file storage system for CS16 coursework.

