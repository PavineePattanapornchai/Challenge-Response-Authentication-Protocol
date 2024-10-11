# Challenge-Response Authentication Protocol

## Overview
This project implements a basic challenge-response authentication protocol using salted password hashing. It demonstrates how a client and server can securely exchange messages to authenticate the client without directly transmitting the password. 

The system uses a challenge-response mechanism:
- The server stores salted, hashed passwords.
- The client responds to the server's challenge (random number and selected hash functions) by hashing the user's password with the provided salt and sending back a response.
- The server verifies the response by comparing it with the expected value.

## Key Features
- **Salted Password Hashing**: The password is hashed using a unique salt to prevent rainbow table attacks.
- **Multiple Hash Functions**: The system can select from SHA-256, SHA-512, or MD5 to hash the challenge-response.
- **Challenge-Response Mechanism**: Prevents replay attacks by incorporating a random number (N) in the authentication process.
- **Simple State Management**: Both client and server states are maintained to track the progress of the authentication.

## How It Works
1. The server stores a salted hash of the user's password.
2. The client sends the user ID to the server.
3. The server generates a challenge including a random number, a salt, and hash functions.
4. The client uses the salt and hash function to hash the password and send a response.
5. The server verifies the response by comparing it to the expected result.

## Installation and Running
To run this project:
1. Clone the repository.
2. Run the Python script to simulate the client-server authentication process.
