# Cybercrime Evidence Management System

A Python-based Cybercrime Evidence Management System designed to securely manage digital evidence, ensure integrity, and support forensic investigations.

## Features
- Create and manage cybercrime cases
- Add digital evidence to cases
- Generate SHA-256 hashes for evidence integrity
- Verify evidence tampering
- Maintain basic chain of custody
- Generate forensic reports
- Digitally sign reports for authenticity

## Technologies Used
- Python
- SQLite
- SHA-256 hashing
- Digital signatures (RSA)

## Project Structure
- main.py – Core application logic
- keygen.py – Digital key generation
- evidence/ – Evidence storage (ignored in Git)
- reports/ – Generated reports (ignored in Git)

## Security Considerations
Sensitive files such as private keys, reports, and evidence are excluded using `.gitignore` to follow secure development practices.

## Use Case
This project demonstrates how digital evidence can be securely handled during cybercrime investigations while maintaining integrity and authenticity.
