# CA_RuleFinder

Project Title: Cryptography System Based on the Use of Multidimensional Cellular Automata

Student and University: Yevhenii Suturin, Group 432, National University “Odesa Law Academy”, Faculty of Cybersecurity

## Project Overview
The multidimensional cellular automata cryptography system is designed for generating pseudorandom bit sequences and using them for data encryption. The project implements automated search for suitable cellular automata rules and statistical analysis of generated bit streams. The NIST SP 800-22 test suite is used to evaluate the cryptographic properties of generated sequences.

## Main Functionality
- Generation of pseudorandom bit streams based on cellular automata.
- XOR encryption and decryption of text messages.
- Automatic statistical analysis and NIST testing of generated bit sequences.

## Technology Stack
- Language: Python 3.10+.
- Libraries: tkinter, hashlib, json, random, statistics.
- Analysis Tools: NIST SP 800-22 Statistical Test Suite.
- Environment: Windows / Linux.

## Deployment Instructions
1. Requirements: Python 3.10+
2. Clone the repository:
```bash
git clone https://github.com/username/project-name.git
cd project-name
```
3. Install required dependencies:
```bash
pip install -r requirements.txt
```
4. Install and configure the NIST SP 800-22 Statistical Test Suite.
5. Specify the path to the NIST test directory in the application configuration.
6. Run the application:
```bash
python3 main.py
```

## Project Structure
```text
├── src/                  # Main application source code
├── screenshots/          # Screenshots used in README
├── rules/                # Cellular automata rules
├── cache/                # Cached search results
├── config/               # Configuration files
├── requirements.txt
├── main.py
└── README.md
```
