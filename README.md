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

## Screenshots
### Main Application Window

The main application window provides interaction with the multidimensional cellular automata system. The user can select rules, generate new fields, launch iterations, perform statistical analysis, and execute encryption or decryption operations.

![Main Window](screenshots/main_window.png)
---

### Rule Management System

The rule management module allows users to create, edit, delete, and review cellular automata rules. Each rule contains information about active configurations and transition patterns used during field evolution.

![Rules List](screenshots/rules_list.png)
---

### Cellular Automata Rule Visualization

The system includes a graphical rule editor for all 256 neighborhood configurations. Each pattern defines the next state of the central cell based on neighboring values.

![Rule Visualization](screenshots/rule_visualization.png)
---

### Rule Editing Interface

The editor allows manual modification of transition results for every local configuration. This enables experimental analysis of different automata behaviors and statistical properties.

![Rule Editor](screenshots/rule_editor.png)
---

### NIST Statistical Test Results

The application performs statistical analysis using the NIST SP 800-22 Rev. 1a test suite. The generated pseudorandom sequences are evaluated according to entropy, frequency balance, Hamming distance, and additional randomness criteria.

![NIST Results](screenshots/nist_rule_result.png)

- Monobit Test is responsible for checking the overall ratio of zeros and ones in the entire bit sequence. If the number of zeros and ones differs significantly, it indicates that the sequence has a noticeable bias and is not sufficiently random.

- Frequency Within Block Test checks the balance of zeros and ones not across the entire sequence at once, but within separate blocks. This test helps identify situations where the overall balance appears normal, but individual sections of the sequence contain uneven bit distribution.
- Runs Test analyzes the number of consecutive runs of identical bits, meaning sequences of zeros or ones appearing continuously. If there are too many or too few runs, this may indicate excessive randomness or, conversely, structural regularity.
- Longest Run Ones In A Block Test determines the longest sequences of ones within individual blocks. It shows whether excessively long groups of ones appear in the sequence, which may indicate patterns or generator instability.
- Binary Matrix Rank Test evaluates linear dependencies between fragments of the bit sequence. For this purpose, the sequence is represented as binary matrices and their rank is analyzed. If the rank is frequently lower than expected, it may indicate the presence of linear dependencies.
- Discrete Fourier Transform Test, also known as the Spectral Test, checks for periodic structures within the sequence. It helps detect repeating patterns that may not be visible through simple balance analysis of zeros and ones.
- Non-overlapping Template Matching Test searches for predefined non-overlapping patterns within the sequence. The test evaluates whether specific bit combinations occur too frequently or too rarely.
- Overlapping Template Matching Test also checks for pattern occurrences, but allows overlaps between them. This makes the test more sensitive to repeating structures that may be hidden within the sequence.
- Universal Statistical Test evaluates the compressibility of the sequence. If the sequence can be compressed efficiently, it means that patterns exist within it, indicating insufficient randomness.
- Linear Complexity Test determines the complexity of the sequence from the perspective of a linear feedback shift register. The lower the linear complexity, the easier it is to predict the sequence, which is undesirable for cryptographic applications.
- Serial Test analyzes the frequency of occurrence of all possible bit combinations of a given length. Its purpose is to verify whether short bit patterns are distributed uniformly.
- Approximate Entropy Test evaluates the regularity and predictability of patterns within the sequence. If certain combinations appear more frequently than expected, the test may fail.
- Cumulative Sums Test checks the cumulative deviation of the sequence from the ideal balance. It interprets bits as upward or downward steps and determines how far the sequence deviates from zero balance.
- Random Excursions Test analyzes the behavior of a random walk generated from the bit sequence. It checks how often the cumulative sum returns to particular states.
- Random Excursions Variant Test is an extension of the previous test. It evaluates the number of visits to individual states in the random walk and allows deeper analysis of the sequence structure.
---

### Comparison of Field Generation Approaches

The system supports evaluation of multiple field generation approaches, including balanced and filtered configurations. Statistical characteristics and NIST results are displayed for comparative analysis.

![Generation Comparison](screenshots/field_generation_comparison.png)
---

### Encryption Process

The application converts plaintext messages into binary representation using UTF-8 encoding, where each character is represented as an eight-bit block. A pseudorandom bit stream generated by the multidimensional cellular automaton is then used for encryption. The XOR operation is applied between the message bits and the generated bit stream, resulting in encrypted data that is additionally displayed in hexadecimal format for convenient storage and transmission.

![Encryption Process](screenshots/encryption_process.png)
---

### Decryption Result

The decryption process is performed by applying the XOR operation again between the encrypted data and the same pseudorandom bit stream generated by the cellular automaton. Since XOR is a symmetric operation, using the identical sequence allows complete restoration of the original plaintext message without data loss. The application displays both intermediate binary blocks and the final decrypted text result.

![Decryption Result](screenshots/decryption_process.png)

## Project Structure
```text
├── src/                  # Source code
├── screenshots/          # Screenshots used in README
├── rules/                # Saved cellular automata rules
├── requirements.txt
└── README.md
```

## Publication
Boyko V. D., Suturin Y. V. Encryption Procedure Using Two-Dimensional Cellular Automata // Cybersecurity in the Modern World: Current Challenges: Proceedings of the VI International Scientific and Practical Conference, November 28, 2025. — Odesa: National University “Odesa Law Academy”, 2025. — pp. 90–93.
[Read Publication](https://dspace.onua.edu.ua/handle/123456789/0000)
