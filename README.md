Password Risk Analyzer

A lightweight, 100% offline password security evaluator built with Python and Flask. It assesses password exposure and guessability locally in your browser without sending any data over the network.

Why This Matters

Weak, predictable, or reused passwords are one of the leading causes of account compromise via brute-force attacks and credential stuffing. This tool provides immediate local feedback so you can evaluate password resilience safely.

Features

- 100% Offline & Private: Runs strictly on localhost (http://127.0.0.1/) with zero external API calls or logging.
- Common-Password Screening: Screens inputs against a local database (common_passwords.txt) of known weak and leaked passwords.
-  Entropy Estimation: Calculates randomness in bits using character pool diversity and password length (L2(N)).
- Guessability Heuristics: Flags short lengths (< 12 characters), single-character-set passwords, repeated characters (aaa, 111), and keyboard sequences (qwerty, 123456).
- Actionable Guidance: Classifies overall strength (Very Weak, Weak, Moderate, Strong) and provides tailored, plain-English recommendations.
- Show / Hide Toggle: Client-side visibility toggle for verifying complex passphrases without leaving the browser.

Project Structure


Password-leak-risk-analyzer-main/
├── app.py                  # Local Flask web server and request routing

├── password_analyzer.py    # Offline screening, entropy math, heuristics, and risk engine

├── common_passwords.txt    # Local list of known weak/leaked passwords

├── templates/
│   └── index.html          # Minimalist HTML interface and visibility toggle

├── static/
│   └── style.css           # Clean, distraction-free stylesheet

└── README.md               # Project documentation


Quick Start (Windows)

1. Clone or download the repository and open the folder in VS Code.
2. Install Flask (the only external dependency):
   `powershell
   python -m pip install flask
   
3. Start the local server:
   powershell
   python app.py
   
4. Open in your browser: Hold Ctrl and click http://127.0.0.1:5000 in the terminal.
