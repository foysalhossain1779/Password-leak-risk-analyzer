# Password Leak Risk Analyzer (Offline) — Python

A lightweight offline command-line tool that evaluates password security risk using
common-password screening, guessability heuristics, and entropy estimation.

## Why this matters
Weak or reused passwords are one of the main causes of account compromise through
brute-force attacks and credential stuffing. This tool provides quick, local analysis
without sending passwords over the network.

## What the tool checks
- Exact match against a local common-password list
- Guessable patterns (1234, qwerty, repeats, year tokens)
- Password length and character diversity
- Entropy-based strength estimation

## How to run
1. Make sure Python is installed
2. Keep `password_analyzer.py` and `common_passwords.txt` in the same folder
3. Open terminal in that folder
4. Run:
   python password_analyzer.py

## Notes / Limitations
- Leak exposure is approximated using an offline common-password list
- Entropy is an estimate and does not capture all human-chosen patterns
