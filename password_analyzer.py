import math
import os
import re

COMMON_SEQUENCES = (
    "1234", "2345", "3456", "4567", "5678", "6789",
    "abcd", "bcde", "qwerty", "asdf", "zxcv",
)


# Load known weak passwords from the local text file into a fast lookup set
def load_common_passwords():
    file_path = os.path.join(os.path.dirname(__file__), "common_passwords.txt")
    if not os.path.exists(file_path):
        return set()

    with open(file_path, "r", encoding="utf-8") as file:
        return {line.strip().lower() for line in file if line.strip()}


# Estimate password entropy in bits based on character pool size and length
def calculate_entropy(password):
    pool_size = 0
    char_types = 0

    if any(c.islower() for c in password):
        pool_size += 26
        char_types += 1
    if any(c.isupper() for c in password):
        pool_size += 26
        char_types += 1
    if any(c.isdigit() for c in password):
        pool_size += 10
        char_types += 1
    if any(not c.isalnum() for c in password):
        pool_size += 32
        char_types += 1

    if pool_size == 0:
        return 0.0, 0

    entropy = round(len(password) * math.log2(pool_size), 1)
    return entropy, char_types


# Flag predictable human habits that weaken password resistance
def detect_heuristics(password, char_types):
    flags = []
    lowered = password.lower()

    if len(password) < 12:
        flags.append("Short length (fewer than 12 characters)")

    if char_types == 1:
        flags.append("Uses only one character type")

    if re.search(r"(.)\1\1", password):
        flags.append("Contains repeated characters (e.g., 'aaa' or '111')")

    if any(seq in lowered for seq in COMMON_SEQUENCES):
        flags.append("Contains a predictable keyboard or sequential pattern")

    return flags


# Assign an overall strength tier, meter percentage, and summary sentence
def classify_risk(is_common, entropy, heuristics):
    if is_common or entropy < 35:
        return {
            "level": "Very Weak",
            "css_class": "risk-critical",
            "percent": 25,
            "summary": "Vulnerable to immediate automated cracking or credential stuffing.",
        }
    if entropy < 55 or len(heuristics) >= 2:
        return {
            "level": "Weak",
            "css_class": "risk-weak",
            "percent": 50,
            "summary": "Easily guessed using modern hardware and common pattern rules.",
        }
    if entropy < 75 or len(heuristics) == 1:
        return {
            "level": "Moderate",
            "css_class": "risk-moderate",
            "percent": 75,
            "summary": "Reasonable baseline, though predictable traits still reduce resilience.",
        }
    return {
        "level": "Strong",
        "css_class": "risk-strong",
        "percent": 100,
        "summary": "High randomness and length provide strong resistance against offline attacks.",
    }


# Build actionable plain-English steps to strengthen the evaluated password
def generate_suggestions(password, is_common, char_types, heuristics):
    suggestions = []

    if is_common:
        suggestions.append("Replace this password immediately—it appears in known leaked password lists.")

    if len(password) < 12:
        suggestions.append("Extend length to at least 14 characters using a multi-word passphrase.")

    if char_types < 3:
        suggestions.append("Mix uppercase letters, lowercase letters, numbers, and symbols.")

    if any("repeated" in flag.lower() for flag in heuristics):
        suggestions.append("Break up repeated characters like '111' or 'aaa'.")

    if any("keyboard" in flag.lower() for flag in heuristics):
        suggestions.append("Avoid keyboard walks or sequences such as 'qwerty' or '1234'.")

    if not suggestions:
        suggestions.append("Good posture—store this uniquely in a password manager and never reuse it.")

    return suggestions


# Run complete offline screening, entropy math, heuristics, and strength scoring
def analyze_password(password, common_passwords):
    is_common = password.strip().lower() in common_passwords
    entropy, char_types = calculate_entropy(password)
    heuristics = detect_heuristics(password, char_types)
    risk = classify_risk(is_common, entropy, heuristics)
    suggestions = generate_suggestions(password, is_common, char_types, heuristics)

    return {
        "is_common": is_common,
        "length": len(password),
        "entropy": entropy,
        "char_types": char_types,
        "heuristics": heuristics,
        "risk": risk,
        "suggestions": suggestions,
    }