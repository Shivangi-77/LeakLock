import re

# ============================================
#             LEAKLOCK DETECTOR
# ============================================


# 1. Email Detection

def detect_email(text):

    pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'

    return re.findall(pattern, text)


# 2. Phone Number Detection

def detect_phone(text):

    pattern = r'(?<!\d)[6-9]\d{9}(?!\d)'

    return re.findall(pattern, text)


# 3. Aadhaar Number Detection

def detect_aadhaar(text):

    pattern = r'(?<!\d)\d{12}(?!\d)'

    return re.findall(pattern, text)


# 4. PAN Number Detection

def detect_pan(text):

    pattern = r'\b[A-Z]{5}[0-9]{4}[A-Z]\b'

    return re.findall(pattern, text, re.IGNORECASE)


# 5. Password Detection

def detect_password(text):

    pattern = r'\b(?:password|passwd|pwd)\s*[:=]\s*(\S+)'

    return re.findall(pattern, text, re.IGNORECASE)


# ============================================
#       INDIVIDUAL MASKING FUNCTIONS
# ============================================


# Email Masking

def mask_email(email):

    if not re.fullmatch(
        r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}',
        email
    ):
        raise ValueError("Invalid email format")

    username, domain = email.split("@", 1)

    return username[0] + "****@" + domain


# Phone Number Masking

def mask_phone(phone):

    if not re.fullmatch(r'[6-9]\d{9}', phone):
        raise ValueError("Invalid phone number")

    return "******" + phone[-4:]


# Aadhaar Number Masking

def mask_aadhaar(aadhaar):

    if not re.fullmatch(r'\d{12}', aadhaar):
        raise ValueError("Invalid Aadhaar number")

    return "********" + aadhaar[-4:]


# PAN Number Masking

def mask_pan(pan):

    if not re.fullmatch(
        r'[A-Z]{5}[0-9]{4}[A-Z]',
        pan,
        re.IGNORECASE
    ):
        raise ValueError("Invalid PAN format")

    return "XXXXX" + pan[5:9] + "X"


# Password Masking

def mask_password(password):

    if not password:
        raise ValueError("Password cannot be empty")

    return "[REDACTED]"


# ============================================
#       AUTOMATIC TEXT MASKING
# ============================================

def mask_sensitive_data(text):

    # Hide passwords first

    text = re.sub(
        r'(\b(?:password|passwd|pwd)\s*[:=]\s*)\S+',
        r'\1[REDACTED]',
        text,
        flags=re.IGNORECASE
    )

    # Hide email addresses

    text = re.sub(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
        lambda match: mask_email(match.group()),
        text
    )

    # Hide phone numbers

    text = re.sub(
        r'(?<!\d)[6-9]\d{9}(?!\d)',
        lambda match: mask_phone(match.group()),
        text
    )

    # Hide Aadhaar numbers

    text = re.sub(
        r'(?<!\d)\d{12}(?!\d)',
        lambda match: mask_aadhaar(match.group()),
        text
    )

    # Hide PAN numbers

    text = re.sub(
        r'\b[A-Z]{5}[0-9]{4}[A-Z]\b',
        lambda match: mask_pan(match.group()),
        text,
        flags=re.IGNORECASE
    )

    return text


# ============================================
#          DETECTION SUMMARY
# ============================================

def scan_text(text):

    results = {

        "Email": detect_email(text),

        "Phone": detect_phone(text),

        "Aadhaar": detect_aadhaar(text),

        "PAN": detect_pan(text),

        "Password": detect_password(text)

    }

    return results