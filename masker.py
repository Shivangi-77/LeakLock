import re

# ============================================
#              LEAKLOCK MASKER
# ============================================


# 1. Mask Email Address

def mask_email(email):

    pattern = r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'

    if not re.fullmatch(pattern, email):
        raise ValueError("Invalid email format")

    username, domain = email.split("@", 1)

    return username[0] + "****@" + domain


# 2. Mask Phone Number

def mask_phone(phone):

    if not re.fullmatch(r'[6-9]\d{9}', phone):
        raise ValueError("Invalid phone number")

    return "******" + phone[-4:]


# 3. Mask Aadhaar Number

def mask_aadhaar(aadhaar):

    if not re.fullmatch(r'\d{12}', aadhaar):
        raise ValueError("Invalid Aadhaar number")

    return "********" + aadhaar[-4:]


# 4. Mask PAN Number

def mask_pan(pan):

    if not re.fullmatch(r'[A-Z]{5}[0-9]{4}[A-Z]', pan, re.IGNORECASE):
        raise ValueError("Invalid PAN format")

    return "XXXXX" + pan[5:9] + "X"


# 5. Mask Password

def mask_password(password):

    if not password:
        raise ValueError("Password cannot be empty")

    return "[REDACTED]"


# ============================================
#       AUTOMATIC TEXT MASKING
# ============================================

def mask_sensitive_data(text):

    # Hide passwords

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