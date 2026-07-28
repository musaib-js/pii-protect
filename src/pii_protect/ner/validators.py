import re

def _luhn_is_valid(digits: str) -> bool:
    """
    Validate a digit string against the Luhn checksum (used to filter the
    CREDIT_CARD pattern — see V-12). Returns False for anything that isn't
    a plausible card number, including sequences that merely look like one.
    """
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    total = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# Verhoeff multiplication table
_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)

# Verhoeff permutation table
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def _verhoeff_is_valid(value: str) -> bool:
    """Validate an Aadhaar number using the Verhoeff checksum."""

    digits = re.sub(r"\s", "", value)

    if len(digits) != 12 or not digits.isdigit():
        return False

    # Aadhaar numbers cannot start with 0 or 1.
    if digits[0] in ("0", "1"):
        return False

    checksum = 0

    for i, digit in enumerate(reversed(digits)):
        checksum = _VERHOEFF_D[
            checksum
        ][
            _VERHOEFF_P[i % 8][int(digit)]
        ]

    return checksum == 0


def _is_valid_gliner_entity(
    text: str,
    label: str,
    score: float,
) -> bool:
    value = text.strip()
    label = label.lower()

    # Reject empty / trivial entities
    if not value:
        return False

    # PERSON is especially noisy on tiny conversational tokens.
    if label in {"person", "customer name"}:
        # "Hi", "Ok", "No", etc.
        if len(value) <= 2:
            return False

    return True