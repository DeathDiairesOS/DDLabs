"""Terminal-safe text; retain SSIDs exactly in structured JSON and comparisons."""

import unicodedata


def terminal_text(value: object) -> str:
    text = str(value)
    return "".join(
        char if not unicodedata.category(char).startswith("C")
        and char not in "\u2028\u2029"
        else (f"\\u{ord(char):04x}" if ord(char) <= 0xFFFF else f"\\U{ord(char):08x}")
        for char in text
    )
