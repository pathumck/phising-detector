import unicodedata
from urllib.parse import urlparse
import domain_lists.whitelist as _whitelist


# Cyrillic characters visually identical to Latin
CYRILLIC_TO_LATIN = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "і": "i",
    "ј": "j",
    "ѕ": "s",
    "ԁ": "d",
}

# Digit substitutions used by Method B for typosquatting
DIGIT_TO_LETTER = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "8": "b",
}