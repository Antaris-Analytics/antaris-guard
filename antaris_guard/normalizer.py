"""
Input normalization for evasion resistance.

Normalizes text before pattern matching to catch:
- Unicode tricks (homoglyphs, NFKC normalization)
- Whitespace/punctuation insertion between characters
- Leetspeak substitutions
- Case variations

All deterministic, zero dependencies.
"""

import re
import unicodedata
from typing import Tuple


# Leetspeak mappings (common substitutions)
LEET_MAP = {
    '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
    '7': 't', '8': 'b', '9': 'g', '@': 'a', '$': 's',
    '!': 'i', '+': 't', '|': 'l',
}

# Common Unicode confusables — Cyrillic/Greek letters that look Latin.
# Applied after NFKC (which doesn't resolve these).
CONFUSABLES_MAP = {
    '\u0430': 'a',  # Cyrillic а
    '\u0435': 'e',  # Cyrillic е
    '\u0456': 'i',  # Cyrillic і
    '\u043e': 'o',  # Cyrillic о
    '\u0440': 'p',  # Cyrillic р
    '\u0441': 'c',  # Cyrillic с
    '\u0443': 'y',  # Cyrillic у (looks like y)
    '\u0445': 'x',  # Cyrillic х
    '\u0455': 's',  # Cyrillic ѕ
    '\u04bb': 'h',  # Cyrillic һ
    '\u0458': 'j',  # Cyrillic ј
    '\u0454': 'e',  # Cyrillic є (looks like reversed e, close enough)
    '\u0472': 'f',  # Cyrillic Ѳ → theta, close to f visually? No — skip
    '\u03b1': 'a',  # Greek α
    '\u03b5': 'e',  # Greek ε
    '\u03bf': 'o',  # Greek ο
    '\u03c1': 'p',  # Greek ρ
    '\u03c4': 't',  # Greek τ
    '\u03ba': 'k',  # Greek κ
    '\u03bd': 'v',  # Greek ν
    '\u0391': 'A',  # Greek Α (capital)
    '\u0392': 'B',  # Greek Β
    '\u0395': 'E',  # Greek Ε
    '\u0397': 'H',  # Greek Η
    '\u0399': 'I',  # Greek Ι
    '\u039a': 'K',  # Greek Κ
    '\u039c': 'M',  # Greek Μ
    '\u039d': 'N',  # Greek Ν
    '\u039f': 'O',  # Greek Ο
    '\u03a1': 'P',  # Greek Ρ (capital rho)
    '\u03a4': 'T',  # Greek Τ
    '\u03a7': 'X',  # Greek Χ
    '\u03a5': 'Y',  # Greek Υ
    '\u0396': 'Z',  # Greek Ζ
}
# Build translation table for str.translate() — fast single-pass
_CONFUSABLES_TABLE = str.maketrans(CONFUSABLES_MAP)

# Characters commonly inserted between letters to evade detection
FILLER_CHARS = frozenset('.-_*~`•·…→←↑↓')

# Soft hyphen and other invisible separators not in the zero-width range
INVISIBLE_SEPARATORS = re.compile(r'[\u00ad\u034f\u2060\ufeff]')


def normalize(text: str) -> Tuple[str, str]:
    """
    Normalize text for pattern matching.
    
    Returns:
        Tuple of (normalized_text, original_text).
        Pattern matching runs against normalized_text,
        but results reference positions in original_text.
    """
    original = text
    
    # Step 1: Unicode NFKC normalization
    # Converts fullwidth chars, compatibility chars, homoglyphs
    text = unicodedata.normalize('NFKC', text)
    
    # Step 2: Strip zero-width characters, control chars, and invisible separators
    text = re.sub(r'[\u200b-\u200f\u2028-\u202f\ufeff\u00ad\u034f\u2060]', '', text)
    
    # Step 3: Replace Unicode confusables (Cyrillic/Greek lookalikes → Latin)
    text = text.translate(_CONFUSABLES_TABLE)
    
    # Step 4: Collapse repeated whitespace/punctuation/emoji between word chars
    # Catches "i g n o r e" and "i.g.n.o.r.e" and "i🧠g🧠n🧠o🧠r🧠e"
    text = _collapse_spaced_words(text)
    
    # Step 5: Apply leetspeak decoding
    text = _decode_leet(text)
    
    return text, original


def _collapse_spaced_words(text: str) -> str:
    """
    Collapse single characters separated by fillers/spaces into words,
    then rejoin with single spaces to preserve word boundaries.
    
    "i g n o r e  a l l  i n s t r u c t i o n s" → "ignore all instructions"
    "i.g.n.o.r.e" → "ignore"
    "e_n_a_b_l_e" → "enable"
    "e*n*a*b*l*e" → "enable"
    """
    def collapse_match(m):
        chars = re.findall(r'[a-zA-Z0-9]', m.group(0))
        return ''.join(chars)
    
    # Filler pattern: spaces, dots, dashes, underscores, asterisks, and
    # non-ASCII symbols (emoji, misc symbols). ASCII symbols like $@!+| are
    # excluded because they're used in leetspeak (handled by _decode_leet).
    # Using [a-zA-Z0-9] instead of \w because \w includes _ which we
    # want to treat as a filler, not a word character.
    filler = r'(?:[\s.\-_*~`•·…]|[^\x00-\x7f\w\s])+'
    alnum = r'[a-zA-Z0-9]'
    
    # Match 3+ single alnum chars separated by fillers
    spaced_pattern = re.compile(alnum + r'(?:' + filler + alnum + r'){2,}')
    
    # Split on double-space or more to detect word boundaries in spaced text
    parts = re.split(r'  +', text)
    collapsed_parts = []
    for part in parts:
        collapsed = spaced_pattern.sub(collapse_match, part)
        collapsed_parts.append(collapsed)
    
    return ' '.join(collapsed_parts)


def _decode_leet(text: str) -> str:
    """
    Apply common leetspeak substitutions.
    
    Only applies when the result would form a recognizable word pattern.
    Conservative — won't mangle normal numbers in context.
    """
    # Simple pass: replace leet chars that are surrounded by letters
    result = list(text)
    for i, char in enumerate(result):
        if char in LEET_MAP:
            # Check if surrounded by letters (likely leet, not a number)
            prev_is_alpha = i > 0 and result[i-1].isalpha()
            next_is_alpha = i < len(result) - 1 and result[i+1].isalpha()
            if prev_is_alpha or next_is_alpha:
                result[i] = LEET_MAP[char]
    
    return ''.join(result)


def normalize_light(text: str) -> str:
    """
    Light normalization — just Unicode NFKC + zero-width removal.
    Use when full normalization is too aggressive.
    """
    text = unicodedata.normalize('NFKC', text)
    text = re.sub(r'[\u200b-\u200f\u2028-\u202f\ufeff\u00ad]', '', text)
    return text
