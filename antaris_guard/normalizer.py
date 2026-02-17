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
    
    # Re-insert spaces where zero-width removal concatenated words
    # "ignore\u200ball" → "ignoreall" → need to match "ignoreall" too
    # This is handled by patterns matching with optional \s*
    
    # Step 3: Collapse repeated whitespace/punctuation between word chars
    # Catches "i g n o r e" and "i.g.n.o.r.e" and "i-g-n-o-r-e"
    text = _collapse_spaced_words(text)
    
    # Step 4: Apply leetspeak decoding
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
    
    # Filler pattern: spaces, dots, dashes, underscores, asterisks, etc.
    # Using [a-zA-Z0-9] instead of \w because \w includes _ which we
    # want to treat as a filler, not a word character.
    filler = r'[\s.\-_*~`•·…]+'
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
