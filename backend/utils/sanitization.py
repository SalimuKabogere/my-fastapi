import re
import unicodedata
from urllib.parse import unquote

# Username: allow only alphanumerics, underscores, hyphens; limit length; normalize unicode
def sanitize_username(input_str: str, max_length: int = 32) -> str:
    if not input_str:
        return ""
    decoded = unquote(input_str)
    normalized = unicodedata.normalize('NFKC', decoded)
    whitelisted = re.sub(r'[^a-zA-Z0-9_-]', '', normalized)
    return whitelisted[:max_length]

# Password: enforce min/max length, complexity (at least one letter, one number, one symbol)
def validate_password(password: str, min_length: int = 8, max_length: int = 128) -> bool:
    if not password or not (min_length <= len(password) <= max_length):
        return False
    # At least one letter, one number, one symbol
    if not re.search(r'[A-Za-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[^A-Za-z0-9]', password):
        return False
    return True

# URL: decode, strip tags, validate as URL, limit length
def sanitize_url(input_str: str, max_length: int = 2048) -> str:
    if not input_str:
        return ""
    decoded = unquote(input_str)
    # Remove script tags
    no_script = re.sub(r'<script.*?</script>', '', decoded, flags=re.IGNORECASE | re.DOTALL)
    # Remove all HTML tags
    no_tags = re.sub(r'<.*?>', '', no_script)
    url = no_tags.strip()[:max_length]
    # Basic URL validation
    if re.match(r'^(https?|ftp)://[\w.-]+(?:\.[\w\.-]+)+[/#?]?.*$', url):
        return url
    return ""

# Free text: remove <script>...</script> blocks and their content, strip all other HTML tags, keep only text, normalize, and limit length
def sanitize_free_text(input_str: str, max_length: int = 1024) -> str:
    """
    Remove <script>...</script> blocks and their content, strip all other HTML tags, keep only the text.
    Normalize unicode and limit length.
    """
    if not input_str:
        return ""
    decoded = unquote(input_str)
    # Remove all <script>...</script> blocks (case-insensitive)
    no_script = re.sub(r'<script.*?</script>', '', decoded, flags=re.IGNORECASE | re.DOTALL)
    # Remove all other HTML tags
    no_tags = re.sub(r'<.*?>', '', no_script)
    normalized = unicodedata.normalize('NFKC', no_tags)
    return normalized.strip()[:max_length] 