"""
Generates a new API key.

    python -m scripts.generate_key

The raw key goes to the consumer (header ``X-Api-Key: Bearer <raw_key>``), the
hash goes into keystore.json together with the scopes granted to that key:

    { "<hash>": { "clientId": "my-client", "scopes": ["read:echo"] } }
"""

import hashlib
import secrets


def generate_api_key(prefix: str = "sk_live") -> str:
    return f"{prefix}_{secrets.token_hex(24)}"


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


if __name__ == "__main__":
    raw_key = generate_api_key()

    print("Raw key (give this to the consumer, shown only once):")
    print(raw_key)
    print("\nHash to store in your key store:")
    print(hash_key(raw_key))
