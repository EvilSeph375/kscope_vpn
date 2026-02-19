from cryptography.hazmat.primitives.asymmetric import ed25519
from common.crypto import save_ed25519_private, save_ed25519_public
import os

os.makedirs("keys", exist_ok=True)

s_priv = ed25519.Ed25519PrivateKey.generate()
save_ed25519_private(s_priv, "keys/server_ed25519_priv.pem")
save_ed25519_public(s_priv.public_key(), "keys/server_ed25519_pub.pem")

c_priv = ed25519.Ed25519PrivateKey.generate()
save_ed25519_private(c_priv, "keys/client_ed25519_priv.pem")
save_ed25519_public(c_priv.public_key(), "keys/client_ed25519_pub.pem")

print("Keys generated")
