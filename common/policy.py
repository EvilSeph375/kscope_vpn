import json
from dataclasses import dataclass


@dataclass
class Policy:
    psk_b64: str
    epoch_seconds: int
    obfs_profiles: list
    transports: list
    rekey: dict
    padding: dict
    endpoints: list


def load_policy(path: str) -> Policy:
    with open(path, "r") as f:
        data = json.load(f)

    return Policy(
        psk_b64=data["psk_b64"],
        epoch_seconds=data.get("epoch_seconds", 60),
        obfs_profiles=data.get("obfs_profiles", []),
        transports=data.get("transports", []),
        rekey=data.get("rekey", {}),
        padding=data.get("padding", {}),
        endpoints=data.get("endpoints", [])
    )
