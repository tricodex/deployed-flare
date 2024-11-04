import base64
import hashlib
import json
from pathlib import Path
from pprint import pprint

from web3 import Web3

from jwks import get_rsa_data_by_kid


def read_data(filepath: Path) -> str:
    with filepath.open("r") as f:
        return f.readline()


def base64url_decode(input_str: str) -> bytes:
    padding = "=" * (4 - (len(input_str) % 4))
    return base64.urlsafe_b64decode(input_str + padding)


if __name__ == "__main__":
    raw_token = read_data(Path("data/oidc"))
    header_b64, payload_b64, signature_b64 = raw_token.split(".")

    decoded_header = base64url_decode(header_b64)
    decoded_payload = base64url_decode(payload_b64)

    header = decoded_header.hex()
    payload = decoded_payload.hex()
    signature = base64url_decode(signature_b64).hex()

    json_payload = json.loads(decoded_payload)
    json_header = json.loads(decoded_header)

    print("----verifyAndAttest INPUTS----")
    print(f"HEADER:\n{header}\n")
    print(f"PAYLOAD:\n{payload}\n")
    print(f"SIGNATURE:\n{signature}\n")
    print("-----------------------\n")

    print("----setBaseVtpmConfig INPUTS----")
    print(f"hwmodel:\n{json_payload['hwmodel']}\n")
    print(f"swname:\n{json_payload['swname']}\n")
    print(f"image_digest:\n{json_payload['submods']['container']['image_digest']}\n")
    print(f"iss:\n{json_payload['iss']}\n")
    print(f"secboot:\n{json_payload['secboot']}\n")
    print("-----------------------\n")

    digest = hashlib.sha256((header_b64 + "." + payload_b64).encode("utf-8")).digest()

    print("----VtpmConfig----")
    print(f"exp:\n{json_payload['exp']}\n")
    print(f"iat:\n{json_payload['iat']}\n")
    print(f"digest:\n{Web3.to_hex(digest)}\n")
    print("-----------------------\n")

    is_pki = json_header.get("x5c", None)
    if not is_pki:
        kid = json_header["kid"]
        e, n = get_rsa_data_by_kid(kid)

        print("----addOidcPubKey INPUTS----")
        print(f"kid:\n{kid}\n")
        print(f"e:\n{base64url_decode(e).hex()}\n")
        print(f"n:\n{base64url_decode(n).hex()}\n")
        print("-----------------------")
    else:
        pprint(json_header)
