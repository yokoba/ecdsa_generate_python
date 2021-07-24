import json
from pathlib import Path

from authlib.jose import JsonWebKey, JsonWebSignature


def generate_key():
    """256bit ECDSA(prime256v1)でprivate key, public keyを作成する
    https://docs.authlib.org/en/stable/specs/rfc7517.html
    """
    key = JsonWebKey.generate_key("EC", "P-256", is_private=True)

    return key


def export_key_to_file(key):
    """JsonWebKey.generate_keyで作成したキーを出力する
    https://docs.authlib.org/en/stable/specs/rfc7517.html

    作成したPEM(ASN.1のデコーダー)
    https://lapo.it/asn1js/#
    """
    private_key = key.as_pem(is_private=True).decode("ascii")
    public_key = key.as_pem(is_private=False).decode("ascii")
    jwk = key.as_json()

    base = Path(__file__).parent

    Path(base).joinpath("private_key.pem").write_text(private_key)
    Path(base).joinpath("public_key.pem").write_text(public_key)
    Path(base).joinpath("jwk.key").write_text(json.dumps(key.as_dict()))

    print("----- Generate Key ------------------------------------------------------------------------")
    print(f"private key\n{private_key}")
    print(f"public  key\n{public_key}")

    print(f"jwk\n{json.dumps(json.loads(jwk))}")
    print("----- Generate Key ------------------------------------------------------------------------\n\n")


def import_key_from_file():
    """作成したpemファイルを取り込んでprivate key, public key, jwk形式で表示する
    https://docs.authlib.org/en/stable/specs/rfc7517.html
    """

    base = Path(__file__).parent
    private_pem = base.joinpath("private_key.pem").read_bytes()
    key = JsonWebKey.import_key(private_pem, {"kty": "EC"})
    private_key = key.as_pem(is_private=True).decode("ascii")

    public_pem = base.joinpath("public_key.pem").read_bytes()
    key = JsonWebKey.import_key(public_pem, {"kty": "EC"})
    public_key = key.as_pem(is_private=False).decode("ascii")

    json_dict = json.loads(base.joinpath("jwk.key").read_text())
    key = JsonWebKey.import_key(json_dict, {"kty": "EC"})
    json_key = key.as_json()

    print("----- Import  Key ------------------------------------------------------------------------")
    print(f"private key\n{private_key}")
    print(f"public  key\n{public_key}")

    print(f"jwk\n{json.dumps(json.loads(json_key))}")
    print("----- Import  Key ------------------------------------------------------------------------\n\n")


def generate_signature(key):
    """generate_keyで作成したキーを利用して署名を行う
    https://docs.authlib.org/en/stable/specs/rfc7515.html

    行った署名の検証
    https://jwt.io/
    """

    header = {"typ": "JWT", "alg": "ES256"}
    payload = {
        "aud": "https://push.services.mozilla.com",
        "exp": 1464269795,
        "sub": "https://example.com",
    }

    json_payload = json.dumps(payload, separators=(",", ":"))
    json_payload = json.dumps(payload)

    jws = JsonWebSignature()
    jws_data = jws.serialize_compact(header, json_payload, key).decode("ascii")

    print("----- Signature Key ------------------------------------------------------------------------")
    print("JWS")
    print(jws_data)
    print("----- Signature Key ------------------------------------------------------------------------\n\n")


if __name__ == "__main__":
    key = generate_key()
    export_key_to_file(key)
    import_key_from_file()
    generate_signature(key)
