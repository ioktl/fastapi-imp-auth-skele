import time
import datetime
import secrets
import hashlib
from pathlib import Path
import pickle
from authlib.jose import JsonWebToken
from authlib.jose import jwt as JWT
from authlib.jose.errors import InvalidClaimError, BadSignatureError, ExpiredTokenError, DecodeError
from jwcrypto import jwk
from .config import config


def create_challenge() -> tuple[str, datetime.datetime]:
    ttl_seconds = int(config["ChallengeTTLSeconds"])
    challenge_length = int(config["ChallengeLength"])
    challenge = secrets.token_hex(challenge_length)
    valid_until = datetime.datetime.now() + datetime.timedelta(seconds=ttl_seconds)
    set_challenge_with_ttl(challenge, valid_until)
    return challenge, valid_until


def delete_challenge(challenge: str) -> None:
    store_root = config["StoreRoot"]
    file = Path(store_root) / Path(challenge + ".pickle")
    file.unlink(missing_ok=True)


def validate_challenge_response(challenge: str, response: str) -> bool:
    if not is_valid_challenge(challenge):
        return False
    secret = config["AuthSecret"]
    digest = hashlib.sha256((secret + challenge).encode("utf8")).hexdigest()
    if response != digest:
        return False
    return True


def is_valid_challenge(challenge: str) -> bool:
    store_root = config["StoreRoot"]
    file = Path(store_root) / Path(challenge + ".pickle")
    if not file.exists():
        return False
    with file.open("rb") as f:
        challenge_object = pickle.load(f)
    if challenge_object["challenge"] != challenge:
        return False
    if datetime.datetime.now() > challenge_object["expires_at"]:
        file.unlink()
        return False
    return True


def set_challenge_with_ttl(challenge: str, expiry: datetime.datetime) -> None:
    store_root = config["StoreRoot"]
    file = Path(store_root) / Path(challenge + ".pickle")
    with file.open("wb") as f:
        pickle.dump({"challenge": challenge, "expires_at": expiry}, f)


def create_jwt() -> str:
    expiry_seconds = int(config["TokenTTLSeconds"])
    jwk_data = get_jwk_private()
    return JWT.encode(
        {
            "alg": jwk_data["alg"],
        },
        {
            "iss": "sample.server",
            "aud": "api",
            "sub": "deadbeef",
            "exp": int(time.time()) + expiry_seconds,
            "iat": int(time.time()),
        },
        jwk_data,
    ).decode("utf8")


def get_jwk_private() -> dict[str, str]:
    return _get_jwk_component("private")


def get_jwk_public() -> dict[str, str]:
    return _get_jwk_component("public")


def _get_jwk_component(component: str) -> dict[str, str]:
    store_root = config["StoreRoot"]
    file = Path(store_root) / Path("jwk.pickle")
    with file.open("rb") as f:
        jwk_data = pickle.load(f)
    return jwk_data[component]


def set_jwk(private: dict[str, str], public: [str, str]) -> None:
    store_root = config["StoreRoot"]
    file = Path(store_root) / Path("jwk.pickle")
    with file.open("wb") as f:
        pickle.dump({"private": private, "public": public}, f)


def create_jwk() -> None:
    key = jwk.JWK.generate(
        kty="EC",
        alg="ES256",
        use="sig",
        kid="deadbeef",
    )
    public = key.export_public(as_dict=True)
    private = key.export_private(as_dict=True)
    set_jwk(private, public)


def validate_jwt(token: str) -> bool:
    jwk_public = get_jwk_public()
    jwt = JsonWebToken(jwk_public["alg"])
    claim_options = {
        "iss": {"essential": True, "value": "sample.server"},
        "aud": {"essential": True, "value": "api"},
    }
    try:
        claims = jwt.decode(token, jwk_public, claims_options=claim_options)
        claims.validate()
    except (BadSignatureError, InvalidClaimError, ExpiredTokenError, DecodeError) as e:
        # note: DecodeError can be raised if token contains some random data
        return False
    return True
