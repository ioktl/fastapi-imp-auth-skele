from fastapi import APIRouter, HTTPException
from .models import Challenge, JWT, SolvedChallenge
from .service import create_challenge, validate_challenge_response, create_jwt, delete_challenge

router = APIRouter()


@router.get("/token")
async def request_challenge() -> Challenge:
    challenge, valid_until = create_challenge()
    return Challenge(challenge=challenge, valid_until=valid_until)


@router.post("/token")
async def request_token(response: SolvedChallenge) -> JWT:
    if not validate_challenge_response(response.challenge, response.response):
        # if the challenge has failed, we delete it from the store to prevent
        # further attempts of solving it
        delete_challenge(response.challenge)
        raise HTTPException(status_code=401, detail="invalid challenge response")
    # however, depending on actual implementation, we might not want to delete
    # the challenge in case of successful auth (e.g. session-challenge used
    # to track auth events)
    return JWT(token=create_jwt())
