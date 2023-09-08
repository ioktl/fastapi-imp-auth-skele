from pydantic import BaseModel
from datetime import datetime


class JWT(BaseModel):
    token: str


class Challenge(BaseModel):
    challenge: str
    valid_until: datetime


class SolvedChallenge(BaseModel):
    challenge: str
    response: str
