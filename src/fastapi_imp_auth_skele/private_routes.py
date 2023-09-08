from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()


@router.get("/resource", response_class=JSONResponse)
async def request_session():
    return JSONResponse(status_code=200, content={"data": "secret-data"})
