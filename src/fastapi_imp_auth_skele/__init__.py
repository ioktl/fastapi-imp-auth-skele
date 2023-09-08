from pathlib import Path
from fastapi import FastAPI
from .private_routes import router as private_router
from .public_routes import router as public_router
from .middleware import JWTAuthMiddleware
from .config import config
from .service import create_jwk

private_app = FastAPI()
public_app = FastAPI()

private_app.add_middleware(JWTAuthMiddleware)
private_app.include_router(private_router)
public_app.include_router(public_router)

app = FastAPI()
app.mount("/public", public_app)
app.mount("/private", private_app)

if not (Path(config["StoreRoot"]) / Path("jwk.pickle")).exists():
    create_jwk()
