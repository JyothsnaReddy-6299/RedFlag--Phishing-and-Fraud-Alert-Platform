from fastapi import APIRouter
from app.api.endpoints import router as url_router

api_router = APIRouter()
api_router.include_router(url_router, prefix="", tags=["Malicious URL Detection"])
