from fastapi import APIRouter
from app.api.endpoints import router as scan_router

api_router = APIRouter()
api_router.include_router(scan_router, prefix="", tags=["Detection & Threat Intelligence"])
