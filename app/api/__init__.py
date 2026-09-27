from fastapi import APIRouter
from app.api.endpoints import router as scan_router
from app.api.report_endpoints import router as report_router
from app.api.graph_endpoints import router as graph_router

api_router = APIRouter()
api_router.include_router(scan_router, prefix="", tags=["Detection & Threat Intelligence"])
api_router.include_router(report_router, prefix="", tags=["Community Reporting & Verification"])
api_router.include_router(graph_router, prefix="", tags=["Graph Analysis & Campaign Detection"])
