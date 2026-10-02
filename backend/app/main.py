import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from app.core.config import settings
from app.api import api_router

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.PROJECT_VERSION,
    description="RedFlag — Real-Time Malicious URL & Phishing Detection Platform.",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=f"{settings.API_V1_STR}/redoc"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API v1
app.include_router(api_router, prefix=settings.API_V1_STR)

@app.get("/health", tags=["System"])
def health_check():
    return {
        "status": "online",
        "service": settings.PROJECT_NAME,
        "version": settings.PROJECT_VERSION,
        "focus": "Malicious Links & Phishing Detection Engine"
    }

# Mount Static frontend UI from frontend/dist (production React build) or frontend
frontend_dist = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../frontend/dist"))
frontend_src = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../frontend"))
target_static = frontend_dist if os.path.exists(frontend_dist) else frontend_src

if os.path.exists(target_static):
    app.mount("/", StaticFiles(directory=target_static, html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
