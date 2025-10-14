
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import os

from routes.scan_routes import router as scan_router

app = FastAPI(title="VulnScan AI Backend", version="1.0.0")

# Allowed origins for CORS - restrict to specific domains
ALLOWED_ORIGINS = [
    "https://2f7ebd3f-a3b3-449b-94ac-f2a2c2d67068.lovableproject.com",  # Production
    "http://localhost:5173",  # Local development
    "http://localhost:3000",  # Alternative local port
]

# Add CORS middleware with restricted origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Include API routers with /api prefix
app.include_router(scan_router, prefix="/api", tags=["scan"])

@app.get("/")
async def read_root():
    return {"message": "VulnScan AI Backend is running"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

# Mount static files AFTER API routes to avoid conflicts
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static", html=True), name="static")
