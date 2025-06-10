
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import os

from routes.scan_routes import router as scan_router

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scan_router)

@app.get("/")
async def read_root():
    return {"message": "VulnScan AI Backend is running"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

# Mount static files on /static path instead of root to avoid conflicts
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static", html=True), name="static")
