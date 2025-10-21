"""
SpyNet Backend - Main application entry point
"""
from fastapi import FastAPI
from config import settings

# Create FastAPI application
app = FastAPI(
    title="SpyNet API",
    description="Network Traffic Analyzer and Intrusion Detection System API",
    version="1.0.0",
    debug=settings.debug
)


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "SpyNet API is running",
        "version": "1.0.0",
        "status": "healthy"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "spynet-api"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug
    )