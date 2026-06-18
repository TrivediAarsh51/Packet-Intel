from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .api import auth, packets, crime, anomaly
from .models import Base
from .database import engine
import os

# Create DB tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Network Forensics Platform API")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(packets.router, prefix="/api/packets", tags=["Packets"])
app.include_router(crime.router, prefix="/api/crime", tags=["Crime"])
app.include_router(anomaly.router, prefix="/api/anomaly", tags=["Anomaly"])

@app.get("/")
async def root():
    return {"message": "Welcome to the Network Forensics Platform API", "version": "0.1"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
