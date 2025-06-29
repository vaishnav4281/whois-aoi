from fastapi import FastAPI
from app.api.ipgeo import router as ipgeo_router
from app.api.abuse import router as abuse_router
from app.api.dns import router as dns_router
from app.api.whois import router as whois_router

app = FastAPI(title="IP Analysis API")

# Include all routers
app.include_router(ipgeo_router, prefix="/ipgeo")
app.include_router(abuse_router, prefix="/abuse")
app.include_router(dns_router, prefix="/dns")
app.include_router(whois_router, prefix="/whois")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
