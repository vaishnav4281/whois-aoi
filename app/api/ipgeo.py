from fastapi import APIRouter, HTTPException
from app.services.ipgeo_service import IPGeoService

router = APIRouter()

@router.get("/ipgeo", tags=["ipgeo"])
async def get_ipgeo(ip: str):
    try:
        return IPGeoService.get_ip_info(ip)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
