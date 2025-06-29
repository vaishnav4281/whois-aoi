from fastapi import APIRouter, HTTPException
from app.services.dns_service import DNSService

router = APIRouter()

@router.get("/dns", tags=["dns"])
async def get_dns(domain: str):
    try:
        return {"ip": DNSService.get_a_records(domain)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
