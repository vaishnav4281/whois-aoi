from fastapi import APIRouter, HTTPException
from app.services.abuse_service import AbuseService

router = APIRouter()

@router.get("/abuse", tags=["abuse"])
async def get_abuse(ip: str):
    try:
        return {"data": AbuseService.get_abuse_info(ip)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
