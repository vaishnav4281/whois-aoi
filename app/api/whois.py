from fastapi import APIRouter, HTTPException
from app.services.whois_service import WhoisService
from datetime import datetime
from dateutil.relativedelta import relativedelta

router = APIRouter(tags=["whois"])

# Initialize the service when the module is imported
WhoisService.initialize()

@router.get("/")
async def get_whois(domain: str):
    try:
        # Add proper domain validation
        if not domain:
            raise ValueError("Domain is required")
        
        # Get domain information using DNS queries
        result = WhoisService.get_domain_info(domain)
        
        # Add some basic validation
        if not result.get("domain"):
            raise ValueError("Invalid domain information")
        
        # Build the response ensuring that no value is returned as `null` in JSON.
        # Strings → empty string "" when absent; lists → empty list [] when absent.
        response = {
            "domain": result.get("domain") or "",
            "creation_date": result.get("creation_date") or "",
            "expiration_date": result.get("expiration_date") or "",
            "registrar": result.get("registrar") or "",
            "registrant_name": result.get("registrant_name") or "",
            "registrant_organization": result.get("registrant_organization") or "",
            "registrant_country": result.get("registrant_country") or "",
            "admin_name": result.get("admin_name") or "",
            "admin_organization": result.get("admin_organization") or "",
            "admin_country": result.get("admin_country") or "",
            "tech_name": result.get("tech_name") or "",
            "tech_organization": result.get("tech_organization") or "",
            "tech_country": result.get("tech_country") or "",
            "dnssec": result.get("dnssec") or "",
            "name_servers": result.get("name_servers") or [],
            "mx_records": result.get("mx_records") or [],
            "ipv4_addresses": result.get("ipv4_addresses") or [],
            "ipv6_addresses": result.get("ipv6_addresses") or [],
            "domain_status": result.get("domain_status") or [],
            "ipv4_locations": result.get("ipv4_locations") or [],
            "ipv6_locations": result.get("ipv6_locations") or []
        }
        # Calculate domain age (in days) if creation_date is available in YYYY-MM-DD format
        if response["creation_date"]:
            try:
                # Some APIs return date with time, take only first part
                creation_str = response["creation_date"].split()[0]
                creation_dt = datetime.strptime(creation_str, "%Y-%m-%d")
                diff = relativedelta(datetime.utcnow(), creation_dt)
                years = diff.years
                months = diff.months
                days = diff.days
                parts = []
                if years:
                    parts.append(f"{years} year{'s' if years != 1 else ''}")
                # Always include months, even if zero
                parts.append(f"{months} month{'s' if months != 1 else ''}")
                # Always include days, even if zero
                parts.append(f"{days} day{'s' if days != 1 else ''}")
                response["domain_age"] = " ".join(parts)
            except Exception:
                response["domain_age"] = ""
        else:
            response["domain_age"] = ""

        return response
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Error making API request: {str(e)}")
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"Error parsing API response: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")
