import requests
from dotenv import load_dotenv
import os

load_dotenv()

class AbuseService:
    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')
    ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

    @staticmethod
    def get_abuse_info(ip: str):
        if not AbuseService.ABUSEIPDB_API_KEY:
            raise Exception("AbuseIPDB API key not configured")

        try:
            headers = {
                'Accept': 'application/json',
                'Key': AbuseService.ABUSEIPDB_API_KEY
            }
            
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90
            }
            
            response = requests.get(
                AbuseService.ABUSEIPDB_URL,
                headers=headers,
                params=params
            )
            response.raise_for_status()
            data = response.json()

            return data.get('data', {})
        except Exception as e:
            raise Exception(f"Error fetching abuse data: {str(e)}")
