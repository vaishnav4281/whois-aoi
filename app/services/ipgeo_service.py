import requests
from dotenv import load_dotenv
import os

load_dotenv()

class IPGeoService:
    IP2LOCATION_API_KEY = os.getenv('IP2LOCATION_API_KEY')
    IP2LOCATION_URL = "https://api.ip2location.com/v2/"

    @staticmethod
    def get_ip_info(ip: str):
        if not IPGeoService.IP2LOCATION_API_KEY:
            raise Exception("IP2Location API key not configured")

        try:
            params = {
                'ip': ip,
                'key': IPGeoService.IP2LOCATION_API_KEY,
                'package': 'WS24',
                'format': 'json'
            }
            
            response = requests.get(IPGeoService.IP2LOCATION_URL, params=params)
            response.raise_for_status()
            data = response.json()

            return {
                "ip": ip,
                "country_name": data.get('country_name'),
                "region_name": data.get('region_name'),
                "city_name": data.get('city_name'),
                "asn": data.get('asn'),
                "as": data.get('as'),
                "timezone": data.get('timezone'),
                "is_proxy": data.get('is_proxy') == 'YES'
            }
        except Exception as e:
            raise Exception(f"Error fetching IP geolocation data: {str(e)}")
