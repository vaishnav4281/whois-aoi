import dns.resolver

class DNSService:
    @staticmethod
    def get_a_records(domain: str):
        try:
            answers = dns.resolver.resolve(domain, 'A')
            return [str(answer) for answer in answers]
        except dns.resolver.NoAnswer:
            return []
        except Exception as e:
            raise Exception(f"Error fetching DNS records: {str(e)}")
