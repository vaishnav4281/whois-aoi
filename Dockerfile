FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY .env .
COPY . .

# Set environment variables
ENV IP2LOCATION_API_KEY=D509C2C9ABE8F74D05B02858BAB1F0B2
ENV ABUSEIPDB_API_KEY=853fb4da0616e5de34f54a8cbfe39f8735b2eafde6060eed87a16c0c268ba1fe11e43e937c215508
ENV WHOIS_API_KEY=at_hKTtzicvCvERVg3yjSH6Zhoq6a2F4

# Run the application with Gunicorn
CMD ["gunicorn", "app.main:app", "-k", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000", "--workers", "4"]
