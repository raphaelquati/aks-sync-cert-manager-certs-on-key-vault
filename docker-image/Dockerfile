# Use Python 3.13 slim image with latest security patches
FROM python:3.13-slim

# Set working directory
WORKDIR /app

# Install system dependencies and security updates
RUN apt-get update && apt-get install -y \
    gcc \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY cert_monitor.py .

# Create non-root user for security
RUN groupadd -r certmonitor && useradd -r -g certmonitor certmonitor
RUN chown -R certmonitor:certmonitor /app
USER certmonitor

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Run the application
CMD ["python", "cert_monitor.py"]
