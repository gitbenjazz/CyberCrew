# -------------------------
# CyberCrew Dockerfile
# Clean, reproducible, production-ready
# -------------------------

# 1. Use a lightweight Python image
FROM python:3.11-slim

# 2. Set working directory inside the container
WORKDIR /app

# 3. Install system dependencies needed for Python packages
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 4. Copy requirements first (better caching)
COPY requirements.txt .

# 5. Install Python dependencies
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 6. Copy the rest of the project code
COPY . .

# 7. Default environment (can be overridden via docker run -e ENV=dev)
ENV ENV=prod

# 8. Command used to start CyberCrew
CMD ["python", "main.py"]

