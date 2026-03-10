FROM python:3.11-slim

WORKDIR /app

# PyMuPDF needs these system libs
RUN apt-get update && apt-get install -y --no-install-recommends \
    libfreetype6 \
    libharfbuzz0b \
    libffi8 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Temp directory for PDF sessions
RUN mkdir -p /tmp/pdf_sessions

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
