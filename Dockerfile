FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p logs alerts static/sounds templates sample_logs

EXPOSE 5000

CMD ["python", "SentinelSOC_Pro.py"]
