FROM demo-fin-app/otel-base:latest

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY .env .

EXPOSE 8000

CMD ["opentelemetry-instrument", "python", "main.py"]
