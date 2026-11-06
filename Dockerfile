FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    WEBWAY_REVEAL_SECRETS=0 \
    WEBWAY_ALLOW_PRIVATE_HOSTS=0 \
    FLASK_DEBUG=0

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["gunicorn", "server:app", "--bind", "0.0.0.0:5000", "--worker-class", "gthread", "--threads", "4", "--timeout", "120"]
