FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends build-essential git && rm -rf /var/lib/apt/lists/*

COPY . /app

RUN pip install --upgrade pip && pip install --no-cache-dir .

EXPOSE 8000

CMD ["uvicorn", "ctf_autopwn.api.server:app", "--host", "0.0.0.0", "--port", "8000"]
