FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir .[ml]
RUN python training/train_all_models.py --synthetic
EXPOSE 8000
CMD ["uvicorn", "diodeshield.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
