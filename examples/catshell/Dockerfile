FROM python:3.12-slim
RUN pip install --no-cache-dir numpy scikit-learn scipy fastapi uvicorn huggingface_hub
WORKDIR /app
COPY app.py entrypoint.sh ./
RUN chmod +x entrypoint.sh
ENV CATSHELL_PORT=8011
CMD ["./entrypoint.sh"]
