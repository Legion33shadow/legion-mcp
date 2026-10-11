FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py legion_tlog_verify.py ./
ENV MCP_TRANSPORT=http MCP_PORT=8802
CMD ["python3", "server.py"]
