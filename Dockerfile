FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --create-home --uid 10001 agent

COPY --chown=agent:agent src ./src
COPY --chown=agent:agent test_runner.py ./test_runner.py
RUN mkdir -p /app/artifacts/trajectories \
    && chown -R agent:agent /app/artifacts

USER agent

ENTRYPOINT ["python", "-m", "vulnerability_agent.cli"]
CMD ["--help"]
