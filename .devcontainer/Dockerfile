FROM python:3.13-slim

# Install related packages
RUN apt-get update && apt-get install -y build-essential vim curl wget git jq
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Environment variables
ENV PYTHONUNBUFFERED 1
ENV PATH "/.venv/bin:${PATH}"
ENV GOOGLE_CLOUD_LOCATION global

# Resolve dependencies for apps
COPY pyproject.toml .
COPY uv.lock .
RUN uv sync

# Working directory
WORKDIR /workspace
