# Use Python 3.8 as base image
FROM python:3.8

# Set working directory
WORKDIR /code/

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Copy project files into the Docker image
COPY pyproject.toml poetry.lock /code/

# Install Poetry
RUN pip install --upgrade pip \
    && pip install poetry

# Install project dependencies
RUN poetry config virtualenvs.create false \
    && poetry install --no-dev

# Copy the rest of the project files
COPY . /code/

# Expose port 8000
EXPOSE 8000

# Command to run the application
CMD ["poetry", "run", "uvicorn", "user_service.main:app", "--host", "0.0.0.0", "--port", "8000"]
