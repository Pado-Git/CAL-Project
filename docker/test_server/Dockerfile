FROM python:3.9-slim

WORKDIR /app

# Install system dependencies for RCE testing (curl, wget)
RUN apt-get update && \
    apt-get install -y curl wget && \
    rm -rf /var/lib/apt/lists/*

# Install Flask
RUN pip install flask

# Copy application
COPY app.py /app/

# Expose port
EXPOSE 8888

# Run the application
CMD ["python", "app.py"]
