# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Exclude the database file if present
RUN rm -f test.db || true

# Copy SSL certificates
COPY key.pem /app/key.pem
COPY cert.pem /app/cert.pem

# Expose the HTTPS port
EXPOSE 8443

# Command to run the app with SSL
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8443", "--ssl-keyfile", "/app/key.pem", "--ssl-certfile", "/app/cert.pem"] 