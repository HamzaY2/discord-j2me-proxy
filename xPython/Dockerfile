FROM python:3.13-slim

WORKDIR /app

# Copy and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the default port (adjust if different)
EXPOSE 8081

# Run the application
CMD ["python", "xWebsocket.py"]

# deploy this app on Render.com