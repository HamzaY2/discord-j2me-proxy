FROM node:alpine

WORKDIR /app
COPY . .

WORKDIR /app/proxy
RUN npm install

# Set up websocket service
WORKDIR /app/websocket
RUN npm ci
RUN npm run build

# Copy NGINX configuration
COPY nginx.conf /etc/nginx/nginx.conf

# --------------------
# Startup Script
# --------------------

# Copy the startup script to /app
COPY start.sh ./start.sh

# Ensure the script has Unix line endings and is executable
RUN sed -i 's/\r$//' ./start.sh && chmod +x ./start.sh

# Expose necessary ports
EXPOSE 80 8080 8081

VOLUME /app/ssl

# Start both applications using the startup script
CMD ["/app/start.sh"]