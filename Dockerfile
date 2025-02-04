FROM node:alpine

WORKDIR /app
COPY . .

WORKDIR /app/proxy
RUN npm install

# WORKDIR /app/websocket
# RUN npm install
# RUN npm run build

EXPOSE 8080
#EXPOSE 8081

WORKDIR /app

# & node websocket/out/index.js
CMD sh -c "node proxy/index.js && wait" 
