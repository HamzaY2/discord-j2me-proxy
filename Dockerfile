FROM node:alpine

WORKDIR /app
COPY . .

WORKDIR /app/proxy
RUN npm install

WORKDIR /app/websocket
RUN npm install
RUN npm run build

EXPOSE 8080 8081

WORKDIR /app
CMD sh -c "node proxy/index.js & node websocket/out/index.js && wait"
