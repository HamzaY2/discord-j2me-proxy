FROM node:alpine

WORKDIR /app
COPY . .

WORKDIR /app/proxy
RUN npm install

WORKDIR /app/websocket
RUN npm ci
RUN npm run build

EXPOSE 8080
EXPOSE 8081

VOLUME /app/ssl

WORKDIR /app

CMD sh -c "node proxy/index.js & node websocket/out/index.js && wait" 