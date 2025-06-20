FROM node:20.11.1-alpine3.19

WORKDIR /app

COPY package.json ./
COPY optimizer.js ./
COPY index.html ./ # 新增：复制 index.html 文件

EXPOSE 3000

RUN apk add --no-cache curl bash && \
    npm install && \
    chmod +x optimizer.js

CMD ["npm", "start"]
