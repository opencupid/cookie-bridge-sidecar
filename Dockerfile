FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --production
COPY index.js .
EXPOSE 3099
CMD ["node", "index.js"]
