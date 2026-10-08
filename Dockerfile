FROM node:24-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:24-slim
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
# Optional deps are the terminal dashboard (blessed); serve never loads them.
RUN npm ci --omit=dev --omit=optional && npm cache clean --force
COPY --from=build /app/dist ./dist
COPY --from=build /app/data ./data
USER node
ENTRYPOINT ["node", "dist/index.js", "serve"]
