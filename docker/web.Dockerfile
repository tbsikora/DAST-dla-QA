FROM node:20-alpine AS builder

WORKDIR /app

RUN corepack enable && corepack prepare yarn@1.22.22 --activate

# Railway Docker builds require ARG to pass service variables into build-time env.
ARG VITE_API_URL
ENV VITE_API_URL=$VITE_API_URL

COPY package.json yarn.lock ./
COPY apps/api/package.json apps/api/package.json
COPY apps/web/package.json apps/web/package.json

RUN yarn install --frozen-lockfile

COPY . .

RUN yarn workspace web build

FROM nginx:1.27-alpine

ENV API_UPSTREAM=http://api:4000
ENV NGINX_ENVSUBST_FILTER=^API_UPSTREAM$

COPY docker/nginx.conf /etc/nginx/templates/default.conf.template
COPY --from=builder /app/apps/web/dist /usr/share/nginx/html

EXPOSE 80
