FROM node:20-alpine

WORKDIR /app

RUN corepack enable && corepack prepare yarn@1.22.22 --activate

COPY package.json yarn.lock ./
COPY apps/api/package.json apps/api/package.json
COPY apps/web/package.json apps/web/package.json

RUN yarn install --frozen-lockfile

COPY . .

EXPOSE 4000

CMD ["yarn", "workspace", "@dast-qa/api", "start"]
