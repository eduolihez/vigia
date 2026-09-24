FROM node:22-slim AS base

ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable

WORKDIR /app

COPY package.json pnpm-lock.yaml* pnpm-workspace.yaml* ./
RUN corepack pnpm install --frozen-lockfile

COPY . .
RUN corepack pnpm run build

EXPOSE 3000

CMD ["corepack", "pnpm", "start"]
