"""Embedded Dockerfile fixtures.

They live in Python rather than on disk so that the corpus-aware ``DF010`` rule
(which stats ``.dockerignore`` in the build context) cannot accidentally pick up
this repository's own ignore file or its absence while tests run.  Tests that do
exercise ``.dockerignore`` create it explicitly - see ``TestDockerignore``.

Every credential-shaped value here is obviously fake on purpose: ``CHANGEME``,
``example-token-1234``, ``hunter2-not-a-real-password``.  Nothing in this
repository is a usable secret, and nothing may ever become one.
"""

#: A single-stage image that trips a wide range of rules.  Used for the
#: "negative control" (a bad Dockerfile must produce findings).
BAD = """\
FROM node:latest
ENV NPM_TOKEN=example-token-1234
ARG DB_PASSWORD=CHANGEME
WORKDIR /app
COPY . .
RUN npm install
RUN apt-get update && apt-get install -y curl
ADD app.py /app/
RUN curl -fsSL https://example.com/install.sh | bash
CMD ["node", "server.js"]
"""

#: A hardened multi-stage image that must produce exactly zero findings.
#: ``.dockerignore`` must contain .git, node_modules and .env next to it.
GOOD = """\
FROM node:20.11.1-alpine3.19 AS build
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY src/ ./src/
RUN npm run build

FROM node:20.11.1-alpine3.19
RUN apk add --no-cache tini \\
    && addgroup -S app \\
    && adduser -S -G app app
WORKDIR /app
COPY --from=build --chown=app:app /build/dist ./dist
COPY --from=build --chown=app:app /build/node_modules ./node_modules
COPY --chown=app:app package.json ./
ENV NODE_ENV=production
USER app
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
    CMD ["node", "dist/healthcheck.js"]
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "dist/server.js"]
"""

#: A correct ``.dockerignore`` for :data:`GOOD`.
DOCKERIGNORE_GOOD = """\
.git
.gitignore
node_modules
.env
.env.*
.venv
__pycache__
*.log
Dockerfile*
README.md
"""

#: ``.dockerignore`` that exists but misses .git, node_modules and .env.
DOCKERIGNORE_WEAK = """\
*.log
*.tmp
coverage
"""

#: A scratch stage with a RUN after the switch: known-fatal, unbuildable.
SCRATCH_WITH_RUN = """\
FROM alpine:3.19 AS fetch
RUN wget -O /out/app https://example.com/app

FROM scratch
COPY --from=fetch /out/app /app
RUN chmod +x /app
USER 65532:65532
ENTRYPOINT ["/app"]
"""

#: Distroless final stage with a RUN in it, same fatal class as scratch.
DISTROLESS_WITH_RUN = """\
FROM golang:1.22.1 AS build
WORKDIR /src
RUN go build -o /out/app ./cmd/app

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
RUN adduser -D app
USER nonroot:nonroot
ENTRYPOINT ["/app"]
"""
