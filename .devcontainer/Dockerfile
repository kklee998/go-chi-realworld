FROM mcr.microsoft.com/devcontainers/go:1.21-bookworm
# Install httpie
RUN curl -SsL https://packages.httpie.io/deb/KEY.gpg | sudo gpg --dearmor -o /usr/share/keyrings/httpie.gpg
RUN sudo echo "deb [arch=amd64 signed-by=/usr/share/keyrings/httpie.gpg] https://packages.httpie.io/deb ./" > /etc/apt/sources.list.d/httpie.list
# Install nodejs
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
RUN export DEBIAN_FRONTEND=noninteractive \
    && apt-get update \
    && apt-get -y install --no-install-recommends \
    postgresql-client-15 \
    httpie \
    nodejs

RUN go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
RUN go install -tags 'pgx5' github.com/golang-migrate/migrate/v4/cmd/migrate@latest