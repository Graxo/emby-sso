# The vendor's licence and purchase service.
#
# NOTHING SECRET IS IN THIS IMAGE. No signing key, no PayPal credentials, no
# database. The key is bind-mounted read-only at runtime and the service
# refuses to start if it is missing or readable by anyone but its owner; the
# credentials come from the environment; the state lives on a volume. An image
# built from this file can be pushed to a public registry without a second
# thought, and that is deliberate - see service/README.md, "What an attacker
# who gets root on this box can do".
#
# UNBUILT. Docker was not available in the environment this was written in, so
# this file has never been through `docker build`. It is short and ordinary, but
# treat the first build as a thing to watch rather than a formality.

FROM mcr.microsoft.com/dotnet/sdk:8.0.424-bookworm-slim AS build
WORKDIR /src

# Project files first, so a change to a .cs file does not re-restore packages.
COPY src/Emby.Sso.Licensing/Emby.Sso.Licensing.csproj src/Emby.Sso.Licensing/
COPY src/Emby.Sso.LicenceService/Emby.Sso.LicenceService.csproj src/Emby.Sso.LicenceService/
RUN dotnet restore src/Emby.Sso.LicenceService/Emby.Sso.LicenceService.csproj

COPY src/ src/
RUN dotnet publish src/Emby.Sso.LicenceService/Emby.Sso.LicenceService.csproj \
      -c Release \
      -o /app \
      --no-restore \
      /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:8.0.30-bookworm-slim AS runtime

# A named non-root account with a fixed uid. Fixed because the signing key on
# the host has to be readable by exactly this uid and by nobody else, and
# "chown 5678" is an instruction the operator can follow; a uid that moved
# between image builds would silently break the mount.
RUN groupadd --gid 5678 licence \
 && useradd --uid 5678 --gid 5678 --no-create-home --shell /usr/sbin/nologin licence

WORKDIR /app
COPY --from=build --chown=root:root /app .

# The volume. The image declares it so that a `docker run` without a -v still
# keeps its state somewhere rather than losing every sale on restart - though
# the compose file below always names one explicitly.
RUN mkdir -p /data && chown 5678:5678 /data
VOLUME ["/data"]

ENV ASPNETCORE_URLS=http://+:8080 \
    ASPNETCORE_ENVIRONMENT=Production \
    DOTNET_NOLOGO=1 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    LICENCE_DATA_DIR=/data \
    LICENCE_SIGNING_KEY_PATH=/run/secrets/licence-signing-key.private.json

EXPOSE 8080
USER 5678:5678

# Asks /healthz, using the service's own binary: the aspnet runtime image has
# no curl and no wget, and adding one would put a package - and its CVE feed -
# on the machine that holds the signing key.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["dotnet", "Emby.Sso.LicenceService.dll", "healthcheck"]

# No shell form, so the process is PID 1 and gets SIGTERM directly.
ENTRYPOINT ["dotnet", "Emby.Sso.LicenceService.dll"]
