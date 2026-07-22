FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY BankingAuth.Api.csproj .
RUN dotnet restore BankingAuth.Api.csproj

COPY . .
RUN dotnet publish BankingAuth.Api.csproj -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app .

# /data is where the SQLite file lives; owned by the non-root "app" user the base image ships
# with so the mounted volume is writable without running the container as root.
RUN mkdir -p /data && chown -R $APP_UID /data
USER $APP_UID

ENV ASPNETCORE_URLS=http://+:8080
ENV ASPNETCORE_ENVIRONMENT=Production
ENV ConnectionStrings__BankingAuthDb="Data Source=/data/bankingauth.db"

EXPOSE 8080
ENTRYPOINT ["dotnet", "BankingAuth.Api.dll"]
