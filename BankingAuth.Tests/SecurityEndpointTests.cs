using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace BankingAuth.Tests;

public class SecurityEndpointTests : IClassFixture<AuthWebApplicationFactory>
{
    private readonly HttpClient _client;

    public SecurityEndpointTests(AuthWebApplicationFactory factory) => _client = factory.CreateClient();

    [Fact]
    public async Task CustomerAndAdminEndpoints_RejectUnauthenticatedRequests()
    {
        Assert.Equal(HttpStatusCode.Unauthorized, (await _client.GetAsync("/api/customer/accounts/summary")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _client.GetAsync("/api/admin/ping")).StatusCode);
    }

    [Fact]
    public async Task HealthResponse_ContainsSecurityHeaders()
    {
        var response = await _client.GetAsync("/health");
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
    }

    [Fact]
    public async Task CustomerToken_CannotAccessAdminPing()
    {
        await _client.PostAsJsonAsync("/api/auth/register", new
        {
            email = "cust.sec@bank.test",
            password = "Secret123!",
            role = "Customer"
        });
        var login = await _client.PostAsJsonAsync("/api/auth/login", new
        {
            email = "cust.sec@bank.test",
            password = "Secret123!"
        });
        login.EnsureSuccessStatusCode();
        var body = await login.Content.ReadFromJsonAsync<JsonElement>();
        var token = body.GetProperty("accessToken").GetString()!;

        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/admin/ping");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var response = await _client.SendAsync(req);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task TellerToken_CannotAccessCustomerSummary()
    {
        await _client.PostAsJsonAsync("/api/auth/register", new
        {
            email = "teller.sec@bank.test",
            password = "Secret123!",
            role = "Teller"
        });
        var login = await _client.PostAsJsonAsync("/api/auth/login", new
        {
            email = "teller.sec@bank.test",
            password = "Secret123!"
        });
        var body = await login.Content.ReadFromJsonAsync<JsonElement>();
        var token = body.GetProperty("accessToken").GetString()!;

        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/customer/accounts/summary");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var response = await _client.SendAsync(req);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task ForgedJwt_IsRejected()
    {
        var forged = CreateForgedToken();
        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", forged);
        var response = await _client.SendAsync(req);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private static string CreateForgedToken()
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("totally-wrong-signing-key-not-in-config!!"));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            issuer: "banking-auth-service",
            audience: "banking-clients",
            claims: [new Claim(JwtRegisteredClaimNames.Sub, "attacker"), new Claim(ClaimTypes.Role, "Admin")],
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: creds);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
