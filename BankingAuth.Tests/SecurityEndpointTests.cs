using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;

namespace BankingAuth.Tests;

public class SecurityEndpointTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public SecurityEndpointTests(WebApplicationFactory<Program> factory) => _client = factory.CreateClient();

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
}
