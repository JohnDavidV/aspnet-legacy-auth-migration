using System.Security.Claims;
using LegacyAuth.Api.Security;
using LegacyAuth.Api.Users;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

var builder = WebApplication.CreateBuilder(args);

// Secrets come from configuration (user-secrets / environment), never from source code.
var linkKey = builder.Configuration["Security:LinkSigningKey"];
if (string.IsNullOrWhiteSpace(linkKey) || Convert.FromBase64String(linkKey).Length < 32)
    throw new InvalidOperationException("Security:LinkSigningKey must be a base64 key of at least 32 bytes.");

builder.Services.AddSingleton(new PasswordHasher(builder.Configuration.GetValue("Security:Pbkdf2Iterations", 600_000)));
builder.Services.AddSingleton(new SignedLinks(Convert.FromBase64String(linkKey)));
builder.Services.AddSingleton<LoginThrottle>();
builder.Services.AddSingleton<IUserStore>(sp => new InMemoryUserStore(DemoData.Users(sp.GetRequiredService<PasswordHasher>())));
builder.Services.AddSingleton<AuthService>();

builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(o =>
    {
        o.Cookie.Name = "__Host-session";
        o.Cookie.HttpOnly = true;
        o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        o.Cookie.SameSite = SameSiteMode.Strict;
        o.ExpireTimeSpan = TimeSpan.FromMinutes(30);
        o.SlidingExpiration = true;
        // An API answers 401/403 instead of redirecting to a login page.
        o.Events.OnRedirectToLogin = ctx => { ctx.Response.StatusCode = 401; return Task.CompletedTask; };
        o.Events.OnRedirectToAccessDenied = ctx => { ctx.Response.StatusCode = 403; return Task.CompletedTask; };
    });
builder.Services.AddAuthorization(o => o.AddPolicy("PasswordUpToDate", p => p.RequireClaim("pwd_ok", "true")));

var app = builder.Build();

app.Use(async (ctx, next) =>
{
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    ctx.Response.Headers["X-Frame-Options"] = "DENY";
    ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
    await next();
});
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

app.MapPost("/auth/login", async (LoginRequest req, AuthService auth, HttpContext ctx) =>
{
    var result = auth.Login(req.Username ?? "", req.Password ?? "");
    switch (result.Status)
    {
        case LoginStatus.LockedOut:
            ctx.Response.Headers.RetryAfter = ((int)Math.Ceiling(result.RetryAfter!.Value.TotalSeconds)).ToString();
            return Results.Problem("Too many failed attempts. Try again later.", statusCode: 429);
        case LoginStatus.InvalidCredentials:
            return Results.Problem("Invalid username or password.", statusCode: 401);
    }

    var user = result.User!;
    var identity = new ClaimsIdentity(
    [
        new Claim(ClaimTypes.Name, user.Username),
        new Claim("display_name", user.DisplayName),
        new Claim("pwd_ok", result.Status == LoginStatus.Ok ? "true" : "false"),
    ], CookieAuthenticationDefaults.AuthenticationScheme);
    await ctx.SignInAsync(new ClaimsPrincipal(identity));
    return Results.Ok(new { user = user.DisplayName, mustChangePassword = result.Status == LoginStatus.MustChangePassword });
});

app.MapPost("/auth/change-password", async (ChangePasswordRequest req, AuthService auth, HttpContext ctx) =>
{
    var username = ctx.User.Identity!.Name!;
    var errors = auth.ChangePassword(username, req.CurrentPassword ?? "", req.NewPassword ?? "");
    if (errors.Count > 0) return Results.ValidationProblem(new Dictionary<string, string[]> { ["newPassword"] = [.. errors] });
    var identity = new ClaimsIdentity(ctx.User.Claims.Where(c => c.Type != "pwd_ok").Append(new Claim("pwd_ok", "true")),
        CookieAuthenticationDefaults.AuthenticationScheme);
    await ctx.SignInAsync(new ClaimsPrincipal(identity));
    return Results.NoContent();
}).RequireAuthorization();

app.MapPost("/auth/logout", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync();
    return Results.NoContent();
});

// A logged-in employee asks for a shareable link to their own certificate.
app.MapPost("/certificates/link", (SignedLinks links, HttpContext ctx) =>
{
    var username = ctx.User.Identity!.Name!;
    var (expires, sig) = links.Sign("certificate", username, TimeSpan.FromHours(24));
    return Results.Ok(new { url = $"/certificates/download?id={Uri.EscapeDataString(username)}&exp={expires}&sig={sig}", expires });
}).RequireAuthorization("PasswordUpToDate");

// Anyone with the link (e.g. a bank) can download until it expires; no login required.
app.MapGet("/certificates/download", (string id, long exp, string sig, SignedLinks links, IUserStore users) =>
{
    if (!links.Verify("certificate", id, exp, sig)) return Results.Problem("This link is invalid or has expired.", statusCode: 403);
    var user = users.Find(id);
    if (user is null) return Results.NotFound();
    var text = $"CERTIFICATE\n\nThis certifies that {user.DisplayName} works at Demo Corp.\nIssued {DateTime.UtcNow:yyyy-MM-dd}.";
    return Results.Text(text, "text/plain");
});

app.Run();

public record LoginRequest(string? Username, string? Password);
public record ChangePasswordRequest(string? CurrentPassword, string? NewPassword);

public partial class Program;

internal static class DemoData
{
    /// <summary>The three kinds of rows a legacy users table typically contains.</summary>
    public static IEnumerable<User> Users(PasswordHasher hasher) =>
    [
        new("ana", "Ana Torres", hasher.Hash("modern-passphrase-1")),
        new("luis", "Luis Pérez", PasswordHasher.LegacySha256Prefix + "$" + PasswordHasher.Sha256Hex("luis-old-pass")),
        new("maria", "María Gómez", "maria2015", MustChangePassword: true),
    ];
}
