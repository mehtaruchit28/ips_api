using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using IPS_API.Models;

namespace IPS_API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class LoginController : ControllerBase
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<LoginController> _logger;


    public LoginController(
        IConfiguration configuration, 
        ILogger<LoginController> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }

    [HttpPost("login")]
    [AllowAnonymous]
    public IActionResult Login([FromBody] LoginRequest loginRequest)
    {
        if (string.IsNullOrEmpty(loginRequest.Username) || string.IsNullOrEmpty(loginRequest.Password))
        {
            return BadRequest(new { message = "Username and password are required." });
        }

        // TODO: Replace this with your actual user validation logic (e.g., database lookup)
        // This is a sample validation - DO NOT use in production
        if (loginRequest.Username == "admin" && loginRequest.Password == "password123")
        {
            var token = GenerateJwtToken(loginRequest.Username);
            var expiresAt = DateTime.UtcNow.AddHours(1);

            _logger.LogInformation("User {Username} logged in successfully at {Time}", loginRequest.Username, DateTime.UtcNow);

            return Ok(new LoginResponse
            {
                Token = token,
                Username = loginRequest.Username,
                ExpiresAt = expiresAt
            });
        }

        _logger.LogWarning("Failed login attempt for username: {Username}", loginRequest.Username);
        return Unauthorized(new { message = "Invalid username or password." });
    }

    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        // Get the username from the token claims
        var username = User.FindFirst(ClaimTypes.Name)?.Value;

        return Ok(new { message = "Logged out successfully. Token has been revoked." });
    }

    private string GenerateJwtToken(string username)
    {
        var jwtSettings = _configuration.GetSection("JwtSettings");
        var secretKey = jwtSettings["SecretKey"] ?? throw new InvalidOperationException("JWT SecretKey is not configured.");
        var issuer = jwtSettings["Issuer"] ?? "IPS_API";
        var audience = jwtSettings["Audience"] ?? "IPS_API_Users";
        var expiryInHours = int.Parse(jwtSettings["ExpiryInHours"] ?? "1");

        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(ClaimTypes.Name, username),
            new Claim(JwtRegisteredClaimNames.Sub, username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
        };

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            expires: DateTime.UtcNow.AddHours(expiryInHours),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
