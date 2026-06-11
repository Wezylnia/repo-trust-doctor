using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Analyzers.Codebase;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.AnalyzerTests;

public sealed class FrameworkRouteAnalyzerTests
{
    [Fact]
    public async Task FrameworkRouteAnalyzer_DetectsRoutesAndMissingAuth()
    {
        using var fixture = TemporaryRepository.Create();

        // C# Controller with Get method but no [Authorize] attribute
        File.WriteAllText(Path.Combine(fixture.Path, "UserController.cs"), """
        [ApiController]
        [Route("api/users")]
        public class UserController : ControllerBase
        {
            [HttpGet("{id}")]
            public IActionResult GetUser(string id) => Ok();
        }
        """);

        // C# Controller with Get method and [Authorize] attribute
        File.WriteAllText(Path.Combine(fixture.Path, "SecureController.cs"), """
        [ApiController]
        [Authorize]
        [Route("api/secure")]
        public class SecureController : ControllerBase
        {
            [HttpPost]
            public IActionResult Save() => Ok();
        }
        """);

        // Express.js file
        File.WriteAllText(Path.Combine(fixture.Path, "routes.js"), """
        app.get('/api/public', (req, res) => { res.send('ok'); });
        router.post('/api/private', authMiddleware, (req, res) => { res.send('ok'); });
        """);

        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);
        var result = await new FrameworkRouteAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        // Verify findings
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-CODE013"); // route detected
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-CODE012"); // HTTP endpoint without auth

        var artifact = Assert.Single(result.Artifacts!, art => art.Key == FrameworkRouteArtifact.ArtifactKey);
        var routesArtifact = Assert.IsType<FrameworkRouteArtifact>(artifact.Value);

        Assert.Equal(6, routesArtifact.Routes.Count);
        
        var unauthRoutes = routesArtifact.Routes.Where(r => !r.HasAuthHint).ToList();
        Assert.NotEmpty(unauthRoutes);
    }
}
