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
        Assert.Contains(unauthRoutes, route => route.FilePath == "UserController.cs");
        Assert.Contains(routesArtifact.Routes, route => route.FilePath == "SecureController.cs" && route.HasAuthHint);
        Assert.Contains(routesArtifact.Routes, route => route.PathPattern == "/api/public" && !route.HasAuthHint);
        Assert.Contains(routesArtifact.Routes, route => route.PathPattern == "/api/private" && route.HasAuthHint);
    }

    [Fact]
    public async Task FrameworkRouteAnalyzer_DoesNotTreatExpressMiddlewareAsEndpoint()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "server.ts"), """
        app.use(corsMiddleware());
        app.use(compression());
        app.use('/api', router);
        """);

        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);
        var result = await new FrameworkRouteAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        var artifact = Assert.Single(result.Artifacts!, art => art.Key == FrameworkRouteArtifact.ArtifactKey);
        var routesArtifact = Assert.IsType<FrameworkRouteArtifact>(artifact.Value);
        var route = Assert.Single(routesArtifact.Routes);
        Assert.Equal("/api", route.PathPattern);
        Assert.DoesNotContain(result.Findings, finding => finding.Message.Contains("corsMiddleware", StringComparison.Ordinal));
        Assert.DoesNotContain(result.Findings, finding => finding.Message.Contains("compression", StringComparison.Ordinal));
    }

    [Fact]
    public async Task FrameworkRouteAnalyzer_DoesNotTreatPythonPathHelpersAsDjangoRoutes()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "script.py"), """
        from pathlib import Path
        from typing import Annotated
        subprocess.run(f"dpkg-deb -x {Path(deb_file)} {tmp_dir}", shell=True)
        item_id: Annotated[int, Path(title="The ID of the item to get", ge=1)]
        """);

        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);
        var result = await new FrameworkRouteAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Empty(result.Findings);
        var routesArtifact = Assert.IsType<FrameworkRouteArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Empty(routesArtifact.Routes);
    }

    [Fact]
    public async Task FrameworkRouteAnalyzer_IgnoresRouteLikeTextInsideStringsAndComments()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "RouteDocumentation.cs"), """
        public static class RouteDocumentation
        {
            private const string AttributeExample = "[HttpGet]";
            private const string MinimalApiExample = "app.MapPost(\"/example\", () => Results.Ok())";

            // app.MapGet("/comment", () => Results.Ok());
            /*
              [Route("api/comment")]
            */
        }
        """);

        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);
        var result = await new FrameworkRouteAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Empty(result.Findings);
        var routesArtifact = Assert.IsType<FrameworkRouteArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Empty(routesArtifact.Routes);
    }

    [Fact]
    public async Task FrameworkRouteAnalyzer_DetectsLineAnchoredDjangoRoutes()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "urls.py"), """
        urlpatterns = [
            path("admin/", admin.site.urls),
            re_path(r"^api/$", view),
        ]
        """);

        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);
        var result = await new FrameworkRouteAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        var routesArtifact = Assert.IsType<FrameworkRouteArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Equal(2, routesArtifact.Routes.Count);
        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-CODE012");
    }

    [Fact]
    public async Task FrameworkRouteAnalyzer_DoesNotTreatDjangoUrlHelperCallsAsRoutes()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "views.py"), """
        def render_link(url):
            return url("admin:index")
        """);

        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);
        var result = await new FrameworkRouteAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Empty(result.Findings);
        var routesArtifact = Assert.IsType<FrameworkRouteArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Empty(routesArtifact.Routes);
    }

    [Fact]
    public async Task FrameworkRouteAnalyzer_TreatsDjangoAdminViewAsAuthHint()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "urls.py"), """
        urlpatterns = [
            path("secure/", admin_site.admin_view(my_view)),
        ]
        """);

        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);
        var result = await new FrameworkRouteAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-CODE012");
        var routesArtifact = Assert.IsType<FrameworkRouteArtifact>(Assert.Single(result.Artifacts!).Value);
        var route = Assert.Single(routesArtifact.Routes);
        Assert.True(route.HasAuthHint);
    }

    [Fact]
    public async Task FrameworkRouteAnalyzer_SkipsDjangoContribFrameworkRouter()
    {
        using var fixture = TemporaryRepository.Create();
        var filePath = Path.Combine(fixture.Path, "django", "contrib", "auth", "urls.py");
        Directory.CreateDirectory(Path.GetDirectoryName(filePath)!);
        File.WriteAllText(filePath, """
        urlpatterns = [
            path("login/", views.LoginView.as_view(), name="login"),
            path("logout/", views.LogoutView.as_view(), name="logout"),
        ]
        """);

        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);
        var result = await new FrameworkRouteAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Empty(result.Findings);
        var routesArtifact = Assert.IsType<FrameworkRouteArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Empty(routesArtifact.Routes);
    }

    [Fact]
    public async Task FrameworkRouteAnalyzer_SkipsDjangoConfUrlFrameworkInternals()
    {
        using var fixture = TemporaryRepository.Create();
        var filePath = Path.Combine(fixture.Path, "django", "conf", "urls", "i18n.py");
        Directory.CreateDirectory(Path.GetDirectoryName(filePath)!);
        File.WriteAllText(filePath, """
        urlpatterns = [
            path("setlang/", set_language, name="set_language"),
        ]
        """);

        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);
        var result = await new FrameworkRouteAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Empty(result.Findings);
        var routesArtifact = Assert.IsType<FrameworkRouteArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Empty(routesArtifact.Routes);
    }

    [Fact]
    public async Task FrameworkRouteAnalyzer_SkipsSpringFrameworkInternalRouteClasses()
    {
        using var fixture = TemporaryRepository.Create();
        var filePath = Path.Combine(
            fixture.Path,
            "module",
            "spring-boot-webmvc",
            "src",
            "main",
            "java",
            "org",
            "springframework",
            "boot",
            "webmvc",
            "autoconfigure",
            "error",
            "BasicErrorController.java");
        Directory.CreateDirectory(Path.GetDirectoryName(filePath)!);
        File.WriteAllText(filePath, """
        @RequestMapping("${spring.web.error.path:${error.path:/error}}")
        public class BasicErrorController {
        }
        """);

        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);
        var result = await new FrameworkRouteAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Empty(result.Findings);
        var routesArtifact = Assert.IsType<FrameworkRouteArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Empty(routesArtifact.Routes);
    }

    [Fact]
    public async Task FrameworkRouteAnalyzer_SkipsSpringAnnotationDeclarations()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "ControllerEndpoint.java"), """
        @GetMapping
        @PostMapping
        public @interface ControllerEndpoint {
        }
        """);

        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);
        var result = await new FrameworkRouteAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Empty(result.Findings);
        var routesArtifact = Assert.IsType<FrameworkRouteArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Empty(routesArtifact.Routes);
    }

    [Fact]
    public async Task FrameworkRouteAnalyzer_DoesNotTreatControllerTypeAsAuthentication()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "OpenController.cs"), """
        [ApiController]
        [Route("api/open")]
        public class OpenController : ControllerBase
        {
            [HttpGet]
            public IActionResult Get() => Ok();
        }
        """);

        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);
        var result = await new FrameworkRouteAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.RuleId == "TRUST-CODE012");
        var artifact = Assert.Single(result.Artifacts!, art => art.Key == FrameworkRouteArtifact.ArtifactKey);
        var routesArtifact = Assert.IsType<FrameworkRouteArtifact>(artifact.Value);
        Assert.All(routesArtifact.Routes, route => Assert.False(route.HasAuthHint));
    }

    [Fact]
    public async Task FrameworkRouteAnalyzer_TreatsMinimalApiAllowAnonymousAsIntentionalPublicAccess()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Program.cs"), """
        var app = WebApplication.Create();
        app.MapGet("/health", () => "ok").AllowAnonymous();
        app.Run();
        """);

        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);
        var result = await new FrameworkRouteAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-CODE012");
        var routesArtifact = Assert.IsType<FrameworkRouteArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.All(routesArtifact.Routes, route => Assert.True(route.HasAuthHint));
    }

    [Fact]
    public async Task FrameworkRouteAnalyzer_DetectsAuthHintAfterMultilineMinimalApiHandler()
    {
        using var fixture = TemporaryRepository.Create();
        File.WriteAllText(Path.Combine(fixture.Path, "Program.cs"), """
        var app = WebApplication.Create();
        app.MapGet("/health", () =>
        {
            var status = new
            {
                name = "repo-trust-doctor",
                version = "test",
                ok = true
            };

            return Results.Ok(status);
        }).AllowAnonymous();
        app.Run();
        """);

        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);
        var result = await new FrameworkRouteAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.DoesNotContain(result.Findings, finding => finding.RuleId == "TRUST-CODE012");
        var routesArtifact = Assert.IsType<FrameworkRouteArtifact>(Assert.Single(result.Artifacts!).Value);
        var route = Assert.Single(routesArtifact.Routes);
        Assert.True(route.HasAuthHint);
        Assert.Equal("/health", route.PathPattern);
    }

    [Fact]
    public async Task FrameworkRouteAnalyzer_SkipsTestSourceFiles()
    {
        using var fixture = TemporaryRepository.Create();
        var directory = Directory.CreateDirectory(Path.Combine(fixture.Path, "tests"));
        File.WriteAllText(Path.Combine(directory.FullName, "RouteFixtureTests.cs"), """
        public sealed class RouteFixtureTests
        {
            private const string Fixture = "app.MapGet(\"/fixture\", () => \"ok\");";
        }
        """);

        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);
        var result = await new FrameworkRouteAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Empty(result.Findings);
        var routesArtifact = Assert.IsType<FrameworkRouteArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Empty(routesArtifact.Routes);
    }

    [Theory]
    [InlineData("playground/ssr/server.js")]
    [InlineData("examples/web/server.js")]
    [InlineData("samples/web/server.js")]
    [InlineData("integration-test/spring-boot-sni/src/main/java/HelloController.java")]
    [InlineData("smoke-test/spring-boot-smoke-test/src/main/java/HelloController.java")]
    [InlineData("module/spring-boot-web-server/src/testFixtures/java/HelloController.java")]
    [InlineData("module/spring-boot-amqp/src/dockerTest/java/HelloController.java")]
    [InlineData("module/spring-boot-devtools/src/intTest/java/com/example/ControllerOne.java")]
    [InlineData("src/Framework/AspNetCoreAnalyzers/src/Analyzers/MvcAnalyzer.cs")]
    [InlineData("src/Components/Testing/src/Infrastructure/ServerFixture.cs")]
    [InlineData("src/Identity/testassets/Identity.DefaultUI.WebSite/server.js")]
    [InlineData("src/Http/Http.Extensions/gen/GeneratedEndpoint.cs")]
    [InlineData("src/Http/Http/perf/Microbenchmarks/RequestDelegateGeneratorBenchmarks.cs")]
    [InlineData("src/ProjectTemplates/Web.ProjectTemplates/content/EmptyWeb-CSharp/Program.cs")]
    [InlineData("fixtures/routes/server.js")]
    [InlineData("docs/demo/server.js")]
    public async Task FrameworkRouteAnalyzer_SkipsExampleAndPlaygroundSourceFiles(string relativePath)
    {
        using var fixture = TemporaryRepository.Create();
        var filePath = Path.Combine(fixture.Path, relativePath.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(filePath)!);
        File.WriteAllText(filePath, """
        app.use('*all', async (req, res) => {
          res.end('demo')
        });
        app.MapPost("/_ready/{token}", () => Results.Ok());
        @GetMapping("/hello")
        public String hello() { return "ok"; }
        """);

        var context = new AnalysisContext(fixture.Path, fixture.Path, AnalysisDepth.Deep);
        var result = await new FrameworkRouteAnalyzer().AnalyzeAsync(context, CancellationToken.None);

        Assert.Empty(result.Findings);
        var routesArtifact = Assert.IsType<FrameworkRouteArtifact>(Assert.Single(result.Artifacts!).Value);
        Assert.Empty(routesArtifact.Routes);
    }
}
