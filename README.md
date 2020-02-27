# Authentication and Authorization
- Generally want to use services.AddAuthentication OR services.AddIdentity, if using both services.AddAuthentication should be called first.
- [PersonalData] attribute can be used to mark data to be deleted when UserManager.Delete is called and allow downloading PersonalData.json.

## Authentication
- Determining Identity
- id_token
- OpenIDConnect

## Authorization
- What actions a user can take
- access_token
- OAuth2

## [Scheme Actions](https://github.com/aspnet/announcements/issues/262)
1. DefaultScheme: if specified, DefaultAuthenticateScheme, DefaultChallengeScheme and DefaultSignInScheme will fallback to this value.
2. DefaultAuthenticateScheme: How claims principal gets read/reconstructed on every request. If specified, AuthenticateAsync() will use this scheme, and also the AuthenticationMiddleware added by UseAuthentication() will use this scheme to set context.User automatically. (Corresponds to AutomaticAuthentication).
3. DefaultChallengeScheme: What happens when user tries to access a resource where authorization is required. e.g Redirect to Sign In. If specified, ChallengeAsync() will use this scheme, [Authorize] with policies that don't specify schemes will also use this.
4. DefaultSignInScheme:  Persists claims principal to Cookie. to Is used by SignInAsync() and also by all of the remote auth schemes like Google/Facebook/OIDC/OAuth, typically this would be set to a cookie.
5. DefaultSignOutScheme: Deletes Cookie. is used by SignOutAsync() falls back to DefaultSignInScheme.
6. DefaultForbidScheme: What happens when a user accesses a resource where authorization fails. e.g Redirect to Access Denied. is used by ForbidAsync(), falls back to DefaultChallengeScheme.

## Authentication Schemes
- Basic
- Cookie. Protected by DataProtection
- External. [Google](https://4sh.nl/GoogleAddApp), Facebook, Microsoft, Twitter. Links with Cookie Authorization
- Identity (Application + External + 2FA Cookies)
- Bearer
- OpenID Connect. Links with Cookie Authorization

## Cookie
- For on URL

```
services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
.AddCookie();
```

## Secrets
- Right Click Project > Manage User Secrets > secrets.sjon

```
dotnet user-secrets init
dotnet user-secrets set "Google:ClientId" "secret"
```

## Microsoft.AspNetCore.Authentication.Google without Microsoft.AspNetCore.Identity
```
public static class ExternalAuthenticationDefaults
{
        public const string AuthenticationScheme = "Identity.External"; // IdentityConstants.ExternalScheme "Identity.External"
}
```

```
services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme);
.AddCookie(ExternalAuthenticationDefaults.AuthenticationScheme);
.AddGoogle(o => {
	o.clientId = Configuration["Google:ClientId"];
        o.clientSecret = Configuration["Google:ClientSecret"];
        o.SignInScheme = ExternalAuthenticationDefaults.AuthenticationScheme;
});
```

## Microsoft.AspNetCore.Identity
- services.AddDefaultIdentity doesn't enable roles

```
services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection")));

services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true)
.AddEntityFrameworkStores<ApplicationDbContext>();

services.AddControllersWithViews();
services.AddRazorPages();
```
```
[assembly: HostingStartup(typeof(App.StartupIdentity))]
namespace App
{
    public class StartupIdentity : IHostingStartup
    {
        public void Configure(IWebHostBuilder builder)
        {
            builder.ConfigureServices((context, services) => {
                services.AddDbContext<IdentityContext>(options => options.UseSqlServer(context.Configuration.GetConnectionString("IdentityConnection")));
                services.AddIdentity<IdentityUser, IdentityRole>(options => options.SignIn.RequireConfirmedAccount = true).AddEntityFrameworkStores<IdentityContext>()
                .AddDefaultUI()
                .AddDefaultTokenProviders();
            });
        }
    }
}
```
```
//Register action
if (result.Succeeded)
{
        await _userManager.AddToRoleAsync(user, "admin");
        await _userManager.AddClaimAsync(user, new Claim("birthdate", new DateTime().ToShortDateString()));
}
```

## Microsoft.AspNetCore.Authentication.OpenIdConnect
```
services.AddAuthentication(options => {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;

})
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
.AddOpenIdConnection(options => {
        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.Authority = "https://localhost:44318";

        //https://www.scottbrady91.com/OpenID-Connect/ASPNET-Core-using-Proof-Key-for-Code-Exchange-PKCE
        //options.ResponseType = "code"; //Authorization
        //options.ResponseType = "id_token"; //Implicit
        //options.ResponseType = "id_token token"; //Implicit
        options.ResponseType = "code id_token"; //Hybrid MVC/Blazor Server
        //options.ResponseType = "code token"; //Hybrid
        //options.ResponseType = "code id_token token"; //Hybrid

        //code > token

        //options.CallbackPath = new PathString("...")
        //options.SignedOutCallbackPath = new PathString("...")
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("email");
        options.Scope.Add("address");
        options.Scope.Add("roles");

        options.Scope.Add("api"); //ApiResource.Name if 0 scopes else Scope.Name

        options.Scope.Add("subscriptionlevel");
        options.Scope.Add("country");
        options.Scope.Add("offline_access"); //refresh tokens, Enabled by AllowOfflineAccess = true. An alternative is AccessTokenType=Reference which allows access to removed.

        //Saves Access and Refresh Tokens in cookie for later use. Can call HttpContext.GetTokenAsync("access_token").
        //Allows for Blazor/SPA > Server > API
        options.SaveTokens = true;

        options.ClientId = "mvc_client";
        options.ClientSecret = "secret";
        options.GetClaimsFromUserInfoEndpoint = true;

        options.ClaimActions.Remove("amr");
        options.ClaimActions.DeleteClaim("sid");
        options.ClaimActions.DeleteClaim("idp");

        options.ClaimActions.MapUniqueJsonKey("role", "role");
        options.ClaimActions.MapUniqueJsonKey("subscriptionlevel", "subscriptionlevel");
        options.ClaimActions.MapUniqueJsonKey("country", "country");

        //For serialization
        options.TokenValidationParameters = new TokenValidationParameters()
        {
                NameClaimType = "given_name",
                RoleClaimType = "role"
        };

        // https://docs.microsoft.com/en-us/dotnet/api/
        // microsoft.aspnetcore.authentication.openidconnect.openidconnectevents
        options.Events.OnTicketReceived = e =>
        {
                Log.Information("Login successfully completed for {UserName}.",
                e.Principal.Identity.Name);
                return Task.CompletedTask;
        };
})
```

## Identity Server
- Single page applications use Authorization Code flow: 'code' + PKCE
- Client > Server > API use Authorization Code flow: 'code' + PKCE + secret(Reference tokens) OR Hyrbid flow: 'code id_token' + secret(Reference tokens)
- Server > API use: Client Credentials Flow + secret
- Refresh Tokens: options.Scope.Add("offline_access") and AllowOfflineAccess = true

## JWT
```
services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
.AddJwtBearer(options => {
        options.Authority = "https://localhost:5000/";
        options.Audience = "api";
});
```

## JWT + Reference Tokens
- Reference Tokens dont store claims in the access_token. Alternative to Refresh Tokens. AccesstokenType=Reference. Use IdentityServer4.AccessTokenValidation instead of JwtBearer

```
services.AddAuthentication(IdentityServerAuthenticationDefaults.AuthenticationScheme)
.AddIdentityServerAuthentication(options => {
        options.Authority = "https://localhost:44318/";
        options.ApiName = "api";
        options.ApiSecret = "apisecret"; //Only need this if AccessTokenType = AccessTokenType.Reference
        options.EnableCaching = true; //Caches response from introspection endpoint.
});
```

## Policies
- [Authorize(Policy = "CanAddConference")] [Authorize(Policy = "YearsOfExperience")]
- IAuthorizationService within Views and Pages
- Multiple policies: One must succeed, if any calls fail, access is denied.
- Resource based policies are at an object level.

```
services.AddAuthorization(options =>{
        options.AddPolicy("IsSpeaker", policy => policy.RequireRole("Speaker"));
        options.AddPolicy("CanAddConference", policy => policy.RequireClaim("Permission", "AddConference"));
        options.AddPolicy("YearsOfExperience", policy => policy.AddRequirements(new YearsOfExperiencerequirement(30)));
        options.AddPolicy("CanEditProposal", policy => policy.AddRequirements(new ProposalRequirement()));
        options.AddPolicy("PostAttendee", policy => policy.RequireClaim("scope", "api.post"));
});
```
```
public class YearsOfExperienceRequirement : IAuthorizationRequirement
{
        public YearsOfExperienceRequirement(int yearsOfExperienceRequired)
        {
                YearsOfExperienceRequired = yearsOfExperienceRequired;
        }
        public int YearsOfExperienceRequired { get; set; }
}

public class YearsOfExperienceAuthorizationHandler :
        AuthorizationHandler<YearsOfExperienceRequirement>
{

        protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        YearsOfExperienceRequirement requirement)
        {
                if (!context.User.HasClaim(c => c.Type == "CareerStarted" &&
                c.Issuer == "https://localhost:5000"))
                {
                return Task.CompletedTask;
                }

                var careerStarted = DateTimeOffset.Parse(
                context.User.FindFirst(c => c.Type == "CareerStarted"
                        && c.Issuer == "https://localhost:5000").Value
                );

                var yearsOfExperience =
                Math.Round((DateTimeOffset.Now - careerStarted).TotalDays / 365);

                if (yearsOfExperience >= requirement.YearsOfExperienceRequired)
                context.Succeed(requirement);

                return Task.CompletedTask;
        }
}
```
```
public class ProposalRequirement : IAuthorizationRequirement
{
}

public class ProposalApprovedAuthorizationHandler : AuthorizationHandler<ProposalRequirement, ProposalModel>
{
        protected override Task HandleRequirementAsync(
                AuthorizationHandlerContext context,
                ProposalRequirement requirement,
                ProposalModel resource)
        {
                if (!resource.Approved)
                context.Succeed(requirement);

                return Task.CompletedTask;
        }
}

var result = await _authorizationService.AuthorizeAsync(User, proposal, "CanEditProposal");
if(result.Succeeded)
{
        return View();
}

return RedirectToAction("AccessDenied", "Account");
```

```
public static class AuthorizationPolicyBuilderExtensions
{
        public static AuthorizationPolicyBuilder RequireScope(this AuthorizationPolicyBuilder builder, params string[] scope)
        {
                return builder.RequireClaim("scope", scope);
        }

        public static AuthorizationPolicyBuilder RequireScopeRequirement(this AuthorizationPolicyBuilder builder, params string[] scope)
        {
                builder.Requirements.Add(new ScopeAuthorizationRequirement(scope));
                return builder;
        }
}

public class ScopeAuthorizationRequirement : ClaimsAuthorizationRequirement
{
        public ScopeAuthorizationRequirement(IEnumerable<string> allowedValues)
                :base("scope", allowedValues)
        {

        }
}
```


## Login
```
await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, new AuthenticationProperties {IsPersistant = model.RememberMe});
return LocalRedirect(model.ReturnUrl);
```

## Logout
```
await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
return Redirect("/");
```