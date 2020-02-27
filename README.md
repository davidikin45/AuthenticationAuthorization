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

## Microsoft.AspNetCore.Authentication.OpenIdConnect for Client > Server > API
```
JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear(); // keep original claim types
services.AddAuthentication(options => {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;

})
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options => {
        options.AccessDeniedPath = "/Authorization/AccessDenied";
})
.AddOpenIdConnection(options => {
        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.Authority = "https://localhost:44318";

        //https://www.scottbrady91.com/OpenID-Connect/ASPNET-Core-using-Proof-Key-for-Code-Exchange-PKCE
        options.ResponseType = "code"; //Authorization
        options.UsePkce = true;
        //options.ResponseType = "id_token"; //Implicit - Dont Use
        //options.ResponseType = "id_token token"; //Implicit - Dont Use
        //options.ResponseType = "code id_token"; //Hybrid MVC/Blazor Server
        //options.ResponseType = "code token"; //Hybrid
        //options.ResponseType = "code id_token token"; //Hybrid  - Dont Use

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

        options.ClaimActions.Remove("amr"); //keep claim
        options.ClaimActions.DeleteClaim("sid"); //delete claim
        options.ClaimActions.DeleteClaim("idp"); //delete claim
        options.ClaimActions.DeleteClaim("s_hash"); //delete claim
        options.ClaimActions.DeleteClaim("auth_time"); //delete claim

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

```
[Route("Authorization")]
public class AuthorizationController : MvcControllerBase
{
        [Route("AccessDenied")]
        public IActionResult AccessDenied()
        {
                return View();
        }
}
```
```
<div class="h3">Woops, looks like you're not authorized to view this page.</div>
<div>Would you prefer to <a asp-controller="Authentication" asp-action="Logout">log in as someone else</a>?</div>
```


## Identity Server
- Confidential Clients (ClientSecret) can use refresh token to get new tokens via the back channel
- Refresh Tokens: options.Scope.Add("offline_access") and AllowOfflineAccess = true
- Reference Tokens dont store claims in the access_token. Alternative to Refresh Tokens and allow access revoke. AccesstokenType=Reference and require ApiSecret. Use IdentityServer4.AccessTokenValidation instead of JwtBearer
- IdentityServer doesn't include identity claims (except sub) in the identity token, unless AlwaysIncludeUserClaimsInIdToken = true > Keeps token smaller avoiding URI length restrictions. Better to set GetClaimsFromUserInfoEndpoint = true
- ClaimsIdentity created from id_token
- Sometimes claims are required in an Access Token. Add them to ApiResource.
- id_token has default 5 minute expiry. Generally applications implement their own expiration policies.
- access_token has default lifetime of 60 minutes.

## Identity Server Response Types
- Client Credentials + ClientSecret = Server > API
- code = Authorization Code + PKCE = SPA, Mobile App
- code = Authorization Code + PKCE + ClientSecret = Client > Server > API,  Mitigates substitution/injection attacks but alot simpler client-side with as only need to generate random string and hash with SHA256. Use ApiSecret for Reference Tokens.
- id_token = Implicit - Dont Use
- id_token token = Implicit - Dont Use
- code id_token = Hybrid + ClientSecret, Mitigates injection/substitution attack but client-side code is more difficult to implement. c
- code token = Hybrid - Dont Use
- code id_token token = Hybrid - Dont Use

## JWT Validation
```
services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
.AddJwtBearer(options => {
        options.Authority = "https://localhost:5000/";
        options.Audience = "api";
});
```

## JWT Validation + Reference Tokens
- Reference Tokens dont store claims in the access_token. Alternative to Refresh Tokens and allow access revoke. AccesstokenType=Reference. Use IdentityServer4.AccessTokenValidation instead of JwtBearer

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

services.AddSingleton<IAuthorizationHandler, YearsOfExperienceAuthorizationHandler>();
services.AddSingleton<IAuthorizationHandler, ProposalApprovedAuthorizationHandler>();
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

## Pluralsight Courses
- [Authentication and Authorization in ASP.NET Core](https://www.pluralsight.com/courses/authentication-authorization-aspnet-core)
- [Securing ASP.NET Core 3 with OAuth2 and OpenID Connect](https://www.pluralsight.com/courses/securing-aspnet-core-3-oauth2-openid-connect)
- [ASP.NET Core 2 Authentication Playbook](https://app.pluralsight.com/library/courses/aspnet-core-identity-management-playbook/table-of-contents)
- [Authentication and Authorization in Blazor Applications](https://www.pluralsight.com/courses/authentication-authorization-blazor-applications)