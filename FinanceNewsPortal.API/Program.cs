using AutoMapper;
using FinanceNewsPortal.API.CustomMiddleWare;
using FinanceNewsPortal.API.Data;
using FinanceNewsPortal.API.DTO;
using FinanceNewsPortal.API.Helper;
using FinanceNewsPortal.API.Models;
using FinanceNewsPortal.API.Repository;
using FinanceNewsPortal.API.Repository.Contracts;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);
var issuer = builder.Configuration["JWT:Issuer"];
var audience = builder.Configuration["JWT:Audience"];
var key = builder.Configuration["JWT:Key"];

//this is the logic that decodes the JWT - verification
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false;
    options.SaveToken = true;
    options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidIssuer = issuer,
        ValidAudience = audience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key))
    };
});

builder.Services.AddAuthorization(options => {
    options.AddPolicy("admin_greetings", policy => policy.RequireAuthenticatedUser());
});

builder.Services.AddAutoMapper(typeof(AutoMapperConfigurationException));
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<FinanceNewsPortalDbContext>()
    .AddDefaultTokenProviders();

builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequiredLength = 1;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireDigit = false;
    options.Password.RequiredUniqueChars = 0;
    options.Password.RequireLowercase = false;
    options.Password.RequireUppercase = false;
});

builder.Services.AddControllers().AddJsonOptions(x =>
                x.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles);
;
builder.Services.AddHttpClient();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddDbContext<FinanceNewsPortalDbContext>();
/*builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<FinanceNewsPortalDbContext>()
    .AddDefaultTokenProviders();*/

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(opt =>
{
    opt.SwaggerDoc("v1", new OpenApiInfo { Title = "eFinancials: Finance News Portal Web API", Version = "v1" });
    opt.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Token",
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        BearerFormat = "JWT",
        Scheme = "bearer"
    });

    opt.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type=ReferenceType.SecurityScheme,
                    Id="Bearer"
                }
            },
            new string[]{}
        }
    });
});

builder.Services.AddScoped<FileUpload>();
builder.Services.AddScoped<INewsArticlesRepository, NewsArticlesRepository>();
builder.Services.AddScoped<IRatesRepository, RatesAPIRepository>();
builder.Services.AddScoped<IUserRepository, UserRepository>();
builder.Services.AddScoped<IAdminRepository, AdminRepository>();

builder.Services.AddHttpContextAccessor();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.MapGet("/GetNewsArticle", async (FinanceNewsPortalDbContext db) => Results.Ok(await db.NewsArticle.ToListAsync()))
    .RequireAuthorization("admin_greetings");

app.MapGet("/GetNewsArticle/{id}", async (FinanceNewsPortalDbContext db, int id) =>
            await db.NewsArticle.FindAsync(id)
                is NewsArticle todo ? Results.Ok(todo) : Results.NotFound());

app.MapPost("/CreateNewsArticle", async (FinanceNewsPortalDbContext db, NewsArticle newsArticle) =>
{
    db.NewsArticle.Add(newsArticle);
    await db.SaveChangesAsync();
    return Results.Created($"/CreateNewsArticle/{newsArticle.Id}", newsArticle);
});

app.MapPut("/UpdateNewsArticle/{id}", async (FinanceNewsPortalDbContext db, NewsArticle newsArticle, int id) =>
{
    var oldTodo = await db.NewsArticle.FindAsync(id);
    if (newsArticle is null) return Results.NotFound();
    // automapper
    oldTodo.Title = newsArticle.Title;
    await db.SaveChangesAsync();
    return Results.NoContent();
});

app.MapDelete("/DeleteNewsArticle/{id}", async (FinanceNewsPortalDbContext db, int id) =>
{
    if (await db.NewsArticle.FindAsync(id) is NewsArticle newsArticle)
    {
        db.NewsArticle.Remove(newsArticle);
        await db.SaveChangesAsync();
        return Results.Ok(newsArticle);
    }
    return Results.NotFound();
});

//validation of credentials both for register and logins
//when the endpoints are called,
app.MapPost("/Register", async (FinanceNewsPortalDbContext context, IMapper mapper, UserManager<ApplicationUser> userManager, RegisterUserDTO registerUserDTO) =>
{
    // credentials will be saved on the database and new user object -> registerUserDTO is created
    var user = mapper.Map<ApplicationUser>(registerUserDTO);
    var newUser = await userManager.CreateAsync(user, registerUserDTO.Password);
    if (newUser.Succeeded)
        return user;
    return null;
});

//login credentials
app.MapPost("/Login", async (FinanceNewsPortalDbContext context,
                            SignInManager<ApplicationUser> signInManager,
                            UserManager<ApplicationUser> userManager,
                            IConfiguration appConfig,
                            LoginUserDTO loginDTO) =>
{
    // generate a token and return a token
    var issuer = appConfig["JWT:Issuer"];
    var audience = appConfig["JWT:Audience"];
    var key = appConfig["JWT:Key"];

    if (loginDTO is not null)
    {
        var loginResult = await signInManager.PasswordSignInAsync(loginDTO.Username, loginDTO.Password, loginDTO.RememberMe, false);
        if (loginResult.Succeeded)
        {
            // generate a token
            var user = await userManager.FindByEmailAsync(loginDTO.Username);
            if (user != null)
            {
                var keyBytes = Encoding.UTF8.GetBytes(key);
                var theKey = new SymmetricSecurityKey(keyBytes); // 256 bits of key
                var creds = new SigningCredentials(theKey, SecurityAlgorithms.HmacSha256);
                var token = new JwtSecurityToken(issuer, audience, null, expires: DateTime.Now.AddMinutes(30), signingCredentials: creds);
                return Results.Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token) }); // token 
            }
        }
    }
    return Results.BadRequest();
});

app.UseStaticFiles();

app.UseMiddleware<APIKeyAuthMiddleware>(); //invokes your customed middleware

app.UseAuthentication();

/*app.UseAuthorization();*/

app.MapControllers();

app.Run();
