namespace FinanceNewsPortal.API.CustomMiddleWare
{
    public class APIKeyAuthMiddleware
    {
        private readonly RequestDelegate _next;
        private const string ApiKey = "ApiKey"; //this makes the validation, it must equal that key
        public APIKeyAuthMiddleware(RequestDelegate next) //RequestDelegate makes the validation that the request should have the API key along with it, validates that and does the next move that's also why it is instantiated as "next"
        {
            _next = next;
        }
        public async Task Invoke(HttpContext context) //after request is made, http request and response interpretation is done here 
        {
            if(!context.Response.Headers.TryGetValue(ApiKey, out var extractedKey)) //this is if there's no API key
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("API not given");
                return;
            }
            //validation of API key by comparing it here if there's one 
            var appSettings = context.RequestServices.GetRequiredService<IConfiguration>(); //getting the key
            var key = appSettings.GetValue<string>(ApiKey); //getting the string value of the key
            if (!key.Equals(extractedKey))
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("API key doesn't match");
                return;
            }
            await _next(context);
        } 
    }
}
