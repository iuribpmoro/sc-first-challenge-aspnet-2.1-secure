using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

// Libs to fix XSS
using System.Text.RegularExpressions; // to use Regex.IsMatch
using System.Web; // to use HttpUtility.HtmlEncode

namespace first_challenge_21
{
    public class User
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
    }

    public class Comment
    {
        public string Text { get; set; }
    }

    public static class AuthenticationMiddlewareExtensions
    {
        public static IApplicationBuilder UseAuthenticationMiddleware(this IApplicationBuilder app)
        {
            return app.Use(async (context, next) =>
            {
                var userIdString = context.Session.GetString("UserId");

                if (string.IsNullOrEmpty(userIdString))
                {
                    context.Response.Redirect("/");
                    return;
                }

                await next();
            });
        }
    }
    
    public class Startup
    {
        private static readonly List<User> users = new List<User>
        {
            new User { Id = Guid.NewGuid(), Name = "Alice", Email = "alice@example.com", Password = "password1" },
            new User { Id = Guid.NewGuid(), Name = "Bob", Email = "bob@example.com", Password = "password2" },
            new User { Id = Guid.NewGuid(), Name = "Charlie", Email = "charlie@example.com", Password = "password3" }
        };

        private static readonly List<Comment> comments = new List<Comment>
        {
            new Comment { Text = "This is a comment" }
        };
        
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();
            services.AddSession();
            services.AddDistributedMemoryCache();
        }

        private static bool IsWhitelisted(string path)
        {
            var whitelist = new[] { "/", "/login" };
            return whitelist.Contains(path);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseSession();

            // Authentication middleware called only when the path is not whitelisted
            app.UseWhen(context => !IsWhitelisted(context.Request.Path), appBuilder =>
            {
                appBuilder.UseAuthenticationMiddleware();
            });

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });

            app.Run(async (context) =>
            {
                if (context.Request.Path == "/")
                {
                    await context.Response.WriteAsync(@"
                        <h1>Welcome to the Store</h1>
                        <form action=""/login"" method=""post"">
                            <label for=""email"">Email:</label>
                            <input type=""email"" name=""email"" id=""email"" required>
                            <label for=""password"">Password:</label>
                            <input type=""password"" name=""password"" id=""password"" required>
                            <button type=""submit"">Login</button>
                        </form>
                    ");
                }
                else if (context.Request.Path == "/login" && context.Request.Method == "POST")
                {
                    var email = context.Request.Form["email"];
                    var password = context.Request.Form["password"];
                    var user = users.Find(u => u.Email == email && u.Password == password);

                    if (user != null)
                    {
                        context.Session.SetString("UserId", user.Id.ToString());
                        context.Response.Redirect($"/user/{user.Id}");
                    }
                    else
                    {
                        await context.Response.WriteAsync("Invalid credentials. Please try again.");
                    }
                }
                else if (context.Request.Path.StartsWithSegments("/user") && context.Request.Method == "GET")
                {
                    var requestedUserId = context.Request.Path.Value.Split("/")[2].ToString();
                    var userIdString = context.Session.GetString("UserId");

                    if (userIdString != requestedUserId)
                    {
                        context.Response.StatusCode = 403;
                        await context.Response.WriteAsync("Access denied!");
                        return;
                    }

                    var id = Guid.Parse(userIdString);
                    var user = users.Find(u => u.Id == id);

                    if (user != null)
                    {
                        var commentsHtml = string.Join("", comments.ConvertAll(c => $"<li>{HttpUtility.HtmlEncode(c.Text)}</li>"));

                        await context.Response.WriteAsync($@"
                            <h1>User Profile</h1>
                            <p>Name: {user.Name}</p>
                            <p>Email: {user.Email}</p>
                            <h2>Write a comment:</h2>
                            <form action=""/comments"" method=""post"">
                                <input type=""text"" name=""comment"" id=""comment"">
                                <button type=""submit"">Send</button>
                            </form>
                            <h2>Comments:</h2>
                            <ul>
                                {commentsHtml}
                            </ul>
                        ");
                    }
                    else
                    {
                        context.Response.StatusCode = 404;
                        await context.Response.WriteAsync("User not found");
                    }
                }
                else if (context.Request.Path == "/comments" && context.Request.Method == "POST")
                {
                    if (context.Session.TryGetValue("UserId", out var userIdBytes))
                    {
                        var userId = BitConverter.ToInt32(userIdBytes);
                        var commentText = context.Request.Form["comment"];

                        // If Regex.IsMatch not alphanumerical, shows error message
                        string pattern = @"^[a-zA-Z0-9\s]*$";
                        if (!Regex.IsMatch(commentText, pattern))
                        {
                            await context.Response.WriteAsync("Invalid comment. Please try again.");
                            return;
                        }
                        else
                        {
                            Console.WriteLine($"Received comment: {commentText}");
                            comments.Add(new Comment { Text = commentText });
                            // Redirects to the user profile page
                            context.Response.Redirect($"/user/{userId}");
                        }
                    }
                    else
                    {
                        context.Response.Redirect("/");
                    }
                }
                else
                {
                    context.Response.StatusCode = 404;
                    await context.Response.WriteAsync("Page not found");
                }
            });
        }
    }
}
