using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Net.Http;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;

namespace Demo.Controllers
{
    public class VulnerableController : Controller
    {
        public void Run(string user, string url, string cmd)
        {
            string query = "SELECT * FROM Users WHERE Name = '" + user + "'";
            var command = new SqlCommand(query);

            Response.Write("<div>" + user + "</div>");
            Process.Start("cmd.exe", cmd);

            var client = new HttpClient();
            client.GetStringAsync(url);

            var md5 = MD5.Create();
            var rng = new Random();

            string password = "demo-insecure-password";
            Console.WriteLine(password);
        }
    }
}
