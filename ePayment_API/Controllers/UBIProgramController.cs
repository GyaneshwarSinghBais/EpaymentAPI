using ePayment_API.classes;
using ePayment_API.Data;
using ePayment_API.DTOs;
using ePayment_API.DTOs.UBI;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.OpenApi.Services;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;


namespace ePayment_API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UBIProgramController : ControllerBase
    {
        private readonly ILogger<IciciProgramController> _logger;
        private readonly DbContextHIMIS _context;
        private readonly IConfiguration _config;
        private readonly UBI _ubi;
        public UBIProgramController(DbContextHIMIS context, ILogger<IciciProgramController> logger, IConfiguration config, IHttpClientFactory httpFactory)
        {
            _context = context;
            _logger = logger;
            _config = config;

            var http = httpFactory.CreateClient();
            _ubi = new UBI(config, logger as ILogger<UBI>, http);
        }
   

    private bool ValidateToken(string token)
        {
            return token == _config["UBI_InternalToken"];
        }

        //  INPUT: ONLY PaymentData
        //  OUTPUT to Bank: msgId + PaymentData wrapper
        [HttpPost("make-UBIpayment")]
        public async Task<IActionResult> MakeUBIPayment([FromBody] UBIPaymentDataDTO request, string token)
        {
            if (!ValidateToken(token))
                return Unauthorized("Invalid internal token");

            try
            {
                // ✔ Generate msgId (as per bank)
                string msgId = $"NT{DateTime.UtcNow:yyMMddHHmmss}";

                // ✔ Wrap payload EXACTLY as UBI wants
                var finalRequest = new UBIBaseRequestDTO
                {
                    msgId = msgId,
                    PaymentData = request
                };

                // ✔ Serialize correct UBI JSON
                string plainJson = System.Text.Json.JsonSerializer.Serialize(finalRequest);

                // ✔ This sends encrypted request and decrypts response
                string decryptedResponse = await _ubi.SendEncryptedRequestAsync(plainJson);

                return Ok(new
                {
                    message = "Payment request sent to UBI",
                    msgId,
                    bankResponse = decryptedResponse
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "UBI Payment Error");
                return StatusCode(500, ex.Message);
            }
        }

        [HttpGet("test-breakpoint")]
        public IActionResult TestBreakpoint()
        {
            //  Put your breakpoint on this line
            var msg = "Breakpoint is working!";

            return Ok(new
            {
                status = "success",
                message = msg,
                time = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")
            });
        }
    }
}

