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
    public class UBIController : ControllerBase
    {
        private readonly ILogger<UBIController> _logger;
        private readonly DbContextHIMIS _context;
        private readonly IConfiguration _config;
        private readonly UBI _ubi;
        public UBIController(DbContextHIMIS context, ILogger<UBIController> logger, IConfiguration config, IHttpClientFactory httpFactory)
        {
            _context = context;
            _logger = logger;
            _config = config;

            try
            {
                var http = httpFactory?.CreateClient();
                _ubi = new UBI(config, logger as ILogger<UBI>, http);
                _logger.LogDebug("UBIController constructed successfully.");
            }
            catch (Exception ex)
            {
                // Log the ctor error so the app doesn't return a 500 without details.
                // Keep controller alive for debugging; _ubi may be null so check before use.
                _logger.LogError(ex, "UBIController constructor failed - allowing controller to continue for debugging.");
                _ubi = null;
            }
        }

        private bool ValidateToken(string token)
        {
            return token == _config["UBI_CgmscToken"];
        }

        [HttpPost("make-UBIpayment")]
        public async Task<IActionResult> MakeUBIPayment([FromBody] UBIPaymentDataDTO request, string token)
        {
            if (!ValidateToken(token))
                return Unauthorized("Invalid internal token");

            try
            {
                string msgId = $"NT{DateTime.UtcNow:yyMMddHHmmss}";

                var finalRequest = new UBIBaseRequestDTO
                {
                    msgId = msgId,
                    PaymentData = request
                };

                string plainJson = System.Text.Json.JsonSerializer.Serialize(finalRequest);

                string decryptedResponse = await _ubi.SendEncryptedRequestAsync(plainJson);

                return Ok(new
                {
                    message = "Request sent to UBI successfully",
                    msgId,
                    response = decryptedResponse
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
            _logger.LogDebug("Entered UBIController.TestBreakpoint");
            return Ok(new
            {
                status = "success",
                message = "Breakpoint working",
                time = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")
            });
        }


        [HttpPost("test-encryption")]
        public IActionResult TestEncryption([FromBody] object rawInput)
        {
            try
            {
                string password = _config["UBI_EncryptionPassword"];

                // 1. Convert body to JSON string exactly as received
                string plainJson = System.Text.Json.JsonSerializer.Serialize(rawInput);

                // 2. Encrypt using official bank class
                string encrypted = AesGcmPayAPIUBI.Encrypt(plainJson, password);

                // 3. Decrypt back to verify correct functionality
                string decrypted = AesGcmPayAPIUBI.Decrypt(encrypted, password);

                return Ok(new
                {
                    message = "UBI encryption test completed successfully.",
                    original = plainJson,
                    encrypted = encrypted,
                    decrypted = decrypted,
                    match = plainJson == decrypted ? "YES - MATCH" : "NO - DOES NOT MATCH"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Encryption test error");
                return StatusCode(500, ex.Message);
            }
        }


    }
}
