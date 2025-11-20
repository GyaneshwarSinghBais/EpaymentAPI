using ePayment_API.classes;
using ePayment_API.Data;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.OpenApi.Services;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using Microsoft.Extensions.Logging;
using ePayment_API.DTOs;

namespace ePayment_API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class IciciProgramController : ControllerBase
    {
        private readonly ILogger<IciciProgramController> _logger;
        private readonly DbContextHIMIS _context;
        private readonly IConfiguration _config;
        public IciciProgramController(DbContextHIMIS context, ILogger<IciciProgramController> logger, IConfiguration config)
        {
            _context = context;
            _logger = logger;
            _config = config;
        }

        [HttpPost("send-payment-imps")]
        public IActionResult SendPaymentIMPS([FromBody] PaymentRequestDTO request, string token)
        {
            string? secretToken = _config["ICICI_SecretToken"];

            if (token != secretToken)
            {
                _logger.LogWarning("Unauthorized access attempt with token: {Token}", token);
                return Unauthorized("Invalid token.");
            }

            ICICIProgram program = new ICICIProgram();
            try
            {
                string encryptedResult = program.paraIMPS(request);
                string decryptedResult = ICICIProgram.DecryptApiResponse(encryptedResult);

                return Ok(new
                {
                    message = "Encryption and decryption successful",
                    encrypted = encryptedResult,
                    decrypted = decryptedResult
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in SendPayment");
                return StatusCode(500, $"Internal error: {ex.Message}");
            }
        }


        [HttpPost("send-payment-neft")]
        public IActionResult SendPaymentNEFT([FromBody] PaymentRequestNEFT_DTO request, string token)
        {
            string? secretToken = _config["ICICI_SecretToken"];

            if (token != secretToken)
            {
                _logger.LogWarning("Unauthorized access attempt with token: {Token}", token);
                return Unauthorized("Invalid token.");
            }

            ICICIProgram program = new ICICIProgram();
            try
            {
                string encryptedResult = program.paraNEFT(request);
                string decryptedResult = ICICIProgram.DecryptApiResponse(encryptedResult);

                return Ok(new
                {
                    message = "Encryption and decryption successful",
                    encrypted = encryptedResult,
                    decrypted = decryptedResult
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in SendPayment");
                return StatusCode(500, $"Internal error: {ex.Message}");
            }
        }


        [HttpPost("send-payment-rtgs")]
        public IActionResult SendPaymentRTGS([FromBody] PaymentRequestRTGS_DTO request, string token)
        {
            string? secretToken = _config["ICICI_SecretToken"];

            if (token != secretToken)
            {
                _logger.LogWarning("Unauthorized access attempt with token: {Token}", token);
                return Unauthorized("Invalid token.");
            }

            ICICIProgram program = new ICICIProgram();
            try
            {
                string encryptedResult = program.paraRTGS(request);
                string decryptedResult = ICICIProgram.DecryptApiResponse(encryptedResult);

                return Ok(new
                {
                    message = "Encryption and decryption successful",
                    encrypted = encryptedResult,
                    decrypted = decryptedResult
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in SendPayment");
                return StatusCode(500, $"Internal error: {ex.Message}");
            }
        }

    }
}
