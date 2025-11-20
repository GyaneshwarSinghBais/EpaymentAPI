using System.ComponentModel.DataAnnotations;

namespace ePayment_API.DTOs
{
    public class GetDistrictDTO
    {
        [Key]
        public string? District_ID { get; set; }
        public string? DBStart_Name_En { get; set; }       
    }
}
