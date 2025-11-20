namespace ePayment_API.DTOs.UBI
{
    public class UBIBaseRequestDTO
    {
        public string msgId { get; set; }
        public UBIPaymentDataDTO PaymentData { get; set; }
    }
}
