namespace ePayment_API.DTOs
{
    public class PaymentRequestRTGS_DTO
    {
        public string? AGGRID { get; set; }
        public string? CORPID { get; set; }
        public string? USERID { get; set; }
        public string? URN { get; set; }
        public string? AGGRNAME { get; set; }
        public string? UNIQUEID { get; set; }
        public string? DEBITACC { get; set; }
        public string? CREDITACC { get; set; }
        public string? IFSC { get; set; }
        public string? AMOUNT { get; set; }
        public string? CURRENCY { get; set; }
        public string? TXNTYPE { get; set; }   // RTG for RTGS transaction
        public string? PAYEENAME { get; set; }
        public string? REMARKS { get; set; }
        public string? WORKFLOW_REQD { get; set; }
        public string? BENLEI { get; set; }
    }
}
