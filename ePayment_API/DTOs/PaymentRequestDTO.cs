namespace ePayment_API.DTOs
{
    public class PaymentRequestDTO
    {
         public string? LocalTxnDtTime { get; set; }
        public string? BeneAccNo { get; set; }
        public string? BeneIFSC { get; set; }
        public string? Amount { get; set; }
        public string? TranRefNo { get; set; }
        public string? PaymentRef { get; set; }
        public string? SenderName { get; set; }
        public string? Mobile { get; set; }
        public string? RetailerCode { get; set; }
        public string? PassCode { get; set; }
        public string? BcID { get; set; }
        public string? AggrId { get; set; }
        public string? CrpId { get; set; }
        public string? CrpUsr { get; set; }
    }
}
