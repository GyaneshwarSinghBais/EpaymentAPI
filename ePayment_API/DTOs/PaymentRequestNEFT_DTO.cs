namespace ePayment_API.DTOs
{
    public class PaymentRequestNEFT_DTO
    {
        public string? TranRefNo { get; set; }
        public string? Amount { get; set; }
        public string? SenderAcctNo { get; set; }
        public string? BeneAccNo { get; set; }
        public string? BeneName { get; set; }
        public string? BeneIFSC { get; set; }
        public string? Narration1 { get; set; }
        public string? Narration2 { get; set; }
        public string? CrpId { get; set; }
        public string? CrpUsr { get; set; }
        public string? AggrId { get; set; }
        public string? AggrName { get; set; }
        public string? Urn { get; set; }
        public string? TxnType { get; set; }
        public string? WORKFLOW_REQD { get; set; }
       // public string? BENLEI { get; set; }
    }
}
