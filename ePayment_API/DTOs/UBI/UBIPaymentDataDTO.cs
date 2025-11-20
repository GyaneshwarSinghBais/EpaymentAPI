namespace ePayment_API.DTOs.UBI
{
    public class UBIPaymentDataDTO
    {
        public string tranType { get; set; }         // IMPS / NEFT / RTGS
        public string tranSubType { get; set; }      // optional (IMPS=11 etc)

        public string debitAccNo { get; set; }
        public string benAccNo { get; set; }
        public string benIFSC { get; set; }
        public string benName { get; set; }

        public string tranAmount { get; set; }       // ex: "1000.00"
        public string remitterName { get; set; }
        public string remarks { get; set; }

        public string custRef { get; set; }          // your own reference
        public string cmsRef { get; set; }           // UBI will return this

        // IMPS Specific (optional)
        public string mobileNo { get; set; }
        public string mmid { get; set; }

        // Dates (yyyyMMdd)
        public string tranDate { get; set; }
        public string valueDate { get; set; }
    }
}
