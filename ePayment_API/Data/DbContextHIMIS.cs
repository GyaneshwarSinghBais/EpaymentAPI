
using ePayment_API.DTOs;
using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;


namespace ePayment_API.Data
{
    public class DbContextHIMIS : DbContext
    {
        public DbContextHIMIS(DbContextOptions<DbContextHIMIS> option) : base(option)
        {

        }

        public DbSet<GetDistrictDTO> GetDistrictDbSet { get; set; }
        public DbSet<PaymentRequestDTO> PaymentRequestDbSet { get; set; }
        public DbSet<PaymentRequestNEFT_DTO> PaymentRequestNEFT_DbSet { get; set; }
        public DbSet<PaymentRequestRTGS_DTO> PaymentRequestRTGS_DbSet { get; set; }

        


        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            // modelBuilder.Entity<GetToBeTenderDTO>().HasNoKey();       

        }
    }
}
