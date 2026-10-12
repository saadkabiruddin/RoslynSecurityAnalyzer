namespace VulnerableBankApi.Data;

public record Account(long Id, long OwnerId, string AccountNo, double Balance);