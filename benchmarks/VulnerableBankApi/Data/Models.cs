namespace VulnerableBankApi.Data;

public record Account(long Id, long OwnerId, string AccountNo, double Balance);

public record Transaction(long Id, long AccountId, double Amount, string Description, string CreatedAt);

public record UserSummary(long Id, string Username, string Role);