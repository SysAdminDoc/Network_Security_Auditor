namespace NetworkSecurityAuditor.Tests;

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class NonParallelTestCollection
{
    public const string Name = "NonParallel";
}
