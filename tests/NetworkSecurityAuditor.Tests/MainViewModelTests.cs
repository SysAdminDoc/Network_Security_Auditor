using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Tests;

public class MainViewModelTests
{
    [Fact]
    public void IsScanning_Raises_Command_CanExecute_Changes()
    {
        var vm = new MainViewModel();
        var startChanges = 0;
        var stopChanges = 0;
        vm.StartScanCommand.CanExecuteChanged += (_, _) => startChanges++;
        vm.StopScanCommand.CanExecuteChanged += (_, _) => stopChanges++;

        Assert.True(vm.StartScanCommand.CanExecute(null));
        Assert.False(vm.StopScanCommand.CanExecute(null));

        vm.IsScanning = true;

        Assert.False(vm.StartScanCommand.CanExecute(null));
        Assert.True(vm.StopScanCommand.CanExecute(null));
        Assert.True(startChanges > 0);
        Assert.True(stopChanges > 0);
    }

    [Fact]
    public void Manual_Status_Changes_Update_Score_Counts()
    {
        var vm = new MainViewModel();
        vm.LoadCheckCatalog();
        var check = vm.Checks[0];

        Assert.Equal(0, vm.PassCount);
        Assert.Equal(0, vm.FailCount);
        Assert.Equal(0, vm.OverallScore);
        Assert.False(vm.HasAssessedChecks);
        Assert.Equal("\u2014", vm.Grade);
        Assert.Equal("Not scanned", vm.OverallScoreDisplay);

        check.Status = CheckStatus.Pass;

        Assert.Equal(1, vm.PassCount);
        Assert.Equal(0, vm.FailCount);
        Assert.True(vm.HasAssessedChecks);
        Assert.Equal(100, vm.OverallScore);
        Assert.Equal("100/100", vm.OverallScoreDisplay);
        Assert.Equal("A", vm.Grade);

        check.Status = CheckStatus.Fail;

        Assert.Equal(0, vm.PassCount);
        Assert.Equal(1, vm.FailCount);
        Assert.True(vm.HasAssessedChecks);
        Assert.Equal(0, vm.OverallScore);
        Assert.Equal("0/100", vm.OverallScoreDisplay);
        Assert.Equal("F", vm.Grade);
    }

    [Fact]
    public void Filtered_Checks_Uses_Stable_View_And_Refreshes_Filters()
    {
        var vm = new MainViewModel();
        vm.LoadCheckCatalog();
        var view = vm.FilteredChecks;
        var check = vm.Checks[0];

        Assert.Same(view, vm.FilteredChecks);
        Assert.Equal(vm.Checks.Count, view.Cast<CheckItemViewModel>().Count());

        vm.SearchText = check.Id;
        Assert.Same(view, vm.FilteredChecks);
        Assert.Single(view.Cast<CheckItemViewModel>());

        vm.StatusFilter = "Pass";
        Assert.Empty(view.Cast<CheckItemViewModel>());

        check.Status = CheckStatus.Pass;

        Assert.Same(view, vm.FilteredChecks);
        Assert.Contains(check, view.Cast<CheckItemViewModel>());
    }
}
