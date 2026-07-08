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
}
