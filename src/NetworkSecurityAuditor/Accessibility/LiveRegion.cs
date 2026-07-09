using System.Windows;
using System.Windows.Automation.Peers;
using System.Windows.Threading;

namespace NetworkSecurityAuditor.Accessibility;

public static class LiveRegion
{
    public static readonly DependencyProperty AnnouncementProperty = DependencyProperty.RegisterAttached(
        "Announcement",
        typeof(string),
        typeof(LiveRegion),
        new FrameworkPropertyMetadata(null, OnAnnouncementChanged));

    public static void SetAnnouncement(DependencyObject element, string? value) =>
        element.SetValue(AnnouncementProperty, value);

    public static string? GetAnnouncement(DependencyObject element) =>
        (string?)element.GetValue(AnnouncementProperty);

    private static void OnAnnouncementChanged(DependencyObject dependencyObject, DependencyPropertyChangedEventArgs args)
    {
        if (dependencyObject is not UIElement element || Equals(args.OldValue, args.NewValue))
            return;

        element.Dispatcher.BeginInvoke(
            DispatcherPriority.ContextIdle,
            () =>
            {
                var peer = UIElementAutomationPeer.FromElement(element)
                    ?? UIElementAutomationPeer.CreatePeerForElement(element);
                peer?.RaiseAutomationEvent(AutomationEvents.LiveRegionChanged);
            });
    }
}
