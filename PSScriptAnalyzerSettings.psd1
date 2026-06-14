@{
    # PSScriptAnalyzer configuration for NetworkSecurityAudit.ps1
    #
    # This is a single-file PowerShell 5.1+ WPF/console security audit tool.
    # Per the roadmap quality-gate plan, the gate enforces syntax, correctness,
    # and security rules first. The rules below are excluded because they flag
    # intentional, documented design choices in a single-file distribution
    # artifact, not defects. Everything else (including
    # PSAvoidAssignmentToAutomaticVariable) is enforced.

    Severity = @('Error', 'Warning')

    ExcludeRules = @(
        # Console + GUI tool: colored host output is the product surface, not a defect.
        'PSAvoidUsingWriteHost'

        # Audit checks degrade gracefully and must never crash a scan; empty
        # catch blocks are deliberate "best-effort evidence" guards.
        'PSAvoidUsingEmptyCatchBlock'

        # Host-modifying setup functions are already gated behind ReadOnly=$false
        # plus explicit user intent; ShouldProcess plumbing is tracked separately.
        'PSUseShouldProcessForStateChangingFunctions'

        # A handful of internal helpers use plural nouns / non-approved verbs by
        # design (e.g. report/section builders). They are never exported.
        'PSUseSingularNouns'
        'PSUseApprovedVerbs'

        # File is UTF-8 without BOM by project convention.
        'PSUseBOMForUnicodeEncodedFile'

        # '$Credential' here is an argument passed into a runspace scriptblock via
        # AddArgument(), not a user-facing parameter. It carries an existing
        # PSCredential or $null; typing it would break null pass-through.
        'PSUsePSCredentialType'
        'PSAvoidUsingPlainTextForPassword'

        # 'Write-Log' is a private in-script helper; the rule mis-detects it as a
        # shadow of a core cmdlet that this script never imports.
        'PSAvoidOverwritingBuiltInCmdlets'

        # The single WMI/DCOM call bootstraps WinRM on a remote host. CIM requires
        # WinRM, which is exactly what that path is enabling, so WMI is correct.
        'PSAvoidUsingWMICmdlet'

        # False positives on intentional output-suppression assignments
        # (e.g. "$out = cmd.exe /c ... 2>&1" to swallow native stdout/stderr).
        'PSUseDeclaredVarsMoreThanAssignments'
    )
}
