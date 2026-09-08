<#
.SYNOPSIS
  UniCryptor3 GUI - graphical interface for UniCryptor3 encryption toolkit.

.DESCRIPTION
  This script provides a Windows Forms graphical user interface for the UniCryptor3
  encryption toolkit. It allows users to perform all encryption operations through
  a convenient GUI without needing to write PowerShell commands.

  Features include:
    • Certificate management - view, select, and create self-signed certificates
    • String encryption/decryption - protect sensitive text with certificates or password
    • File encryption/decryption - protect individual files with certificates or password
    • Folder encryption/decryption - batch encrypt/decrypt entire folders recursively
    • Archive operations - create certificate-encrypted 7-zip archives, extract them,
      view archive contents, and retrieve archive passwords
    • Container inspection - view detailed information about encrypted containers
      including recipients, mode, metadata, and size information
    • Multi-language support - interface available in multiple languages
    • Asynchronous operations - all long-running tasks run in background runspaces
      with progress indication

.NOTES
  Version:        0.1
  Author:         Andrew Afanasiev
  Date:           08.09.2026
  Contacts:       AfanasievAA@yandex.ru
  Requirements:   Windows, PowerShell 7.5+
                  UniCryptor3.ps1 in the same directory
                  modules\Localization.ps1
                  localization\strings.en.json (+ optional strings.<lang>.json)
  Changes:
    • Initial release

.EXAMPLE
  # Launch the GUI (auto-relaunches with -STA if needed)
  pwsh -File .\UniCryptor3GUI.ps1

.EXAMPLE
  # Launch with execution policy bypass
  pwsh -ExecutionPolicy Bypass -File .\UniCryptor3GUI.ps1

.DETAILS
  GUI Architecture:
    • WinForms-based with STA threading requirement for clipboard and UI operations
    • Asynchronous operations via PowerShell runspaces to keep UI responsive
    • Status bar with progress indication for all long-running tasks
    • Drag-and-drop support for file and folder selection
    • Localization system with language switching without restart

  Tabs:
    • Certificates - manage X.509 certificates from Windows Certificate Store,
      select certificates for encryption, create self-signed certificates
    • String - encrypt/decrypt text with certificate or password mode
    • File - encrypt/decrypt individual files with destination selection
    • Folder - batch encrypt/decrypt folders with recursive processing
    • Archive - create certificate-encrypted 7-zip archives, extract, view content,
      retrieve embedded passwords
    • Container Info - inspect encrypted containers for detailed metadata

  Security Notes:
    • Passwords are masked using SystemPasswordChar in input fields
    • Selected certificates are stored in memory only during the session
    • All cryptographic operations are performed by UniCryptor3 library
    • Encrypted outputs are displayed in Base64 format for safe copying
#>

$ErrorActionPreference = 'Stop'
# WinForms and the clipboard require an STA thread; relaunch under pwsh -STA if needed
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA' -and $PSCommandPath) {
    Start-Process pwsh -ArgumentList @('-STA', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', $PSCommandPath)
    exit
}

$script:LibraryFileName = 'UniCryptor3.ps1'
$script:UCScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$script:LibPath = Join-Path $script:UCScriptRoot $script:LibraryFileName

if (-not (Test-Path -LiteralPath $script:LibPath)) { throw "Library not found: $script:LibPath" }

# Localization module in modules\, string files in localization\ (resolved by Localization.ps1 itself)
$script:LocModulePath = Join-Path (Join-Path $script:UCScriptRoot 'modules') 'Localization.ps1'

if (-not (Test-Path -LiteralPath $script:LocModulePath)) { throw "Localization module not found: $script:LocModulePath" }

. $script:LibPath
. $script:LocModulePath

try { Initialize-Localization } catch { throw "Localization init failed: $($_.Exception.Message)" }

Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# Shared state and worker engine
$script:sync = [hashtable]::Synchronized(@{ State = 'Idle'; Tag = ''; Result = $null; Error = $null; StatusText = ''; Percent = -1; Language = 'en' })
$script:jobs = [System.Collections.Generic.List[object]]::new()
$script:SelectedThumbprints = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:TextBindings = [System.Collections.Generic.List[object]]::new()

# Set the status label text
function Set-UcStatus { param([string]$Text) $script:statusLabel.Text = $Text }

# Registers a control for localized text
function Bind-UcText {
    param($Control, [string]$Key)
    $script:TextBindings.Add([pscustomobject]@{ Control = $Control; Key = $Key })
    $Control.Text = Get-String -Key $Key
}

# Apply localization to all registered controls
function Apply-UcLocalization {
    foreach ($b in $script:TextBindings) { $b.Control.Text = Get-String -Key $b.Key }
    Update-UcSelectionLabel
    if ($script:sync.State -eq 'Idle') { Set-UcStatus (Get-String -Key 'status.ready') }
}

# Update UI busy state
function Update-UcBusyState {
    $busy = ($script:sync.State -eq 'Running')
    $script:mainTabControl.Enabled = -not $busy
    $script:progressBar.Style = if ($busy) { 'Marquee' } else { 'Continuous' }
    if (-not $busy) { $script:progressBar.Value = 0 }
}

# Start an operation in a separate runspace
function Start-UcOperation {
    param([string]$Tag, [scriptblock]$Body, [hashtable]$Inputs = @{})
    if ($script:sync.State -eq 'Running') { Set-UcStatus (Get-String -Key 'status.wait'); return }
    $script:sync.State = 'Running'; $script:sync.Tag = $Tag
    $script:sync.Result = $null; $script:sync.Error = $null; $script:sync.StatusText = ''; $script:sync.Percent = -1
    $script:sync.Language = Get-CurrentLanguage
    foreach ($key in $Inputs.Keys) { $script:sync[$key] = $Inputs[$key] }
    $worker = 'param($ctx, $libPath, $locPath)' + "`n" + '$ErrorActionPreference = ''Stop''' + "`n" +
        '. $libPath' + "`n" + '. $locPath' + "`n" +
        'Initialize-Localization -LanguageCode $ctx.Language' + "`n" +
        '& {' + "`n" + $Body.ToString() + "`n" + '} $ctx'
    $ps = [powershell]::Create()
    $null = $ps.AddScript($worker)
    $null = $ps.AddArgument($script:sync); $null = $ps.AddArgument($script:LibPath); $null = $ps.AddArgument($script:LocModulePath)
    $script:jobs.Add([pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke() })
    Update-UcBusyState
    Set-UcStatus (Get-String -Key 'status.running' -Params @($Tag))
}

# Worker bodies (each receives $ctx = $script:sync and runs inside a worker runspace)
$script:bodies = @{
    ProtectString = {
        param($ctx)
        try {
            $params = @{ PlainText = $ctx.InText }
            if ($ctx.InMode -eq 'Password') { $params.Password = $ctx.InPassword }
            elseif ($ctx.InCerts.Count -ge 1) { $params.Certificate = $ctx.InCerts }
            $ctx.Result = Protect-UCString @params
        } catch { $ctx.Error = $_.Exception.GetBaseException().Message }
    }
    UnprotectString = {
        param($ctx)
        try {
            $params = @{ ProtectedText = $ctx.InText }
            if ($ctx.InPassword) { $params.Password = $ctx.InPassword }
            $ctx.Result = Unprotect-UCString @params
        } catch { $ctx.Error = $_.Exception.GetBaseException().Message }
    }
    ProtectFile = {
        param($ctx)
        try {
            $params = @{ Path = $ctx.InPath; Destination = $ctx.InDestination; Overwrite = $ctx.InOverwrite }
            if ($ctx.InMode -eq 'Password') { $params.Password = $ctx.InPassword }
            elseif ($ctx.InCerts.Count -ge 1) { $params.Certificate = $ctx.InCerts }
            $ctx.Result = Protect-UCFile @params
        } catch { $ctx.Error = $_.Exception.GetBaseException().Message }
    }
    UnprotectFile = {
        param($ctx)
        try {
            $params = @{ Path = $ctx.InPath; Destination = $ctx.InDestination; Overwrite = $ctx.InOverwrite }
            if ($ctx.InPassword) { $params.Password = $ctx.InPassword }
            $ctx.Result = Unprotect-UCFile @params
        } catch { $ctx.Error = $_.Exception.GetBaseException().Message }
    }
    # Folder operations loop over files with public per-file methods: independent of the folder facade signature and gives real progress
    ProtectFolder = {
        param($ctx)
        try {
            $uc = [UniCryptor3]::new()
            $src = Get-Item -LiteralPath $ctx.InFolder -ErrorAction Stop
            if (-not $src.PSIsContainer) { throw (Get-String -Key 'worker.notFolder' -Params @($src.FullName)) }
            $files = @(Get-ChildItem -LiteralPath $src.FullName -Force -File -Recurse:$ctx.InRecurse | Where-Object { $_.Extension -ne [UniCryptor3]::DefaultExtension })
            if ($files.Count -lt 1) { throw (Get-String -Key 'worker.noFilesEncrypt') }
            $mode = $ctx.InMode
            if ($mode -ne 'Password') {
                $certs = $ctx.InCerts
                if ($certs.Count -lt 1) { $certs = @(Get-UCCertificates -RequirePrivateKey) }
                if ($certs.Count -lt 1) { throw (Get-String -Key 'worker.noCerts') }
                $uc.SetEncryptionCertificates([System.Security.Cryptography.X509Certificates.X509Certificate2[]]$certs)
            }
            $ok = 0; $failed = [System.Collections.Generic.List[object]]::new(); $i = 0
            foreach ($f in $files) {
                $i++
                $ctx.StatusText = "($i/$($files.Count)) $($f.Name)"
                $ctx.Percent = [int](100 * ($i - 1) / $files.Count)
                try {
                    if ($mode -eq 'Password') { $null = $uc.ProtectFileWithPassword($f.FullName, $ctx.InDestination, $ctx.InPassword, $ctx.InOverwrite) }
                    else { $null = $uc.ProtectFile($f.FullName, $ctx.InDestination, $ctx.InOverwrite) }
                    $ok++
                } catch { $failed.Add([pscustomobject]@{ Path = $f.FullName; Message = $_.Exception.GetBaseException().Message }) }
            }
            $ctx.Percent = 100
            $ctx.Result = [pscustomobject]@{ Total = $files.Count; Succeeded = $ok; Failed = $failed }
        } catch { $ctx.Error = $_.Exception.GetBaseException().Message }
    }
    UnprotectFolder = {
        param($ctx)
        try {
            $uc = [UniCryptor3]::new()
            $src = Get-Item -LiteralPath $ctx.InFolder -ErrorAction Stop
            if (-not $src.PSIsContainer) { throw (Get-String -Key 'worker.notFolder' -Params @($src.FullName)) }
            $files = @(Get-ChildItem -LiteralPath $src.FullName -Force -File -Recurse:$ctx.InRecurse -Filter ('*' + [UniCryptor3]::DefaultExtension))
            if ($files.Count -lt 1) { throw (Get-String -Key 'worker.noFilesDecrypt' -Params @([UniCryptor3]::DefaultExtension)) }
            $ok = 0; $failed = [System.Collections.Generic.List[object]]::new(); $i = 0
            foreach ($f in $files) {
                $i++
                $ctx.StatusText = "($i/$($files.Count)) $($f.Name)"
                $ctx.Percent = [int](100 * ($i - 1) / $files.Count)
                try {
                    if ($ctx.InPassword) { $null = $uc.UnprotectFileWithPassword($f.FullName, $ctx.InDestination, $ctx.InPassword, $ctx.InOverwrite) }
                    else { $null = $uc.UnprotectFile($f.FullName, $ctx.InDestination, $ctx.InOverwrite) }
                    $ok++
                } catch { $failed.Add([pscustomobject]@{ Path = $f.FullName; Message = $_.Exception.GetBaseException().Message }) }
            }
            $ctx.Percent = 100
            $ctx.Result = [pscustomobject]@{ Total = $files.Count; Succeeded = $ok; Failed = $failed }
        } catch { $ctx.Error = $_.Exception.GetBaseException().Message }
    }
    Compress = {
        param($ctx)
        try {
            $params = @{ Folder = $ctx.InFolder; DestinationPath = $ctx.InArchive; Overwrite = $ctx.InOverwrite }
            if ($ctx.InCerts.Count -ge 1) { $params.Certificate = $ctx.InCerts }
            if ($ctx.InLevel) { $params.CompressionLevel = $ctx.InLevel }
            if ($ctx.InOnlyBit) { $params.OnlyFilesWithArchiveBit = $true }
            if ($ctx.InClearBit) { $params.ClearArchiveBit = $true }
            $ctx.Result = Compress-UCArchive @params
        } catch { $ctx.Error = $_.Exception.GetBaseException().Message }
    }
    Expand = {
        param($ctx)
        try { $ctx.Result = Expand-UCArchive -ArchivePath $ctx.InArchive -Destination $ctx.InDestination -Overwrite:$ctx.InOverwrite }
        catch { $ctx.Error = $_.Exception.GetBaseException().Message }
    }
    ArchiveContent = {
        param($ctx)
        try {
            $entries = @(Get-UCArchiveContent -ArchivePath $ctx.InArchive)
            $ctx.Result = @($entries | ForEach-Object { [pscustomobject]@{ FileName = [string]$_.FileName; Size = [uint64]$_.Size; LastWriteTime = $_.LastWriteTime; IsDirectory = [bool]$_.IsDirectory } })
        } catch { $ctx.Error = $_.Exception.GetBaseException().Message }
    }
    ArchivePassword = {
        param($ctx)
        try { $ctx.Result = Get-UCArchivePassword -ArchivePath $ctx.InArchive }
        catch { $ctx.Error = $_.Exception.GetBaseException().Message }
    }
    FileInfo = {
        param($ctx)
        try { $ctx.Result = Get-UCFileInfo -Path $ctx.InPath }
        catch { $ctx.Error = $_.Exception.GetBaseException().Message }
    }
    NewCert = {
        param($ctx)
        try { $ctx.Result = New-UCSelfSignedCertificate -Subject $ctx.InSubject }
        catch { $ctx.Error = $_.Exception.GetBaseException().Message }
    }
}

# Show folder operation results
function Show-UcFolderResult { param([string]$Prefix)
    $r = $script:sync.Result
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add((Get-String -Key 'folder.result.line' -Params @($r.Total, $r.Succeeded, @($r.Failed).Count)))
    foreach ($f in @($r.Failed)) { $lines.Add((Get-String -Key 'folder.result.error' -Params @($f.Path, $f.Message))) }
    $script:folderResultBox.Lines = $lines.ToArray()
    Set-UcStatus (Get-String -Key 'folder.status.done' -Params @($Prefix, $r.Succeeded, $r.Total, @($r.Failed).Count))
}

# Show archive content in list view
function Show-UcArchiveContent {
    $script:archiveListView.BeginUpdate()
    try {
        $script:archiveListView.Items.Clear()
        foreach ($e in @($script:sync.Result)) {
            $item = [System.Windows.Forms.ListViewItem]::new($e.FileName)
            $null = $item.SubItems.Add($(if ($e.IsDirectory) { '-' } else { '{0:N0}' -f [double]$e.Size }))
            $null = $item.SubItems.Add($(if ($e.LastWriteTime -and $e.LastWriteTime -ne [datetime]::MinValue) { ([datetime]$e.LastWriteTime).ToString('yyyy-MM-dd HH:mm') } else { '' }))
            $null = $item.SubItems.Add($(if ($e.IsDirectory) { Get-String -Key 'archive.type.dir' } else { Get-String -Key 'archive.type.file' }))
            $null = $script:archiveListView.Items.Add($item)
        }
    } finally { $script:archiveListView.EndUpdate() }
    Set-UcStatus (Get-String -Key 'archive.status.content' -Params @($script:archiveListView.Items.Count))
}

# Show file info results
function Show-UcFileInfoResult {
    $r = $script:sync.Result
    $kb = "$( [math]::Round($r.FileLength / 1KB, 1) ) $(Get-String -Key 'info.unit.kb')"
    $mode = if ($r.Mode -eq 'Password') { Get-String -Key 'info.mode.password' } else { Get-String -Key 'info.mode.certificates' }
    $meta = if ($r.MetadataEncrypted) { Get-String -Key 'info.meta.encrypted' } else { Get-String -Key 'info.meta.absent' }
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add((Get-String -Key 'info.line.file' -Params @($r.File)))
    $lines.Add((Get-String -Key 'info.line.size' -Params @($kb)))
    $lines.Add((Get-String -Key 'info.line.version' -Params @($r.ContainerVersion)))
    $lines.Add((Get-String -Key 'info.line.mode' -Params @($mode)))
    $lines.Add((Get-String -Key 'info.line.meta' -Params @($meta)))
    $lines.Add((Get-String -Key 'info.line.ctlen' -Params @($r.CiphertextLength)))
    $lines.Add((Get-String -Key 'info.line.offset' -Params @($r.ContainerStartsAt)))
    $script:infoTextBox.Lines = $lines.ToArray()
    $script:infoListView.Items.Clear()
    foreach ($rec in @($r.Recipients)) {
        $item = [System.Windows.Forms.ListViewItem]::new([string]$rec.KeyId)
        $null = $item.SubItems.Add($(if ($rec.MatchedLocalCertificate) { [string]$rec.MatchedLocalCertificate } else { Get-String -Key 'info.recipient.noMatch' }))
        $null = $script:infoListView.Items.Add($item)
    }
    Set-UcStatus (Get-String -Key 'info.status.done')
}

# Complete operation based on tag
function Complete-UcOperation {
    if ($script:sync.Error) { Set-UcStatus (Get-String -Key 'status.error' -Params @([string]$script:sync.Error)); $script:sync.State = 'Idle'; Update-UcBusyState; return }
    switch ($script:sync.Tag) {
        'ProtectString' { $script:stringOutBox.Text = [string]$script:sync.Result; Set-UcStatus (Get-String -Key 'string.status.encrypted') }
        'UnprotectString' { $script:unprotectOutBox.Text = [string]$script:sync.Result; Set-UcStatus (Get-String -Key 'string.status.decrypted') }
        'ProtectFile' { $script:fileResultBox.Text = [string]$script:sync.Result; Set-UcStatus (Get-String -Key 'file.status.encrypted' -Params @([string]$script:sync.Result)) }
        'UnprotectFile' { $script:fileResultBox.Text = [string]$script:sync.Result; Set-UcStatus (Get-String -Key 'file.status.decrypted' -Params @([string]$script:sync.Result)) }
        'ProtectFolder' { Show-UcFolderResult (Get-String -Key 'folder.status.encrypted') }
        'UnprotectFolder' { Show-UcFolderResult (Get-String -Key 'folder.status.decrypted') }
        'Compress' { $script:arcPathBox.Text = [string]$script:sync.Result; Set-UcStatus (Get-String -Key 'archive.status.created' -Params @([string]$script:sync.Result)) }
        'Expand' { Set-UcStatus (Get-String -Key 'archive.status.extracted' -Params @([string]$script:sync.InDestination)) }
        'ArchiveContent' { Show-UcArchiveContent }
        'ArchivePassword' { $script:arcPasswordBox.Text = [string]$script:sync.Result; Set-UcStatus (Get-String -Key 'archive.status.password') }
        'FileInfo' { Show-UcFileInfoResult }
        'NewCert' {
            Update-UcCertificateList
            $tp = $script:sync.Result.Thumbprint; $idx = 0
            for ($i = 0; $i -lt $script:certListView.Items.Count; $i++) { if ($script:certListView.Items[$i].Tag.Thumbprint -eq $tp) { $script:certListView.Items[$i].Checked = $true; $idx = $i } }
            $script:certListView.EnsureVisible($idx)
            Set-UcStatus (Get-String -Key 'cert.status.created' -Params @($tp))
        }
        default { Set-UcStatus (Get-String -Key 'status.ready') }
    }
    $script:sync.State = 'Idle'
    Update-UcBusyState
}

# Create a control with specified properties
function Add-UcCtl {
    param($Parent, [Type]$Type, [int]$X, [int]$Y, [int]$W, [int]$H = 25, [string]$Anchor = 'Left,Top', [hashtable]$Props = @{})
    $c = $Type::new()
    foreach ($k in $Props.Keys) { $c.$k = $Props[$k] }
    $c.Location = [System.Drawing.Point]::new($X, $Y)
    $c.Size = [System.Drawing.Size]::new($W, $H)
    $c.Anchor = [System.Windows.Forms.AnchorStyles]$Anchor
    $Parent.Controls.Add($c)
    return $c
}

# Create browse button for file/folder selection
function Add-UcBrowse {
    param($Parent, [int]$X, [int]$Y, $TargetBox, [ValidateSet('File', 'Save', 'Folder')][string]$Kind, [string]$TitleKey, [string]$Filter)
    $btn = Add-UcCtl $Parent ([System.Windows.Forms.Button]) $X $Y 40 25 'Top,Right' @{ Text = '...' }
    switch ($Kind) {
        'File' { $btn.Add_Click({ $dlg = [System.Windows.Forms.OpenFileDialog]::new(); $dlg.Title = Get-String -Key $TitleKey; if ($Filter) { $dlg.Filter = $Filter }; if ($dlg.ShowDialog($script:mainForm) -eq [System.Windows.Forms.DialogResult]::OK) { $TargetBox.Text = $dlg.FileName } }.GetNewClosure()) }
        'Save' { $btn.Add_Click({ $dlg = [System.Windows.Forms.SaveFileDialog]::new(); $dlg.Title = Get-String -Key $TitleKey; $dlg.Filter = $Filter; $dlg.OverwritePrompt = $true; if ($dlg.ShowDialog($script:mainForm) -eq [System.Windows.Forms.DialogResult]::OK) { $TargetBox.Text = $dlg.FileName } }.GetNewClosure()) }
        'Folder' { $btn.Add_Click({ $dlg = [System.Windows.Forms.FolderBrowserDialog]::new(); $dlg.Description = Get-String -Key $TitleKey; if ($dlg.ShowDialog($script:mainForm) -eq [System.Windows.Forms.DialogResult]::OK) { $TargetBox.Text = $dlg.SelectedPath } }.GetNewClosure()) }
    }
}

# Enable drag and drop for a text box
function Enable-UcDrop { param($TextBox)
    $TextBox.AllowDrop = $true
    $TextBox.Add_DragEnter({ param($s, $e) if ($e.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) { $e.Effect = [System.Windows.Forms.DragDropEffects]::Copy } })
    $TextBox.Add_DragDrop({ param($s, $e) $paths = $e.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop); if ($paths -and $paths.Count -gt 0) { $s.Text = $paths[0] } })
}

# Copy text to clipboard
function Copy-UcText { param($Text)
    if ([string]::IsNullOrEmpty($Text)) { Set-UcStatus (Get-String -Key 'status.copyEmpty'); return }
    try { [System.Windows.Forms.Clipboard]::SetText($Text); Set-UcStatus (Get-String -Key 'status.copied') }
    catch { Set-UcStatus (Get-String -Key 'status.copyFailed' -Params @($_.Exception.Message)) }
}

# Get selected certificates
function Get-UcSelectedCertificates {
    $list = [System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]]::new()
    foreach ($item in $script:certListView.Items) { if ($item.Checked -and $null -ne $item.Tag) { $list.Add($item.Tag) } }
    return $list.ToArray()
}

# Update selection label
function Update-UcSelectionLabel {
    $script:lblCertSelection.Text = Get-String -Key 'cert.selection.label' -Params @($script:SelectedThumbprints.Count)
}

# Update certificate list view
function Update-UcCertificateList {
    $script:certListView.BeginUpdate()
    try {
        $script:certListView.Items.Clear()
        $certs = @(Get-UCCertificates)
        foreach ($c in $certs) {
            $hasPriv = $null -ne [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)
            $item = [System.Windows.Forms.ListViewItem]::new($c.Subject)
            $null = $item.SubItems.Add($c.Thumbprint)
            $null = $item.SubItems.Add($c.NotAfter.ToString('yyyy-MM-dd'))
            $null = $item.SubItems.Add($(if ($hasPriv) { Get-String -Key 'cert.priv.yes' } else { Get-String -Key 'cert.priv.no' }))
            $item.Tag = $c
            $item.Checked = $script:SelectedThumbprints.Contains($c.Thumbprint)
            $null = $script:certListView.Items.Add($item)
        }
        # Drop thumbprints that no longer exist in the store
        $existing = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($c in $certs) { $null = $existing.Add($c.Thumbprint) }
        $null = $script:SelectedThumbprints.RemoveWhere({ param($tp) -not $existing.Contains($tp) })
    } finally { $script:certListView.EndUpdate() }
    Update-UcSelectionLabel
}

# ---------- Form ----------
$script:mainForm = [System.Windows.Forms.Form]::new()
$script:mainForm.Text = 'UniCryptor3'
$script:mainForm.ClientSize = [System.Drawing.Size]::new(900, 660)
$script:mainForm.MinimumSize = [System.Drawing.Size]::new(820, 640)
$script:mainForm.StartPosition = 'CenterScreen'
$script:mainForm.Font = [System.Drawing.Font]::new('Segoe UI', 9)

$script:mainTabControl = [System.Windows.Forms.TabControl]::new()
$script:mainTabControl.Dock = 'Fill'
$script:mainForm.Controls.Add($script:mainTabControl)

# --- Tab: Certificates ---
$tabCert = [System.Windows.Forms.TabPage]::new()
$tabCert.Size = [System.Drawing.Size]::new(900, 660)
Bind-UcText $tabCert 'tab.certificates'

$script:certListView = Add-UcCtl $tabCert ([System.Windows.Forms.ListView]) 10 10 866 340 'Left,Top,Right' @{ View = 'Details'; CheckBoxes = $true; FullRowSelect = $true; GridLines = $true }
$null = $script:certListView.Columns.Add('S', 320)
$null = $script:certListView.Columns.Add('T', 240)
$null = $script:certListView.Columns.Add('V', 110)
$null = $script:certListView.Columns.Add('P', 120)
Bind-UcText $script:certListView.Columns[0] 'cert.column.subject'
Bind-UcText $script:certListView.Columns[1] 'cert.column.thumbprint'
Bind-UcText $script:certListView.Columns[2] 'cert.column.validTo'
Bind-UcText $script:certListView.Columns[3] 'cert.column.privateKey'

$script:certListView.Add_ItemChecked({ param($s, $e)
    if ($null -eq $e.Item -or $null -eq $e.Item.Tag) { return }
    $tp = $e.Item.Tag.Thumbprint
    if ($e.Item.Checked) { $null = $script:SelectedThumbprints.Add($tp) } else { $null = $script:SelectedThumbprints.Remove($tp) }
    Update-UcSelectionLabel
})

$script:btnCertRefresh = Add-UcCtl $tabCert ([System.Windows.Forms.Button]) 10 358 150 28 'Left,Top' @{}
Bind-UcText $script:btnCertRefresh 'cert.btn.refresh'

$script:btnCertCheckAll = Add-UcCtl $tabCert ([System.Windows.Forms.Button]) 170 358 140 28 'Left,Top' @{}
Bind-UcText $script:btnCertCheckAll 'cert.btn.selectAll'

$script:btnCertUncheckAll = Add-UcCtl $tabCert ([System.Windows.Forms.Button]) 320 358 150 28 'Left,Top' @{}
Bind-UcText $script:btnCertUncheckAll 'cert.btn.clear'

Bind-UcText (Add-UcCtl $tabCert ([System.Windows.Forms.Label]) 10 400 190 23 'Left,Top' @{}) 'cert.label.newSubject'

$script:certSubjectBox = Add-UcCtl $tabCert ([System.Windows.Forms.TextBox]) 205 397 300 25 'Left,Top' @{}

$script:btnNewCert = Add-UcCtl $tabCert ([System.Windows.Forms.Button]) 515 396 220 28 'Left,Top' @{}
Bind-UcText $script:btnNewCert 'cert.btn.create'

$script:lblCertSelection = Add-UcCtl $tabCert ([System.Windows.Forms.Label]) 10 434 866 40 'Left,Top,Right' @{ AutoSize = $false; ForeColor = [System.Drawing.Color]::DimGray }

Bind-UcText (Add-UcCtl $tabCert ([System.Windows.Forms.Label]) 10 484 80 23 'Left,Top' @{}) 'language.label'

$script:langCombo = Add-UcCtl $tabCert ([System.Windows.Forms.ComboBox]) 95 481 240 25 'Left,Top' @{ DropDownStyle = 'DropDownList' }

$script:btnCertRefresh.Add_Click({ Update-UcCertificateList })
$script:btnCertCheckAll.Add_Click({ foreach ($item in $script:certListView.Items) { $item.Checked = $true } })
$script:btnCertUncheckAll.Add_Click({ foreach ($item in $script:certListView.Items) { $item.Checked = $false } })

$script:btnNewCert.Add_Click({
    if ([string]::IsNullOrWhiteSpace($script:certSubjectBox.Text)) { Set-UcStatus (Get-String -Key 'cert.status.needSubject'); return }
    Start-UcOperation 'NewCert' $script:bodies.NewCert @{ InSubject = $script:certSubjectBox.Text }
})

# --- Tab: String ---
$tabString = [System.Windows.Forms.TabPage]::new()
$tabString.Size = [System.Drawing.Size]::new(900, 660)
Bind-UcText $tabString 'tab.string'

$gb1 = Add-UcCtl $tabString ([System.Windows.Forms.GroupBox]) 10 8 880 300 'Left,Top,Right' @{}
Bind-UcText $gb1 'string.group.protect'

Bind-UcText (Add-UcCtl $gb1 ([System.Windows.Forms.Label]) 14 22 120 23 'Left,Top' @{}) 'label.text'

$script:stringInBox = Add-UcCtl $gb1 ([System.Windows.Forms.TextBox]) 14 45 852 64 'Left,Top,Right' @{ Multiline = $true; ScrollBars = 'Vertical' }

$script:rdoStringCert = Add-UcCtl $gb1 ([System.Windows.Forms.RadioButton]) 14 116 280 25 'Left,Top' @{ Checked = $true }
Bind-UcText $script:rdoStringCert 'mode.certificates'

$script:rdoStringPass = Add-UcCtl $gb1 ([System.Windows.Forms.RadioButton]) 300 116 80 25 'Left,Top' @{}
Bind-UcText $script:rdoStringPass 'mode.password'

$script:stringPassBox = Add-UcCtl $gb1 ([System.Windows.Forms.TextBox]) 384 113 150 25 'Left,Top' @{ UseSystemPasswordChar = $true }

$script:chkStringShow = Add-UcCtl $gb1 ([System.Windows.Forms.CheckBox]) 540 114 90 25 'Left,Top' @{}
Bind-UcText $script:chkStringShow 'label.show'

$script:btnProtectString = Add-UcCtl $gb1 ([System.Windows.Forms.Button]) 14 146 140 28 'Left,Top' @{}
Bind-UcText $script:btnProtectString 'btn.encrypt'

$script:btnCopyProtectOut = Add-UcCtl $gb1 ([System.Windows.Forms.Button]) 162 146 150 28 'Left,Top' @{}
Bind-UcText $script:btnCopyProtectOut 'btn.copyResult'

Bind-UcText (Add-UcCtl $gb1 ([System.Windows.Forms.Label]) 14 184 160 23 'Left,Top' @{}) 'label.resultB64'

$script:stringOutBox = Add-UcCtl $gb1 ([System.Windows.Forms.TextBox]) 14 207 852 80 'Left,Top,Right,Bottom' @{ Multiline = $true; ScrollBars = 'Vertical'; ReadOnly = $true }

$gb2 = Add-UcCtl $tabString ([System.Windows.Forms.GroupBox]) 10 316 880 268 'Left,Top,Right' @{}
Bind-UcText $gb2 'string.group.unprotect'

Bind-UcText (Add-UcCtl $gb2 ([System.Windows.Forms.Label]) 14 22 120 23 'Left,Top' @{}) 'label.base64'

$script:unprotectInBox = Add-UcCtl $gb2 ([System.Windows.Forms.TextBox]) 14 45 852 64 'Left,Top,Right' @{ Multiline = $true; ScrollBars = 'Vertical' }

Bind-UcText (Add-UcCtl $gb2 ([System.Windows.Forms.Label]) 14 120 150 23 'Left,Top' @{}) 'label.passwordIf'

$script:stringUnprotectPassBox = Add-UcCtl $gb2 ([System.Windows.Forms.TextBox]) 170 117 200 25 'Left,Top' @{ UseSystemPasswordChar = $true }

$script:btnUnprotectString = Add-UcCtl $gb2 ([System.Windows.Forms.Button]) 14 146 140 28 'Left,Top' @{}
Bind-UcText $script:btnUnprotectString 'btn.decrypt'

$script:btnPasteUnprotectIn = Add-UcCtl $gb2 ([System.Windows.Forms.Button]) 162 146 170 28 'Left,Top' @{}
Bind-UcText $script:btnPasteUnprotectIn 'btn.paste'

$script:btnCopyUnprotectOut = Add-UcCtl $gb2 ([System.Windows.Forms.Button]) 340 146 150 28 'Left,Top' @{}
Bind-UcText $script:btnCopyUnprotectOut 'btn.copyResult'

Bind-UcText (Add-UcCtl $gb2 ([System.Windows.Forms.Label]) 14 184 160 23 'Left,Top' @{}) 'label.result'

$script:unprotectOutBox = Add-UcCtl $gb2 ([System.Windows.Forms.TextBox]) 14 207 852 55 'Left,Top,Right,Bottom' @{ Multiline = $true; ScrollBars = 'Vertical'; ReadOnly = $true }

$script:chkStringShow.Add_CheckedChanged({ $script:stringPassBox.UseSystemPasswordChar = -not $script:chkStringShow.Checked })

$script:btnProtectString.Add_Click({
    $mode = if ($script:rdoStringPass.Checked) { 'Password' } else { 'Cert' }
    if ([string]::IsNullOrWhiteSpace($script:stringInBox.Text)) { Set-UcStatus (Get-String -Key 'string.status.needText'); return }
    if ($mode -eq 'Password' -and [string]::IsNullOrEmpty($script:stringPassBox.Text)) { Set-UcStatus (Get-String -Key 'status.needPassword'); return }
    Start-UcOperation 'ProtectString' $script:bodies.ProtectString @{
        InText = $script:stringInBox.Text; InMode = $mode; InPassword = $script:stringPassBox.Text; InCerts = @(Get-UcSelectedCertificates)
    }
})

$script:btnCopyProtectOut.Add_Click({ Copy-UcText $script:stringOutBox.Text })

$script:btnUnprotectString.Add_Click({
    if ([string]::IsNullOrWhiteSpace($script:unprotectInBox.Text)) { Set-UcStatus (Get-String -Key 'string.status.needBase64'); return }
    Start-UcOperation 'UnprotectString' $script:bodies.UnprotectString @{ InText = $script:unprotectInBox.Text.Trim(); InPassword = $script:stringUnprotectPassBox.Text }
})

$script:btnPasteUnprotectIn.Add_Click({ try { $script:unprotectInBox.Text = [System.Windows.Forms.Clipboard]::GetText() } catch { Set-UcStatus (Get-String -Key 'status.clipboardFail' -Params @($_.Exception.Message)) } })

$script:btnCopyUnprotectOut.Add_Click({ Copy-UcText $script:unprotectOutBox.Text })

# --- Tab: File ---
$tabFile = [System.Windows.Forms.TabPage]::new()
$tabFile.Size = [System.Drawing.Size]::new(900, 660)
Bind-UcText $tabFile 'tab.file'

$gbF = Add-UcCtl $tabFile ([System.Windows.Forms.GroupBox]) 10 8 880 310 'Left,Top,Right' @{}
Bind-UcText $gbF 'file.group'

Bind-UcText (Add-UcCtl $gbF ([System.Windows.Forms.Label]) 14 22 200 23 'Left,Top' @{}) 'label.srcFile'

$script:filePathBox = Add-UcCtl $gbF ([System.Windows.Forms.TextBox]) 14 45 796 25 'Left,Top,Right' @{}
Add-UcBrowse $gbF 826 44 $script:filePathBox 'File' 'dlg.selectFile' 'All files (*.*)|*.*'

Bind-UcText (Add-UcCtl $gbF ([System.Windows.Forms.Label]) 14 79 380 23 'Left,Top' @{}) 'label.destFolderFile'

$script:fileDestBox = Add-UcCtl $gbF ([System.Windows.Forms.TextBox]) 14 102 796 25 'Left,Top,Right' @{}
Add-UcBrowse $gbF 826 101 $script:fileDestBox 'Folder' 'dlg.selectFolder' ''

$script:chkFileOverwrite = Add-UcCtl $gbF ([System.Windows.Forms.CheckBox]) 14 134 320 25 'Left,Top' @{}
Bind-UcText $script:chkFileOverwrite 'chk.overwrite'

$script:rdoFileCert = Add-UcCtl $gbF ([System.Windows.Forms.RadioButton]) 14 162 280 25 'Left,Top' @{ Checked = $true }
Bind-UcText $script:rdoFileCert 'mode.certificates'

$script:rdoFilePass = Add-UcCtl $gbF ([System.Windows.Forms.RadioButton]) 300 162 80 25 'Left,Top' @{}
Bind-UcText $script:rdoFilePass 'mode.password'

$script:filePassBox = Add-UcCtl $gbF ([System.Windows.Forms.TextBox]) 384 159 150 25 'Left,Top' @{ UseSystemPasswordChar = $true }

$script:chkFileShow = Add-UcCtl $gbF ([System.Windows.Forms.CheckBox]) 540 160 90 25 'Left,Top' @{}
Bind-UcText $script:chkFileShow 'label.show'

$script:btnProtectFile = Add-UcCtl $gbF ([System.Windows.Forms.Button]) 14 190 140 28 'Left,Top' @{}
Bind-UcText $script:btnProtectFile 'btn.encrypt'

$script:btnUnprotectFile = Add-UcCtl $gbF ([System.Windows.Forms.Button]) 162 190 140 28 'Left,Top' @{}
Bind-UcText $script:btnUnprotectFile 'btn.decrypt'

Bind-UcText (Add-UcCtl $gbF ([System.Windows.Forms.Label]) 14 228 160 23 'Left,Top' @{}) 'label.result'

$script:fileResultBox = Add-UcCtl $gbF ([System.Windows.Forms.TextBox]) 14 251 690 44 'Left,Top,Right' @{ Multiline = $true; ReadOnly = $true }

$script:btnOpenFileFolder = Add-UcCtl $gbF ([System.Windows.Forms.Button]) 714 250 152 28 'Top,Right' @{}
Bind-UcText $script:btnOpenFileFolder 'btn.openFolder'

$script:chkFileShow.Add_CheckedChanged({ $script:filePassBox.UseSystemPasswordChar = -not $script:chkFileShow.Checked })

Enable-UcDrop $script:filePathBox
Enable-UcDrop $script:fileDestBox

$script:btnProtectFile.Add_Click({
    $mode = if ($script:rdoFilePass.Checked) { 'Password' } else { 'Cert' }
    if ([string]::IsNullOrWhiteSpace($script:filePathBox.Text)) { Set-UcStatus (Get-String -Key 'file.status.needSrc'); return }
    if ($mode -eq 'Password' -and [string]::IsNullOrEmpty($script:filePassBox.Text)) { Set-UcStatus (Get-String -Key 'status.needPassword'); return }
    Start-UcOperation 'ProtectFile' $script:bodies.ProtectFile @{
        InPath = $script:filePathBox.Text; InDestination = $script:fileDestBox.Text; InOverwrite = [bool]$script:chkFileOverwrite.Checked
        InMode = $mode; InPassword = $script:filePassBox.Text; InCerts = @(Get-UcSelectedCertificates)
    }
})

$script:btnUnprotectFile.Add_Click({
    if ([string]::IsNullOrWhiteSpace($script:filePathBox.Text)) { Set-UcStatus (Get-String -Key 'file.status.needSrc'); return }
    Start-UcOperation 'UnprotectFile' $script:bodies.UnprotectFile @{
        InPath = $script:filePathBox.Text; InDestination = $script:fileDestBox.Text; InOverwrite = [bool]$script:chkFileOverwrite.Checked
        InPassword = $script:filePassBox.Text
    }
})

$script:btnOpenFileFolder.Add_Click({
    $p = $script:fileResultBox.Text
    if ($p -and (Test-Path -LiteralPath $p)) { Start-Process explorer.exe -ArgumentList "/select,`"$p`"" } else { Set-UcStatus (Get-String -Key 'status.noResultToOpen') }
})

# --- Tab: Folder ---
$tabFolder = [System.Windows.Forms.TabPage]::new()
$tabFolder.Size = [System.Drawing.Size]::new(900, 660)
Bind-UcText $tabFolder 'tab.folder'

$gbFo = Add-UcCtl $tabFolder ([System.Windows.Forms.GroupBox]) 10 8 880 340 'Left,Top,Right' @{}
Bind-UcText $gbFo 'folder.group'

Bind-UcText (Add-UcCtl $gbFo ([System.Windows.Forms.Label]) 14 22 200 23 'Left,Top' @{}) 'label.srcFolder'

$script:folderPathBox = Add-UcCtl $gbFo ([System.Windows.Forms.TextBox]) 14 45 796 25 'Left,Top,Right' @{}
Add-UcBrowse $gbFo 826 44 $script:folderPathBox 'Folder' 'dlg.selectFolder' ''

Bind-UcText (Add-UcCtl $gbFo ([System.Windows.Forms.Label]) 14 79 380 23 'Left,Top' @{}) 'label.destFolderEmpty'

$script:folderDestBox = Add-UcCtl $gbFo ([System.Windows.Forms.TextBox]) 14 102 796 25 'Left,Top,Right' @{}
Add-UcBrowse $gbFo 826 101 $script:folderDestBox 'Folder' 'dlg.selectFolder' ''

$script:chkFolderRecurse = Add-UcCtl $gbFo ([System.Windows.Forms.CheckBox]) 14 134 260 25 'Left,Top' @{}
Bind-UcText $script:chkFolderRecurse 'chk.recurse'

$script:chkFolderOverwrite = Add-UcCtl $gbFo ([System.Windows.Forms.CheckBox]) 300 134 320 25 'Left,Top' @{}
Bind-UcText $script:chkFolderOverwrite 'chk.overwrite'

$script:rdoFolderCert = Add-UcCtl $gbFo ([System.Windows.Forms.RadioButton]) 14 162 280 25 'Left,Top' @{ Checked = $true }
Bind-UcText $script:rdoFolderCert 'mode.certificates'

$script:rdoFolderPass = Add-UcCtl $gbFo ([System.Windows.Forms.RadioButton]) 300 162 80 25 'Left,Top' @{}
Bind-UcText $script:rdoFolderPass 'mode.password'

$script:folderPassBox = Add-UcCtl $gbFo ([System.Windows.Forms.TextBox]) 384 159 150 25 'Left,Top' @{ UseSystemPasswordChar = $true }

$script:chkFolderShow = Add-UcCtl $gbFo ([System.Windows.Forms.CheckBox]) 540 160 90 25 'Left,Top' @{}
Bind-UcText $script:chkFolderShow 'label.show'

$script:btnProtectFolder = Add-UcCtl $gbFo ([System.Windows.Forms.Button]) 14 190 170 28 'Left,Top' @{}
Bind-UcText $script:btnProtectFolder 'btn.encryptFolder'

$script:btnUnprotectFolder = Add-UcCtl $gbFo ([System.Windows.Forms.Button]) 192 190 170 28 'Left,Top' @{}
Bind-UcText $script:btnUnprotectFolder 'btn.decryptFolder'

Bind-UcText (Add-UcCtl $gbFo ([System.Windows.Forms.Label]) 14 228 160 23 'Left,Top' @{}) 'label.summary'

$script:folderResultBox = Add-UcCtl $gbFo ([System.Windows.Forms.TextBox]) 14 251 852 76 'Left,Top,Right,Bottom' @{ Multiline = $true; ScrollBars = 'Vertical'; ReadOnly = $true }

$script:chkFolderShow.Add_CheckedChanged({ $script:folderPassBox.UseSystemPasswordChar = -not $script:chkFolderShow.Checked })

Enable-UcDrop $script:folderPathBox
Enable-UcDrop $script:folderDestBox

$script:btnProtectFolder.Add_Click({
    $mode = if ($script:rdoFolderPass.Checked) { 'Password' } else { 'Cert' }
    if ([string]::IsNullOrWhiteSpace($script:folderPathBox.Text)) { Set-UcStatus (Get-String -Key 'folder.status.needSrc'); return }
    if ($mode -eq 'Password' -and [string]::IsNullOrEmpty($script:folderPassBox.Text)) { Set-UcStatus (Get-String -Key 'status.needPassword'); return }
    Start-UcOperation 'ProtectFolder' $script:bodies.ProtectFolder @{
        InFolder = $script:folderPathBox.Text; InDestination = $script:folderDestBox.Text; InRecurse = [bool]$script:chkFolderRecurse.Checked
        InOverwrite = [bool]$script:chkFolderOverwrite.Checked; InMode = $mode; InPassword = $script:folderPassBox.Text; InCerts = @(Get-UcSelectedCertificates)
    }
})

$script:btnUnprotectFolder.Add_Click({
    if ([string]::IsNullOrWhiteSpace($script:folderPathBox.Text)) { Set-UcStatus (Get-String -Key 'folder.status.needSrc'); return }
    Start-UcOperation 'UnprotectFolder' $script:bodies.UnprotectFolder @{
        InFolder = $script:folderPathBox.Text; InDestination = $script:folderDestBox.Text; InRecurse = [bool]$script:chkFolderRecurse.Checked
        InOverwrite = [bool]$script:chkFolderOverwrite.Checked; InPassword = $script:folderPassBox.Text
    }
})

# --- Tab: Archive ---
$tabArc = [System.Windows.Forms.TabPage]::new()
$tabArc.Size = [System.Drawing.Size]::new(900, 660)
Bind-UcText $tabArc 'tab.archive'

$gbA1 = Add-UcCtl $tabArc ([System.Windows.Forms.GroupBox]) 10 8 880 220 'Left,Top,Right' @{}
Bind-UcText $gbA1 'archive.group.create'

Bind-UcText (Add-UcCtl $gbA1 ([System.Windows.Forms.Label]) 14 22 200 23 'Left,Top' @{}) 'label.srcFolder'

$script:arcFolderBox = Add-UcCtl $gbA1 ([System.Windows.Forms.TextBox]) 14 45 796 25 'Left,Top,Right' @{}
Add-UcBrowse $gbA1 826 44 $script:arcFolderBox 'Folder' 'dlg.selectFolder' ''

Bind-UcText (Add-UcCtl $gbA1 ([System.Windows.Forms.Label]) 14 79 200 23 'Left,Top' @{}) 'label.archiveFile'

$script:arcDestBox = Add-UcCtl $gbA1 ([System.Windows.Forms.TextBox]) 14 102 796 25 'Left,Top,Right' @{}
Add-UcBrowse $gbA1 826 101 $script:arcDestBox 'Save' 'dlg.selectArchiveSave' '7z archive (*.7z)|*.7z|All files (*.*)|*.*'

Bind-UcText (Add-UcCtl $gbA1 ([System.Windows.Forms.Label]) 14 136 110 23 'Left,Top' @{}) 'label.compressionLevel'

$script:comboLevel = Add-UcCtl $gbA1 ([System.Windows.Forms.ComboBox]) 130 133 130 25 'Left,Top' @{ DropDownStyle = 'DropDownList' }
$null = $script:comboLevel.Items.AddRange(@('None', 'Fast', 'Normal', 'High', 'Ultra'))
$script:comboLevel.SelectedIndex = 2

$script:chkArcOnlyBit = Add-UcCtl $gbA1 ([System.Windows.Forms.CheckBox]) 275 135 260 25 'Left,Top' @{}
Bind-UcText $script:chkArcOnlyBit 'chk.onlyArchiveBit'

$script:chkArcClearBit = Add-UcCtl $gbA1 ([System.Windows.Forms.CheckBox]) 545 135 250 25 'Left,Top' @{}
Bind-UcText $script:chkArcClearBit 'chk.clearArchiveBit'

$script:btnCompress = Add-UcCtl $gbA1 ([System.Windows.Forms.Button]) 14 168 150 28 'Left,Top' @{}
Bind-UcText $script:btnCompress 'btn.createArchive'

Bind-UcText (Add-UcCtl $gbA1 ([System.Windows.Forms.Label]) 14 196 852 20 'Left,Top' @{ AutoSize = $false; ForeColor = [System.Drawing.Color]::DimGray }) 'archive.hint'

$gbA2 = Add-UcCtl $tabArc ([System.Windows.Forms.GroupBox]) 10 236 880 150 'Left,Top,Right' @{}
Bind-UcText $gbA2 'archive.group.extract'

Bind-UcText (Add-UcCtl $gbA2 ([System.Windows.Forms.Label]) 14 22 120 23 'Left,Top' @{}) 'label.archive'

$script:arcPathBox = Add-UcCtl $gbA2 ([System.Windows.Forms.TextBox]) 14 45 796 25 'Left,Top,Right' @{}
Add-UcBrowse $gbA2 826 44 $script:arcPathBox 'File' 'dlg.selectArchiveOpen' '7z archive (*.7z)|*.7z|All files (*.*)|*.*'

Bind-UcText (Add-UcCtl $gbA2 ([System.Windows.Forms.Label]) 14 79 200 23 'Left,Top' @{}) 'label.destFolder'

$script:arcExtractBox = Add-UcCtl $gbA2 ([System.Windows.Forms.TextBox]) 14 102 796 25 'Left,Top,Right' @{}
Add-UcBrowse $gbA2 826 101 $script:arcExtractBox 'Folder' 'dlg.selectFolder' ''

$script:chkArcOverwrite = Add-UcCtl $gbA2 ([System.Windows.Forms.CheckBox]) 14 134 300 25 'Left,Top' @{}
Bind-UcText $script:chkArcOverwrite 'chk.overwrite'

$script:btnExtract = Add-UcCtl $gbA2 ([System.Windows.Forms.Button]) 330 133 150 28 'Left,Top' @{}
Bind-UcText $script:btnExtract 'btn.extract'

$script:btnArcContent = Add-UcCtl $gbA2 ([System.Windows.Forms.Button]) 490 133 140 28 'Left,Top' @{}
Bind-UcText $script:btnArcContent 'btn.content'

$gbA3 = Add-UcCtl $tabArc ([System.Windows.Forms.GroupBox]) 10 394 880 160 'Left,Top,Right' @{}
Bind-UcText $gbA3 'archive.group.tools'

Bind-UcText (Add-UcCtl $gbA3 ([System.Windows.Forms.Label]) 14 24 120 23 'Left,Top' @{}) 'label.archivePassword'

$script:arcPasswordBox = Add-UcCtl $gbA3 ([System.Windows.Forms.TextBox]) 140 21 230 25 'Left,Top' @{ ReadOnly = $true; UseSystemPasswordChar = $true }

$script:btnArcPassword = Add-UcCtl $gbA3 ([System.Windows.Forms.Button]) 380 20 150 27 'Left,Top' @{}
Bind-UcText $script:btnArcPassword 'btn.showPassword'

$script:chkArcShowPass = Add-UcCtl $gbA3 ([System.Windows.Forms.CheckBox]) 540 21 90 25 'Left,Top' @{}
Bind-UcText $script:chkArcShowPass 'label.show'

$script:archiveListView = Add-UcCtl $gbA3 ([System.Windows.Forms.ListView]) 14 54 852 94 'Left,Top,Right' @{ View = 'Details'; FullRowSelect = $true; GridLines = $true }
$null = $script:archiveListView.Columns.Add('N', 400)
$null = $script:archiveListView.Columns.Add('S', 120)
$null = $script:archiveListView.Columns.Add('M', 150)
$null = $script:archiveListView.Columns.Add('T', 100)
Bind-UcText $script:archiveListView.Columns[0] 'archive.column.name'
Bind-UcText $script:archiveListView.Columns[1] 'archive.column.size'
Bind-UcText $script:archiveListView.Columns[2] 'archive.column.modified'
Bind-UcText $script:archiveListView.Columns[3] 'archive.column.type'

$script:chkArcShowPass.Add_CheckedChanged({ $script:arcPasswordBox.UseSystemPasswordChar = -not $script:chkArcShowPass.Checked })

Enable-UcDrop $script:arcFolderBox
Enable-UcDrop $script:arcPathBox

$script:btnCompress.Add_Click({
    if ([string]::IsNullOrWhiteSpace($script:arcFolderBox.Text)) { Set-UcStatus (Get-String -Key 'archive.status.needFolder'); return }
    if ([string]::IsNullOrWhiteSpace($script:arcDestBox.Text)) { Set-UcStatus (Get-String -Key 'archive.status.needArchive'); return }
    Start-UcOperation 'Compress' $script:bodies.Compress @{
        InFolder = $script:arcFolderBox.Text; InArchive = $script:arcDestBox.Text; InOverwrite = $true
        InLevel = [string]$script:comboLevel.SelectedItem; InOnlyBit = [bool]$script:chkArcOnlyBit.Checked
        InClearBit = [bool]$script:chkArcClearBit.Checked; InCerts = @(Get-UcSelectedCertificates)
    }
})

$script:btnExtract.Add_Click({
    if ([string]::IsNullOrWhiteSpace($script:arcPathBox.Text)) { Set-UcStatus (Get-String -Key 'archive.status.needArchive'); return }
    Start-UcOperation 'Expand' $script:bodies.Expand @{
        InArchive = $script:arcPathBox.Text; InDestination = $script:arcExtractBox.Text; InOverwrite = [bool]$script:chkArcOverwrite.Checked
    }
})

$script:btnArcContent.Add_Click({
    if ([string]::IsNullOrWhiteSpace($script:arcPathBox.Text)) { Set-UcStatus (Get-String -Key 'archive.status.needArchive'); return }
    Start-UcOperation 'ArchiveContent' $script:bodies.ArchiveContent @{ InArchive = $script:arcPathBox.Text }
})

$script:btnArcPassword.Add_Click({
    if ([string]::IsNullOrWhiteSpace($script:arcPathBox.Text)) { Set-UcStatus (Get-String -Key 'archive.status.needArchive'); return }
    Start-UcOperation 'ArchivePassword' $script:bodies.ArchivePassword @{ InArchive = $script:arcPathBox.Text }
})

# --- Tab: Container info ---
$tabInfo = [System.Windows.Forms.TabPage]::new()
$tabInfo.Size = [System.Drawing.Size]::new(900, 660)
Bind-UcText $tabInfo 'tab.container'

Bind-UcText (Add-UcCtl $tabInfo ([System.Windows.Forms.Label]) 10 12 260 23 'Left,Top' @{}) 'container.label.path'

$script:infoPathBox = Add-UcCtl $tabInfo ([System.Windows.Forms.TextBox]) 10 35 816 25 'Left,Top,Right' @{}
Add-UcBrowse $tabInfo 836 34 $script:infoPathBox 'File' 'dlg.selectContainer' 'Containers (*.AESPKI)|*.AESPKI|All files (*.*)|*.*'

$script:btnGetInfo = Add-UcCtl $tabInfo ([System.Windows.Forms.Button]) 10 68 150 28 'Left,Top' @{}
Bind-UcText $script:btnGetInfo 'container.btn.info'

$script:infoTextBox = Add-UcCtl $tabInfo ([System.Windows.Forms.TextBox]) 10 104 876 150 'Left,Top,Right' @{ Multiline = $true; ScrollBars = 'Vertical'; ReadOnly = $true }

Bind-UcText (Add-UcCtl $tabInfo ([System.Windows.Forms.Label]) 10 262 400 23 'Left,Top' @{}) 'container.label.recipients'

$script:infoListView = Add-UcCtl $tabInfo ([System.Windows.Forms.ListView]) 10 285 876 220 'Left,Top,Right' @{ View = 'Details'; FullRowSelect = $true; GridLines = $true }
$null = $script:infoListView.Columns.Add('K', 300)
$null = $script:infoListView.Columns.Add('C', 540)
Bind-UcText $script:infoListView.Columns[0] 'cert.column.thumbprint'
Bind-UcText $script:infoListView.Columns[1] 'container.label.recipients'

$script:btnCopyInfo = Add-UcCtl $tabInfo ([System.Windows.Forms.Button]) 10 512 180 28 'Left,Top' @{}
Bind-UcText $script:btnCopyInfo 'container.btn.copyReport'

Enable-UcDrop $script:infoPathBox

$script:btnGetInfo.Add_Click({
    if ([string]::IsNullOrWhiteSpace($script:infoPathBox.Text)) { Set-UcStatus (Get-String -Key 'container.status.needPath'); return }
    Start-UcOperation 'FileInfo' $script:bodies.FileInfo @{ InPath = $script:infoPathBox.Text }
})

$script:btnCopyInfo.Add_Click({
    $rec = @($script:infoListView.Items | ForEach-Object { "  $($_.SubItems[0].Text)  ->  $($_.SubItems[1].Text)" })
    Copy-UcText ($script:infoTextBox.Text + [Environment]::NewLine + (Get-String -Key 'container.report.recipients') + [Environment]::NewLine + ($rec -join [Environment]::NewLine))
})

# Assemble, language selector, poll timer, run
foreach ($t in @($tabCert, $tabString, $tabFile, $tabFolder, $tabArc, $tabInfo)) { $null = $script:mainTabControl.TabPages.Add($t) }

$script:statusStrip = [System.Windows.Forms.StatusStrip]::new()
$script:statusLabel = [System.Windows.Forms.ToolStripStatusLabel]::new()
$script:statusLabel.Text = ''; $script:statusLabel.Spring = $true; $script:statusLabel.TextAlign = 'MiddleLeft'
$script:progressBar = [System.Windows.Forms.ToolStripProgressBar]::new()
$script:progressBar.Size = [System.Drawing.Size]::new(220, 16)
$null = $script:statusStrip.Items.Add($script:statusLabel)
$null = $script:statusStrip.Items.Add($script:progressBar)
$script:mainForm.Controls.Add($script:statusStrip)

Apply-UcLocalization
Update-UcCertificateList

# Language selector: plain Items + parallel code list (no WinForms data binding to PS objects)
$script:langCodes = [System.Collections.Generic.List[string]]::new()
$langs = Get-LanguageList
foreach ($entry in ($langs.GetEnumerator() | Sort-Object Value)) {
    $null = $script:langCombo.Items.Add([string]$entry.Value)
    $script:langCodes.Add([string]$entry.Key)
    if ($entry.Key -eq (Get-CurrentLanguage)) { $script:langCombo.SelectedIndex = $script:langCombo.Items.Count - 1 }
}

$script:langCombo.Add_SelectedIndexChanged({
    if ($this.SelectedIndex -lt 0) { return }
    $code = $script:langCodes[$this.SelectedIndex]
    if ($code -ne (Get-CurrentLanguage)) {
        $null = Set-Language -LanguageCode $code
        Update-UcCertificateList
        Apply-UcLocalization
    }
})

$script:pollTimer = [System.Windows.Forms.Timer]::new()
$script:pollTimer.Interval = 200
$script:pollTimer.Add_Tick({
    for ($i = $script:jobs.Count - 1; $i -ge 0; $i--) {
        $job = $script:jobs[$i]
        if (-not $job.Handle.IsCompleted) { continue }
        try { $null = $job.PS.EndInvoke($job.Handle) } catch { $script:sync.Error = $_.Exception.GetBaseException().Message }
        finally { $job.PS.Dispose() }
        $script:jobs.RemoveAt($i)
        if ($script:sync.State -eq 'Running') { Complete-UcOperation }
    }
    if ($script:sync.State -eq 'Running') {
        $status = Get-String -Key 'status.running' -Params @($script:sync.Tag)
        if ($script:sync.StatusText) { $status += " - $($script:sync.StatusText)" }
        Set-UcStatus $status
        if ($script:sync.Percent -ge 0) {
            $script:progressBar.Style = 'Continuous'
            if ($script:progressBar.Value -ne $script:sync.Percent) { $script:progressBar.Value = $script:sync.Percent }
        } else { $script:progressBar.Style = 'Marquee' }
    }
})

$script:pollTimer.Start()

$script:mainForm.Add_FormClosing({ param($s, $e)
    if ($script:sync.State -eq 'Running') {
        $answer = [System.Windows.Forms.MessageBox]::Show($s, (Get-String -Key 'dialog.closeConfirm'), (Get-String -Key 'dialog.title'), 'YesNo', 'Warning')
        if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { $e.Cancel = $true; return }
    }
    $script:pollTimer.Stop()
})

Set-UcStatus (Get-String -Key 'status.readyHint')
[void]$script:mainForm.ShowDialog()
$script:mainForm.Dispose()