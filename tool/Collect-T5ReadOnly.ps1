#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only Windows PowerShell 5.1 collector (T5).
.DESCRIPTION
    Collects read-only inventory data, absent-path existence checks, and
    pattern-matched running items (processes, listening ports, services, and
    scheduled tasks) into a newly created output folder with UTF-8 (no BOM)
    LF-terminated TSV files and a SHA-256 manifest.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$InventoryRoots,

    [Parameter(Mandatory = $false)]
    [string[]]$AbsentPaths = @(),

    [Parameter(Mandatory = $true)]
    [string]$OutputFolder,

    [Parameter(Mandatory = $false)]
    [string[]]$NamePatterns = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace T5Native {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WIN32_FIND_DATAW {
        public uint dwFileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftLastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftLastWriteTime;
        public uint nFileSizeHigh;
        public uint nFileSizeLow;
        public uint dwReserved0;
        public uint dwReserved1;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string cFileName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)]
        public string cAlternateFileName;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WIN32_FIND_STREAM_DATA {
        public long StreamSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
        public string cStreamName;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct BY_HANDLE_FILE_INFORMATION {
        public uint dwFileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftLastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftLastWriteTime;
        public uint dwVolumeSerialNumber;
        public uint nFileSizeHigh;
        public uint nFileSizeLow;
        public uint nNumberOfLinks;
        public uint nFileIndexHigh;
        public uint nFileIndexLow;
    }

    public static class NativeMethods {
        public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        public const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
        public const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
        public const uint IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003;
        public const uint IO_REPARSE_TAG_SYMLINK = 0xA000000C;
        public const uint GENERIC_READ = 0x80000000;
        public const uint FILE_SHARE_READ = 0x00000001;
        public const uint FILE_SHARE_WRITE = 0x00000002;
        public const uint FILE_SHARE_DELETE = 0x00000004;
        public const uint OPEN_EXISTING = 3;
        public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        public const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        public const int FindExInfoStandard = 0;
        public const int FindExSearchNameMatch = 0;
        public const int FindExSearchLimitToDirectories = 1;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr FindFirstFileExW(
            string lpFileName,
            int fInfoLevelId,
            out WIN32_FIND_DATAW lpFindFileData,
            int fSearchOp,
            IntPtr lpSearchFilter,
            int dwAdditionalFlags);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool FindNextFileW(IntPtr hFindFile, out WIN32_FIND_DATAW lpFindFileData);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FindClose(IntPtr hFindFile);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr FindFirstStreamW(
            string lpFileName,
            int InfoLevel,
            out WIN32_FIND_STREAM_DATA lpFindStreamData,
            uint dwFlags);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool FindNextStreamW(IntPtr hFindStream, out WIN32_FIND_STREAM_DATA lpFindStreamData);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr CreateFileW(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool GetFileInformationByHandle(
            IntPtr hFile,
            out BY_HANDLE_FILE_INFORMATION lpFileInformation);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CloseHandle(IntPtr hObject);
    }
}
"@

function ConvertTo-ExtendedPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [System.IO.Path]::GetFullPath($Path)
    if ($full.StartsWith('\\?\')) {
        return $full
    }
    if ($full.StartsWith('\\')) {
        return '\\?\UNC\' + $full.TrimStart('\')
    }
    return '\\?\' + $full
}

function Sanitize-Field {
    param([AllowNull()][string]$Value)
    if ($null -eq $Value) { return '' }
    return ($Value -replace "[\r\n\t]", ' ')
}

function Write-Utf8LfFile {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Lines
    )
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $content = if ($Lines.Count -gt 0) { ($Lines -join "`n") + "`n" } else { '' }
    [System.IO.File]::WriteAllText($FilePath, $content, $utf8NoBom)
}

function Get-FileSha256Hex {
    param([Parameter(Mandatory = $true)][string]$TargetPath)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $fs = New-Object System.IO.FileStream(
            $TargetPath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
        )
        try {
            $hashBytes = $sha.ComputeHash($fs)
            return ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()
        }
        finally {
            $fs.Dispose()
        }
    }
    finally {
        $sha.Dispose()
    }
}

function Get-AlternateStreamsInfo {
    param([Parameter(Mandatory = $true)][string]$ExtendedPath)
    $streams = New-Object System.Collections.Generic.List[object]
    $streamData = New-Object T5Native.WIN32_FIND_STREAM_DATA
    $hStream = [T5Native.NativeMethods]::FindFirstStreamW($ExtendedPath, 0, [ref]$streamData, 0)
    if ($hStream -eq [T5Native.NativeMethods]::INVALID_HANDLE_VALUE) {
        return @{ Streams = $streams; Error = '' }
    }
    try {
        do {
            $rawName = $streamData.cStreamName
            if (-not [string]::IsNullOrEmpty($rawName) -and $rawName -ne '::$DATA') {
                $cleanName = $rawName
                if ($cleanName.StartsWith(':')) { $cleanName = $cleanName.Substring(1) }
                if ($cleanName.EndsWith(':$DATA')) {
                    $cleanName = $cleanName.Substring(0, $cleanName.Length - 6)
                }
                $streamSize = [long]$streamData.StreamSize
                $streamHash = ''
                $streamError = ''
                if ($streamSize -eq 0) {
                    $sha = [System.Security.Cryptography.SHA256]::Create()
                    try {
                        $streamHash = ([System.BitConverter]::ToString($sha.ComputeHash([byte[]]@())) -replace '-', '').ToLowerInvariant()
                    }
                    finally {
                        $sha.Dispose()
                    }
                }
                else {
                    try {
                        $streamHash = Get-FileSha256Hex -TargetPath ($ExtendedPath + ':' + $cleanName)
                    }
                    catch {
                        $streamError = $_.Exception.Message
                    }
                }
                $streams.Add([PSCustomObject]@{
                    Name  = $cleanName
                    Size  = $streamSize
                    Sha256 = $streamHash
                    Error = $streamError
                })
            }
        } while ([T5Native.NativeMethods]::FindNextStreamW($hStream, [ref]$streamData))
    }
    finally {
        [T5Native.NativeMethods]::FindClose($hStream) | Out-Null
    }
    return @{ Streams = $streams; Error = '' }
}

function Get-LinkAndHardLinkInfo {
    param(
        [Parameter(Mandatory = $true)][string]$ExtendedPath,
        [Parameter(Mandatory = $true)][uint32]$Attributes
    )
    $isReparse = (($Attributes -band [T5Native.NativeMethods]::FILE_ATTRIBUTE_REPARSE_POINT) -ne 0)
    $isDir = (($Attributes -band [T5Native.NativeMethods]::FILE_ATTRIBUTE_DIRECTORY) -ne 0)
    $linkStatus = if ($isReparse) {
        if ($isDir) { 'LINK_OR_JUNCTION_DIR' } else { 'LINK_OR_JUNCTION_FILE' }
    } else {
        'NO'
    }

    $flags = [T5Native.NativeMethods]::FILE_FLAG_BACKUP_SEMANTICS
    if ($isReparse) {
        $flags = $flags -bor [T5Native.NativeMethods]::FILE_FLAG_OPEN_REPARSE_POINT
    }

    $hFile = [T5Native.NativeMethods]::CreateFileW(
        $ExtendedPath,
        0,
        [T5Native.NativeMethods]::FILE_SHARE_READ -bor [T5Native.NativeMethods]::FILE_SHARE_WRITE -bor [T5Native.NativeMethods]::FILE_SHARE_DELETE,
        [IntPtr]::Zero,
        [T5Native.NativeMethods]::OPEN_EXISTING,
        $flags,
        [IntPtr]::Zero
    )
    if ($hFile -eq [T5Native.NativeMethods]::INVALID_HANDLE_VALUE) {
        $errCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        return @{
            HardLinks = ''
            LinkStatus = $linkStatus
            Error = "CreateFileW failed (Win32 error $errCode)"
        }
    }
    try {
        $info = New-Object T5Native.BY_HANDLE_FILE_INFORMATION
        if (-not [T5Native.NativeMethods]::GetFileInformationByHandle($hFile, [ref]$info)) {
            $errCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            return @{
                HardLinks = ''
                LinkStatus = $linkStatus
                Error = "GetFileInformationByHandle failed (Win32 error $errCode)"
            }
        }
        return @{
            HardLinks = [string]$info.nNumberOfLinks
            LinkStatus = $linkStatus
            Error = ''
        }
    }
    finally {
        [T5Native.NativeMethods]::CloseHandle($hFile) | Out-Null
    }
}

function Test-MatchesPattern {
    param(
        [string[]]$Patterns,
        [string[]]$Fields
    )
    if (-not $Patterns -or $Patterns.Count -eq 0) {
        return $false
    }
    foreach ($f in $Fields) {
        if ([string]::IsNullOrEmpty($f)) { continue }
        foreach ($p in $Patterns) {
            if ([string]::IsNullOrEmpty($p)) { continue }
            if ($f.IndexOf($p, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                return $true
            }
        }
    }
    return $false
}

# 1. OutputFolder check before reading anything else
if (Test-Path -LiteralPath $OutputFolder) {
    throw "OutputFolder already exists: $OutputFolder"
}
[System.IO.Directory]::CreateDirectory($OutputFolder) | Out-Null
$resolvedOut = [System.IO.Path]::GetFullPath($OutputFolder)

# 2. Inventory collection
$inventoryRows = New-Object System.Collections.Generic.List[string]
$inventoryRows.Add("relative_path`ttype`tbytes`tsha256`thard_links`tlink_or_junction`textra_streams`tnotes")

$stack = New-Object System.Collections.Generic.Stack[object]

foreach ($root in $InventoryRoots) {
    $rootFull = [System.IO.Path]::GetFullPath($root)
    $rootExt = ConvertTo-ExtendedPath -Path $rootFull
    $rootName = [System.IO.Path]::GetFileName($rootFull.TrimEnd('\','/'))
    if ([string]::IsNullOrEmpty($rootName)) { $rootName = $rootFull }

    $findData = New-Object T5Native.WIN32_FIND_DATAW
    $hFindRoot = [T5Native.NativeMethods]::FindFirstFileExW(
        $rootExt,
        [T5Native.NativeMethods]::FindExInfoStandard,
        [ref]$findData,
        [T5Native.NativeMethods]::FindExSearchNameMatch,
        [IntPtr]::Zero,
        0
    )
    if ($hFindRoot -eq [T5Native.NativeMethods]::INVALID_HANDLE_VALUE) {
        $errCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $row = @(
            (Sanitize-Field $rootName),
            'root_error',
            '',
            '',
            '',
            'UNKNOWN',
            '',
            (Sanitize-Field "FindFirstFileExW failed on root (Win32 error $errCode)")
        ) -join "`t"
        $inventoryRows.Add($row)
        continue
    }
    [T5Native.NativeMethods]::FindClose($hFindRoot) | Out-Null

    $rootAttr = $findData.dwFileAttributes
    $rootIsReparse = (($rootAttr -band [T5Native.NativeMethods]::FILE_ATTRIBUTE_REPARSE_POINT) -ne 0)
    $linkInfo = Get-LinkAndHardLinkInfo -ExtendedPath $rootExt -Attributes $rootAttr
    $streamInfo = Get-AlternateStreamsInfo -ExtendedPath $rootExt

    $streamSummaryParts = New-Object System.Collections.Generic.List[string]
    $notesParts = New-Object System.Collections.Generic.List[string]
    if ($linkInfo.Error) { $notesParts.Add($linkInfo.Error) }
    if ($streamInfo.Error) { $notesParts.Add($streamInfo.Error) }
    foreach ($s in $streamInfo.Streams) {
        $streamSummaryParts.Add("$($s.Name):$($s.Size):$($s.Sha256)")
        if ($s.Error) { $notesParts.Add("stream '$($s.Name)' error: $($s.Error)") }
    }

    $inventoryRows.Add((@(
        (Sanitize-Field $rootName),
        'folder',
        '',
        '',
        (Sanitize-Field $linkInfo.HardLinks),
        (Sanitize-Field $linkInfo.LinkStatus),
        (Sanitize-Field ($streamSummaryParts -join ';')),
        (Sanitize-Field ($notesParts -join ' | '))
    ) -join "`t"))

    if (-not $rootIsReparse) {
        $stack.Push([PSCustomObject]@{
            FullPath = $rootFull
            ExtPath  = $rootExt
            RelPath  = $rootName
        })
    }

    while ($stack.Count -gt 0) {
        $current = $stack.Pop()
        $searchSpec = $current.ExtPath.TrimEnd('\') + '\*'
        $entryData = New-Object T5Native.WIN32_FIND_DATAW
        $hSearch = [T5Native.NativeMethods]::FindFirstFileExW(
            $searchSpec,
            [T5Native.NativeMethods]::FindExInfoStandard,
            [ref]$entryData,
            [T5Native.NativeMethods]::FindExSearchNameMatch,
            [IntPtr]::Zero,
            0
        )
        if ($hSearch -eq [T5Native.NativeMethods]::INVALID_HANDLE_VALUE) {
            $errCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $inventoryRows.Add((@(
                (Sanitize-Field $current.RelPath),
                'folder_read_error',
                '',
                '',
                '',
                'UNKNOWN',
                '',
                (Sanitize-Field "Enumerate failed (Win32 error $errCode)")
            ) -join "`t"))
            continue
        }

        try {
            do {
                $name = $entryData.cFileName
                if ($name -eq '.' -or $name -eq '..') { continue }

                $childRel = $current.RelPath + '\' + $name
                $childFull = $current.FullPath.TrimEnd('\') + '\' + $name
                $childExt = ConvertTo-ExtendedPath -Path $childFull

                $attr = $entryData.dwFileAttributes
                $isDir = (($attr -band [T5Native.NativeMethods]::FILE_ATTRIBUTE_DIRECTORY) -ne 0)
                $isReparse = (($attr -band [T5Native.NativeMethods]::FILE_ATTRIBUTE_REPARSE_POINT) -ne 0)

                $childLink = Get-LinkAndHardLinkInfo -ExtendedPath $childExt -Attributes $attr
                $childStreams = Get-AlternateStreamsInfo -ExtendedPath $childExt

                $childStreamList = New-Object System.Collections.Generic.List[string]
                $childNotes = New-Object System.Collections.Generic.List[string]
                if ($childLink.Error) { $childNotes.Add($childLink.Error) }
                if ($childStreams.Error) { $childNotes.Add($childStreams.Error) }
                foreach ($s in $childStreams.Streams) {
                    $childStreamList.Add("$($s.Name):$($s.Size):$($s.Sha256)")
                    if ($s.Error) { $childNotes.Add("stream '$($s.Name)' error: $($s.Error)") }
                }

                if ($isDir) {
                    $inventoryRows.Add((@(
                        (Sanitize-Field $childRel),
                        'folder',
                        '',
                        '',
                        (Sanitize-Field $childLink.HardLinks),
                        (Sanitize-Field $childLink.LinkStatus),
                        (Sanitize-Field ($childStreamList -join ';')),
                        (Sanitize-Field ($childNotes -join ' | '))
                    ) -join "`t"))

                    if (-not $isReparse) {
                        $stack.Push([PSCustomObject]@{
                            FullPath = $childFull
                            ExtPath  = $childExt
                            RelPath  = $childRel
                        })
                    }
                }
                else {
                    $sizeBytes = ([uint64]$entryData.nFileSizeHigh -shl 32) -bor [uint64]$entryData.nFileSizeLow
                    $shaHex = ''
                    if (-not $isReparse) {
                        try {
                            $shaHex = Get-FileSha256Hex -TargetPath $childExt
                        }
                        catch {
                            $childNotes.Add("SHA-256 read error: $($_.Exception.Message)")
                        }
                    }
                    else {
                        $childNotes.Add('Reparse point / link not followed for content hash')
                    }

                    $inventoryRows.Add((@(
                        (Sanitize-Field $childRel),
                        'file',
                        [string]$sizeBytes,
                        (Sanitize-Field $shaHex),
                        (Sanitize-Field $childLink.HardLinks),
                        (Sanitize-Field $childLink.LinkStatus),
                        (Sanitize-Field ($childStreamList -join ';')),
                        (Sanitize-Field ($childNotes -join ' | '))
                    ) -join "`t"))
                }
            } while ([T5Native.NativeMethods]::FindNextFileW($hSearch, [ref]$entryData))
        }
        finally {
            [T5Native.NativeMethods]::FindClose($hSearch) | Out-Null
        }
    }
}

$invHeader = $inventoryRows[0]
[string[]]$invBody = @($inventoryRows | Select-Object -Skip 1)
[Array]::Sort($invBody, [Comparison[string]]{ param($a, $b) [System.StringComparer]::Ordinal.Compare((($a -split "`t")[0]), (($b -split "`t")[0])) })
$sortedInventory = @($invHeader) + @($invBody)
$inventoryPath = Join-Path $resolvedOut 'inventory.tsv'
Write-Utf8LfFile -FilePath $inventoryPath -Lines $sortedInventory

# 3. Absent path existence check (never open or list inside)
$absentRows = New-Object System.Collections.Generic.List[string]
$absentRows.Add("path`tstatus`tnotes")

foreach ($ap in $AbsentPaths) {
    $apNormalized = $ap
    if ($apNormalized.Length -gt 3) {
        $apNormalized = $apNormalized.TrimEnd('\', '/')
    }
    $apExt = ConvertTo-ExtendedPath -Path $apNormalized
    $fd = New-Object T5Native.WIN32_FIND_DATAW
    $hAp = [T5Native.NativeMethods]::FindFirstFileExW(
        $apExt,
        [T5Native.NativeMethods]::FindExInfoStandard,
        [ref]$fd,
        [T5Native.NativeMethods]::FindExSearchNameMatch,
        [IntPtr]::Zero,
        0
    )
    if ($hAp -ne [T5Native.NativeMethods]::INVALID_HANDLE_VALUE) {
        [T5Native.NativeMethods]::FindClose($hAp) | Out-Null
        $absentRows.Add((@((Sanitize-Field $ap), 'EXISTS', '') -join "`t"))
    }
    else {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($err -eq 2 -or $err -eq 3) {
            $absentRows.Add((@((Sanitize-Field $ap), 'ABSENT', '') -join "`t"))
        }
        else {
            $absentRows.Add((@((Sanitize-Field $ap), 'UNKNOWN', "Win32 error $err") -join "`t"))
        }
    }
}

$absHeader = $absentRows[0]
[string[]]$absBody = @($absentRows | Select-Object -Skip 1)
[Array]::Sort($absBody, [Comparison[string]]{ param($a, $b) [System.StringComparer]::Ordinal.Compare((($a -split "`t")[0]), (($b -split "`t")[0])) })
$sortedAbsent = @($absHeader) + @($absBody)
$absentPath = Join-Path $resolvedOut 'absent.tsv'
Write-Utf8LfFile -FilePath $absentPath -Lines $sortedAbsent

# 4. Running-program check (processes, listening ports, services, scheduled tasks)
$runningRows = New-Object System.Collections.Generic.List[string]
$runningRows.Add("kind`tname`tid_or_port`tpath_or_command`tdetails`tnotes")

# 4a. Processes
$procTotal = 0
try {
    $procs = Get-CimInstance -ClassName Win32_Process -ErrorAction Stop
    foreach ($p in $procs) {
        $procTotal++
        $pName = [string]$p.Name
        $pExe = [string]$p.ExecutablePath
        $pCmd = [string]$p.CommandLine
        if (Test-MatchesPattern -Patterns $NamePatterns -Fields @($pName, $pExe, $pCmd)) {
            $runningRows.Add((@(
                'process',
                (Sanitize-Field $pName),
                (Sanitize-Field ([string]$p.ProcessId)),
                (Sanitize-Field $(if ($pCmd) { $pCmd } else { $pExe })),
                (Sanitize-Field "ExecutablePath=$pExe"),
                ''
            ) -join "`t"))
        }
    }
}
catch {
    $runningRows.Add((@('process_scan_error', '', '', '', '', (Sanitize-Field $_.Exception.Message)) -join "`t"))
}

# 4b. Listening ports
$portTotal = 0
$procNameById = @{}
try {
    foreach ($gp in (Get-Process -ErrorAction SilentlyContinue)) {
        $procNameById[[int]$gp.Id] = [string]$gp.ProcessName
    }
}
catch { }

try {
    $listeners = Get-NetTCPConnection -State Listen -ErrorAction Stop
    foreach ($l in $listeners) {
        $portTotal++
        $owningId = [int]$l.OwningProcess
        $ownerName = if ($procNameById.ContainsKey($owningId)) { $procNameById[$owningId] } else { '' }
        $endpointStr = "$($l.LocalAddress):$($l.LocalPort)"
        if (Test-MatchesPattern -Patterns $NamePatterns -Fields @($ownerName, $endpointStr, [string]$l.LocalPort, [string]$owningId)) {
            $runningRows.Add((@(
                'listening_port',
                (Sanitize-Field $ownerName),
                (Sanitize-Field $endpointStr),
                (Sanitize-Field "OwningProcess=$owningId"),
                (Sanitize-Field "State=$($l.State)"),
                ''
            ) -join "`t"))
        }
    }
}
catch {
    $runningRows.Add((@('listening_port_scan_error', '', '', '', '', (Sanitize-Field $_.Exception.Message)) -join "`t"))
}

# 4c. Services
$svcTotal = 0
try {
    $svcs = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop
    foreach ($s in $svcs) {
        $svcTotal++
        $sName = [string]$s.Name
        $sDisp = [string]$s.DisplayName
        $sPath = [string]$s.PathName
        if (Test-MatchesPattern -Patterns $NamePatterns -Fields @($sName, $sDisp, $sPath)) {
            $runningRows.Add((@(
                'service',
                (Sanitize-Field $sName),
                (Sanitize-Field ([string]$s.State)),
                (Sanitize-Field $sPath),
                (Sanitize-Field "DisplayName=$sDisp;StartMode=$($s.StartMode)"),
                ''
            ) -join "`t"))
        }
    }
}
catch {
    $runningRows.Add((@('service_scan_error', '', '', '', '', (Sanitize-Field $_.Exception.Message)) -join "`t"))
}

# 4d. Scheduled tasks (record unreadable tasks without failing)
$taskTotal = 0
try {
    $tasks = Get-ScheduledTask -ErrorAction Stop
    foreach ($t in $tasks) {
        $taskTotal++
        $tFull = ($t.TaskPath + $t.TaskName)
        $tActions = ''
        $tNote = ''
        try {
            $actionList = New-Object System.Collections.Generic.List[string]
            foreach ($act in @($t.Actions)) {
                if ($act.PSObject.Properties['Execute']) {
                    $exec = [string]$act.Execute
                    $actArgs = if ($act.PSObject.Properties['Arguments']) { [string]$act.Arguments } else { '' }
                    $actionList.Add(("$exec $actArgs").Trim())
                }
                else {
                    $actType = if ($act.PSObject.Properties['ActionType']) { [string]$act.ActionType } else { $act.GetType().Name }
                    $clsId = if ($act.PSObject.Properties['ClassId']) { [string]$act.ClassId } else { '' }
                    if ($clsId) {
                        $actionList.Add("$actType ClassId=$clsId")
                    }
                    else {
                        $actionList.Add($actType)
                    }
                }
            }
            $tActions = $actionList -join ' || '
        }
        catch {
            $tNote = "Unreadable task actions: $($_.Exception.Message)"
        }

        if ($tNote -or (Test-MatchesPattern -Patterns $NamePatterns -Fields @($t.TaskName, $t.TaskPath, $tFull, $tActions))) {
            $runningRows.Add((@(
                'scheduled_task',
                (Sanitize-Field $tFull),
                (Sanitize-Field ([string]$t.State)),
                (Sanitize-Field $tActions),
                (Sanitize-Field "Author=$($t.Author)"),
                (Sanitize-Field $tNote)
            ) -join "`t"))
        }
    }
}
catch {
    $runningRows.Add((@('scheduled_task_scan_error', '', '', '', '', (Sanitize-Field $_.Exception.Message)) -join "`t"))
}

$runAcct = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$runElev = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$runningRows.Add((@(
    'summary_total',
    'inspected_counts',
    '',
    '',
    "processes=$procTotal;listening_ports=$portTotal;services=$svcTotal;scheduled_tasks=$taskTotal;account=$runAcct;elevated=$runElev",
    ''
) -join "`t"))

$runHeader = $runningRows[0]
[string[]]$runBody = @($runningRows | Select-Object -Skip 1)
[Array]::Sort($runBody, [Comparison[string]]{
    param($a, $b)
    $pa = $a -split "`t"
    $pb = $b -split "`t"
    $c1 = [System.StringComparer]::Ordinal.Compare($pa[1], $pb[1])
    if ($c1 -ne 0) { return $c1 }
    return [System.StringComparer]::Ordinal.Compare($pa[0], $pb[0])
})
$sortedRunning = @($runHeader) + @($runBody)
$runningPath = Join-Path $resolvedOut 'running.tsv'
Write-Utf8LfFile -FilePath $runningPath -Lines $sortedRunning

# 5. Manifest with size and SHA-256 of each output file
[string[]]$outFiles = @('inventory.tsv', 'absent.tsv', 'running.tsv')
[Array]::Sort($outFiles, [Comparison[string]]{ param($a, $b) [System.StringComparer]::Ordinal.Compare($a, $b) })
$manifestLines = New-Object System.Collections.Generic.List[string]
$manifestLines.Add("file`tbytes`tsha256")

foreach ($fname in $outFiles) {
    $fpath = Join-Path $resolvedOut $fname
    $finfo = [System.IO.FileInfo]::new($fpath)
    $fhash = Get-FileSha256Hex -TargetPath $fpath
    $manifestLines.Add("$fname`t$($finfo.Length)`t$fhash")
}

$manifestPath = Join-Path $resolvedOut 'manifest.tsv'
Write-Utf8LfFile -FilePath $manifestPath -Lines $manifestLines
$manifestSha = Get-FileSha256Hex -TargetPath $manifestPath

Write-Output "T5_COLLECT_DONE;manifest SHA256=$manifestSha"
