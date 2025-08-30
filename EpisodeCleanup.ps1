<#
EpisodeCleanup.ps1

Scans a TV library structured mostly to Plex standards. In each leaf season
folder, it parses filenames to identify Season/Episode, detects duplicates,
offers interactive deletion (move to Drive:\Deletions\...), checks that each
episode resides in the correct season folder, and proposes moves. Also finds
empty leaf folders (only images/nfo/url/txt) and proposes moving entire folders
to Deletions when appropriate. Supports dry-run and logs actions.

Usage examples:
  .\EpisodeCleanup.ps1 -RootPath "R:\TV Shows" -DryRun
  .\EpisodeCleanup.ps1 -RootPath "." 

#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$RootPath,

  [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -------------------------- Config & Globals --------------------------

# Known video extensions
$VideoExtensions = @(
  '.mkv','.mp4','.avi','.mov','.m4v','.wmv','.ts','.m2ts','.mpg','.mpeg','.flv','.webm'
)

# Folders Plex uses for extras that we should ignore when scanning
$ExtrasFolderNames = @(
  'extras','extra','featurettes','behind the scenes','deleted scenes','interviews',
  'scenes','shorts','trailers','other','others','samples','sample','bonus',
  'bonus features','.actors','clips'
)

# File types that make a season folder considered "empty/leaf-only"
$AllowedLeafOnlyExtensions = @('.jpg','.jpeg','.png','.webp','.tbn','.nfo','.url','.txt','.gif','.bmp')

# Log file path (as requested; confirm spelling)
$LogDir = 'C:\istools'
$LogFile = Join-Path $LogDir ("EpisodeCleanup-{0}.log" -f (Get-Date -Format 'yyyyMMdd'))

# -------------------------- Helpers --------------------------

function Initialize-Log {
  if (-not (Test-Path -LiteralPath $LogDir)) {
    try { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null } catch {}
  }
}

function Write-Log {
  param(
    [Parameter(Mandatory=$true)][string]$Message,
    [ValidateSet('Info','Warn','Error')][string]$Level = 'Info',
    [switch]$HostOnly
  )
  $prefix = "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))] [$Level]"
  $line = "$prefix $Message"
  Write-Host $line
  if (-not $HostOnly) {
    try { Add-Content -Path $LogFile -Value $line } catch {}
  }
}

function Test-IsExtrasFolderName {
  param([string]$Name)
  return $ExtrasFolderNames -contains $Name.ToLowerInvariant()
}

function Test-IsVideoFile {
  param([IO.FileInfo]$File)
  return $VideoExtensions -contains $File.Extension.ToLowerInvariant()
}

function Parse-SeasonFromFolderName {
  param([string]$FolderName)
  $n = $FolderName.Trim()
  if ($n -match '^(?i)specials?$') { return 0 }
  # Common patterns: Season 1, Season 01, S01, S1
  $m = [regex]::Match($n,'(?i)\bseason\s*(\d{1,2})\b')
  if ($m.Success) { return [int]$m.Groups[1].Value }
  $m = [regex]::Match($n,'(?i)\bs\s*(\d{1,2})\b')
  if ($m.Success) { return [int]$m.Groups[1].Value }
  return $null
}

function Parse-SeasonEpisodeFromFileName {
  param([string]$FileName)
  $name = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
  # Most common: S01E02, s01e02
  $m = [regex]::Match($name,'(?i)\bS(?<s>\d{1,2})\s*E(?<e>\d{1,3})\b')
  if ($m.Success) {
    return [pscustomobject]@{ Season = [int]$m.Groups['s'].Value; Episode=[int]$m.Groups['e'].Value }
  }
  # Alternative: 1x02, 01x02
  $m = [regex]::Match($name,'(?i)\b(?<s>\d{1,2})\s*x\s*(?<e>\d{1,3})\b')
  if ($m.Success) {
    return [pscustomobject]@{ Season = [int]$m.Groups['s'].Value; Episode=[int]$m.Groups['e'].Value }
  }
  # Very loose: Season 1 Episode 2
  $m = [regex]::Match($name,'(?i)season\s*(?<s>\d{1,2}).*episode\s*(?<e>\d{1,3})')
  if ($m.Success) {
    return [pscustomobject]@{ Season = [int]$m.Groups['s'].Value; Episode=[int]$m.Groups['e'].Value }
  }
  return $null
}

function Get-ShowRootForSeasonFolder {
  param([IO.DirectoryInfo]$SeasonDir)
  return $SeasonDir.Parent
}

function Get-ExpectedSeasonFolder {
  param(
    [IO.DirectoryInfo]$ShowRoot,
    [int]$SeasonNumber
  )
  if ($SeasonNumber -eq 0) {
    # Prefer "Specials" if it exists; else Season 00
    $specials = Get-ChildItem -LiteralPath $ShowRoot.FullName -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(?i)specials?$' }
    if ($specials) { return $specials[0] }
    $s0 = Join-Path $ShowRoot.FullName 'Season 00'
    if (-not (Test-Path -LiteralPath $s0)) { New-Item -ItemType Directory -Path $s0 -Force | Out-Null }
    return (Get-Item -LiteralPath $s0)
  }
  $seasonLabel = ('Season {0:D2}' -f $SeasonNumber)
  $target = Join-Path $ShowRoot.FullName $seasonLabel
  if (-not (Test-Path -LiteralPath $target)) { New-Item -ItemType Directory -Path $target -Force | Out-Null }
  return (Get-Item -LiteralPath $target)
}

function Get-DriveRoot {
  param([string]$FullPath)
  return [System.IO.Path]::GetPathRoot($FullPath)
}

function Get-DeletionsPathForItem {
  param([string]$FullPath)
  $root = Get-DriveRoot -FullPath $FullPath  # e.g. R:\
  $afterRoot = $FullPath.Substring($root.Length)
  $destRoot = Join-Path $root 'Deletions'
  return (Join-Path $destRoot $afterRoot)
}

function Ensure-ParentDirectory {
  param([string]$TargetPath)
  $parent = Split-Path -LiteralPath $TargetPath -Parent
  if (-not (Test-Path -LiteralPath $parent)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
  }
}

function Format-Size {
  param([long]$Bytes)
  if ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes / 1GB)) }
  if ($Bytes -ge 1MB) { return ('{0:N2} MB' -f ($Bytes / 1MB)) }
  if ($Bytes -ge 1KB) { return ('{0:N2} KB' -f ($Bytes / 1KB)) }
  return ("$Bytes B")
}

function Get-MediaInfoSummary {
  param([string]$FilePath)
  # mediainfo --Output=JSON file
  try {
    $json = & mediainfo --Output=JSON --Full "$FilePath"
  } catch {
    return $null
  }
  if (-not $json) { return $null }
  try {
    $obj = $json | ConvertFrom-Json -ErrorAction Stop
  } catch {
    return $null
  }
  $tracks = @($obj.media.track)
  $gen = $tracks | Where-Object { $_.'@type' -eq 'General' } | Select-Object -First 1
  $vid = $tracks | Where-Object { $_.'@type' -eq 'Video' } | Select-Object -First 1
  $aud = $tracks | Where-Object { $_.'@type' -eq 'Audio' } | Select-Object -First 1

  $width = $vid.Width
  $height = $vid.Height
  if (-not $width -and $vid.'DisplayWidth') { $width = $vid.'DisplayWidth' }
  if (-not $height -and $vid.'DisplayHeight') { $height = $vid.'DisplayHeight' }
  $res = $null
  if ($width -and $height) { $res = "${width}x${height}" }

  $vcodec = $vid.Format
  if (-not $vcodec -and $vid.CodecID) { $vcodec = $vid.CodecID }
  $acodec = $aud.Format
  if (-not $acodec -and $aud.CodecID) { $acodec = $aud.CodecID }
  $channels = $aud.'Channel(s)'
  if (-not $channels) { $channels = $aud.'Channel_s_' }
  if (-not $channels -and $aud.Channels) { $channels = $aud.Channels }

  return [pscustomobject]@{
    Resolution = $res
    VideoCodec = $vcodec
    AudioCodec = $acodec
    AudioChannels = $channels
  }
}

function Confirm-YesNo {
  param([string]$Prompt, [switch]$DefaultYes)
  $suffix = if ($DefaultYes) { '[Y/n]' } else { '[y/N]' }
  while ($true) {
    $resp = Read-Host "$Prompt $suffix"
    if ([string]::IsNullOrWhiteSpace($resp)) { return [bool]$DefaultYes }
    switch ($resp.ToLowerInvariant()) {
      'y' { return $true }
      'yes' { return $true }
      'n' { return $false }
      'no' { return $false }
    }
  }
}

# -------------------------- Scan Phase --------------------------

Initialize-Log

if (-not (Test-Path -LiteralPath $RootPath)) {
  throw "RootPath '$RootPath' does not exist."
}

$RootFull = (Get-Item -LiteralPath $RootPath).FullName

Write-Log -Message "Starting EpisodeCleanup against '$RootFull' DryRun=$DryRun" -Level Info
Write-Host "Collecting directories and files..."

# Gather all directories under root (ensure array, even if empty)
$allDirs = @(Get-ChildItem -LiteralPath $RootFull -Directory -Recurse -Force)

$leafSeasonDirs = New-Object System.Collections.Generic.List[object]

$i = 0
$totalDirs = $allDirs.Count
foreach ($dir in $allDirs) {
  $i++
  $pct = [int](($i / [math]::Max(1,$totalDirs)) * 100)
  Write-Progress -Activity 'Scanning folders' -Status $dir.FullName -PercentComplete $pct

  $subDirs = Get-ChildItem -LiteralPath $dir.FullName -Directory -Force -ErrorAction SilentlyContinue
  if (-not $subDirs -or ($subDirs | Where-Object { -not (Test-IsExtrasFolderName -Name $_.Name) }).Count -eq 0) {
    # No subdirs or only extras subdirs -> treat as leaf (season) folder
    $leafSeasonDirs.Add($dir)
  }
}
Write-Progress -Activity 'Scanning folders' -Completed

Write-Log -Message ("Leaf season-like folders found: {0}" -f $leafSeasonDirs.Count) -Level Info

# -------------------------- Analyze Phase --------------------------

$duplicateGroups = New-Object System.Collections.Generic.List[object]
$misplacedEpisodes = New-Object System.Collections.Generic.List[object]
$emptyLeafDirs = New-Object System.Collections.Generic.List[object]

$j = 0
foreach ($seasonDir in $leafSeasonDirs) {
  $j++
  $pct = [int](($j / [math]::Max(1,$leafSeasonDirs.Count)) * 100)
  Write-Progress -Activity 'Analyzing season folders' -Status $seasonDir.FullName -PercentComplete $pct

  $folderSeason = Parse-SeasonFromFolderName -FolderName $seasonDir.Name
  $showRoot = Get-ShowRootForSeasonFolder -SeasonDir $seasonDir

  $files = Get-ChildItem -LiteralPath $seasonDir.FullName -File -Force -ErrorAction SilentlyContinue
  $videoFiles = $files | Where-Object { Test-IsVideoFile -File $_ }

  # Detect duplicates per episode within this folder
  $byEpisode = @{}
  foreach ($vf in $videoFiles) {
    $info = Parse-SeasonEpisodeFromFileName -FileName $vf.Name
    if ($null -eq $info) { continue }
    $key = ('S{0:D2}E{1:D2}' -f $info.Season, $info.Episode)
    if (-not $byEpisode.ContainsKey($key)) { $byEpisode[$key] = New-Object System.Collections.Generic.List[object] }
    $byEpisode[$key].Add($vf)

    # Misplacement: folder season vs parsed season
    if ($folderSeason -ne $null -and $info.Season -ne $folderSeason) {
      $expected = Get-ExpectedSeasonFolder -ShowRoot $showRoot -SeasonNumber $info.Season
      $misplacedEpisodes.Add([pscustomobject]@{
        File = $vf
        FromFolder = $seasonDir
        ExpectedFolder = $expected
        EpisodeKey = $key
      })
    }
  }
  foreach ($kv in $byEpisode.GetEnumerator()) {
    if ($kv.Value.Count -gt 1) {
      $duplicateGroups.Add([pscustomobject]@{
        Folder = $seasonDir
        EpisodeKey = $kv.Key
        Files = @($kv.Value)
      })
    }
  }

  # Empty leaf folder (no video files, and only allowed leaf-only extensions present)
  if ($videoFiles.Count -eq 0) {
    $nonAllowed = @($files | Where-Object { $AllowedLeafOnlyExtensions -notcontains $_.Extension.ToLowerInvariant() })
    if ($nonAllowed.Count -eq 0) {
      $emptyLeafDirs.Add($seasonDir)
    }
  }
}
Write-Progress -Activity 'Analyzing season folders' -Completed

Write-Log -Message ("Duplicate groups: {0}; Misplaced episodes: {1}; Empty leaf dirs: {2}" -f $duplicateGroups.Count, $misplacedEpisodes.Count, $emptyLeafDirs.Count) -Level Info

# Determine parent folders where all non-extras children are empty and can be moved entirely
$parentsToDelete = New-Object System.Collections.Generic.HashSet[string]
if ($emptyLeafDirs.Count -gt 0) {
  $byParent = $emptyLeafDirs | Group-Object { $_.Parent.FullName }
  foreach ($grp in $byParent) {
    $parentPath = $grp.Name
    $allChildren = Get-ChildItem -LiteralPath $parentPath -Directory -Force -ErrorAction SilentlyContinue | Where-Object { -not (Test-IsExtrasFolderName -Name $_.Name) }
    if (-not $allChildren -or $allChildren.Count -eq 0) { continue }
    $allEmpty = $true
    foreach ($child in $allChildren) {
      if (-not ($emptyLeafDirs | Where-Object { $_.FullName -eq $child.FullName })) { $allEmpty = $false; break }
    }
    if ($allEmpty -or $allChildren.Count -eq 1) {
      [void]$parentsToDelete.Add($parentPath)
    }
  }
}

# Remove children from deletion list if parent is being deleted
$finalFoldersToDelete = New-Object System.Collections.Generic.HashSet[string]
foreach ($leaf in $emptyLeafDirs) {
  if (-not ($parentsToDelete.Contains($leaf.Parent.FullName))) {
    [void]$finalFoldersToDelete.Add($leaf.FullName)
  }
}
foreach ($p in $parentsToDelete) { [void]$finalFoldersToDelete.Add($p) }

# -------------------------- Interactive Phase --------------------------

Write-Host ''
Write-Host 'Analysis complete.'
Write-Host ("- Duplicate episodes: {0}" -f $duplicateGroups.Count)
Write-Host ("- Misplaced episodes: {0}" -f $misplacedEpisodes.Count)
Write-Host ("- Folders to consider for deletion: {0}" -f $finalFoldersToDelete.Count)
Write-Host ''

# 1) Handle duplicates: present mediainfo and let user select one to delete (move to Deletions)
if ($duplicateGroups.Count -gt 0) {
  Write-Host 'Duplicate episodes detected. Review each group and choose a file to delete.'
  $gIndex = 0
  foreach ($group in $duplicateGroups) {
    $gIndex++
    Write-Host ''
    Write-Host ("[{0}/{1}] {2} - {3}" -f $gIndex, $duplicateGroups.Count, $group.Folder.FullName, $group.EpisodeKey)
    $choices = @()
    $idx = 0
    foreach ($f in $group.Files | Sort-Object Length) {
      $idx++
      $mi = Get-MediaInfoSummary -FilePath $f.FullName
      $date = $f.LastWriteTime.ToString('yyyy-MM-dd')
      $size = Format-Size -Bytes $f.Length
      $res = if ($mi) { $mi.Resolution } else { $null }
      $vcodec = if ($mi) { $mi.VideoCodec } else { $null }
      $acodec = if ($mi) { $mi.AudioCodec } else { $null }
      $ach = if ($mi) { $mi.AudioChannels } else { $null }
      $summary = "[$idx] $($f.Name) | $date | $size"
      if ($res) { $summary += " | $res" }
      if ($vcodec) { $summary += " | v:$vcodec" }
      if ($acodec) { $summary += " | a:$acodec" }
      if ($ach) { $summary += " ($ach)" }
      Write-Host $summary
      $choices += ,$f
    }
    Write-Host "[0] Keep all (do not delete)"
    $sel = Read-Host 'Select a number to delete, or 0 to keep all'
    if ([int]::TryParse($sel, [ref]([int]$null))) {
      $n = [int]$sel
      if ($n -gt 0 -and $n -le $choices.Count) {
        $toDelete = $choices[$n-1]
        $dest = Get-DeletionsPathForItem -FullPath $toDelete.FullName
        Ensure-ParentDirectory -TargetPath $dest
        if ($DryRun) {
          Write-Log -Message ("DRY RUN: Move duplicate to Deletions: '{0}' -> '{1}'" -f $toDelete.FullName, $dest) -Level Info
        } else {
          Write-Log -Message ("Moving duplicate to Deletions: '{0}' -> '{1}'" -f $toDelete.FullName, $dest) -Level Info
          Move-Item -LiteralPath $toDelete.FullName -Destination $dest -Force
        }
      } else {
        Write-Host 'Keeping all in this group.'
      }
    } else {
      Write-Host 'Invalid input. Keeping all in this group.'
    }
  }
}

# 2) Handle misplaced episodes: confirm before moving to correct season folder
if ($misplacedEpisodes.Count -gt 0) {
  Write-Host ''
  Write-Host 'Misplaced episodes detected. You can move them to the correct season folders.'
  $applyAll = $false
  foreach ($m in $misplacedEpisodes) {
    $src = $m.File.FullName
    $dst = Join-Path $m.ExpectedFolder.FullName $m.File.Name
    Write-Host ''
    Write-Host ("{0} -> {1}" -f $src, $m.ExpectedFolder.FullName)
    $doMove = $applyAll -or (Confirm-YesNo -Prompt 'Move this file?' -DefaultYes)
    if ($doMove) {
      if ($DryRun) {
        Write-Log -Message ("DRY RUN: Move misplaced: '{0}' -> '{1}'" -f $src, $dst) -Level Info
      } else {
        Write-Log -Message ("Moving misplaced: '{0}' -> '{1}'" -f $src, $dst) -Level Info
        Ensure-ParentDirectory -TargetPath $dst
        Move-Item -LiteralPath $src -Destination $dst -Force
      }
      if (-not $applyAll) {
        $applyAll = Confirm-YesNo -Prompt 'Apply same decision (move) to all remaining misplaced episodes?' -DefaultYes
      }
    } else {
      # Ask if user wants to skip all remaining
      $skipRest = Confirm-YesNo -Prompt 'Skip all remaining misplaced episodes?' -DefaultYes:$false
      if ($skipRest) { break }
    }
  }
}

# 3) Handle folders to delete (move to Deletions with full path preserved)
if ($finalFoldersToDelete.Count -gt 0) {
  Write-Host ''
  Write-Host 'Folders containing only images/nfo/url/txt detected.'
  $list = $finalFoldersToDelete.ToArray() | Sort-Object
  $k = 0
  foreach ($folderPath in $list) {
    $k++
    Write-Host ("[{0}/{1}] {2}" -f $k, $list.Count, $folderPath)
    $ok = Confirm-YesNo -Prompt 'Move this folder to Deletions?' -DefaultYes:$false
    if ($ok) {
      $dest = Get-DeletionsPathForItem -FullPath $folderPath
      Ensure-ParentDirectory -TargetPath $dest
      if ($DryRun) {
        Write-Log -Message ("DRY RUN: Move folder to Deletions: '{0}' -> '{1}'" -f $folderPath, $dest) -Level Info
      } else {
        Write-Log -Message ("Moving folder to Deletions: '{0}' -> '{1}'" -f $folderPath, $dest) -Level Info
        Move-Item -LiteralPath $folderPath -Destination $dest -Force
      }
    }
  }
}

Write-Host ''
Write-Log -Message 'EpisodeCleanup complete.' -Level Info

Write-Host 'Note: Log file written to:'
Write-Host "  $LogFile"
Write-Host ''
Write-Host 'If you want to adjust the extras-folder list or parsing patterns, let me know.'
