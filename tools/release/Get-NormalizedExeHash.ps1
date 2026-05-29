param(
  [Parameter(Mandatory = $true)]
  [string] $Path,

  [string] $EmbeddedHash = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Zero-Range {
  param([byte[]] $Bytes, [int] $Offset, [int] $Length)
  if ($Offset -ge 0 -and $Length -ge 0 -and ($Offset + $Length) -le $Bytes.Length) {
    for ($i = 0; $i -lt $Length; $i++) {
      $Bytes[$Offset + $i] = 0
    }
  }
}

function Read-U16 {
  param([byte[]] $Bytes, [int] $Offset)
  [BitConverter]::ToUInt16($Bytes, $Offset)
}

function Read-U32 {
  param([byte[]] $Bytes, [int] $Offset)
  [BitConverter]::ToUInt32($Bytes, $Offset)
}

function Normalize-EmbeddedHash {
  param([byte[]] $Bytes, [string] $Hash)
  if ($Hash.Length -ne 64) {
    return
  }
  $needle = [Text.Encoding]::ASCII.GetBytes($Hash)
  $zero = [Text.Encoding]::ASCII.GetBytes(("0" * 64))
  for ($i = 0; $i -le $Bytes.Length - $needle.Length; $i++) {
    $matched = $true
    for ($j = 0; $j -lt $needle.Length; $j++) {
      if ($Bytes[$i + $j] -ne $needle[$j]) {
        $matched = $false
        break
      }
    }
    if ($matched) {
      [Array]::Copy($zero, 0, $Bytes, $i, $zero.Length)
    }
  }
}

function Normalize-CodeView {
  param([byte[]] $Bytes)
  foreach ($signature in @("RSDS", "NB10")) {
    $needle = [Text.Encoding]::ASCII.GetBytes($signature)
    $offset = 0
    while ($offset -le $Bytes.Length - $needle.Length) {
      $found = -1
      for ($i = $offset; $i -le $Bytes.Length - $needle.Length; $i++) {
        $matched = $true
        for ($j = 0; $j -lt $needle.Length; $j++) {
          if ($Bytes[$i + $j] -ne $needle[$j]) {
            $matched = $false
            break
          }
        }
        if ($matched) {
          $found = $i
          break
        }
      }
      if ($found -lt 0) {
        break
      }
      $end = [Math]::Min($found + 512, $Bytes.Length)
      for ($i = $found; $i -lt $end; $i++) {
        if ($Bytes[$i] -eq 0) {
          $end = $i + 1
          break
        }
      }
      Zero-Range -Bytes $Bytes -Offset $found -Length ($end - $found)
      $offset = $end
    }
  }
}

function Normalize-PeMutableFields {
  param([byte[]] $Bytes)
  if ($Bytes.Length -lt 0x40 -or $Bytes[0] -ne 0x4d -or $Bytes[1] -ne 0x5a) {
    return
  }
  $pe = [int](Read-U32 -Bytes $Bytes -Offset 0x3c)
  if (($pe + 0x18) -gt $Bytes.Length -or $Bytes[$pe] -ne 0x50 -or $Bytes[$pe + 1] -ne 0x45) {
    return
  }
  $fileHeader = $pe + 4
  $sectionCount = [int](Read-U16 -Bytes $Bytes -Offset ($fileHeader + 2))
  $optionalSize = [int](Read-U16 -Bytes $Bytes -Offset ($fileHeader + 16))
  $optionalHeader = $fileHeader + 20
  if (($optionalHeader + $optionalSize) -gt $Bytes.Length) {
    return
  }

  Zero-Range -Bytes $Bytes -Offset ($fileHeader + 4) -Length 4
  Zero-Range -Bytes $Bytes -Offset ($optionalHeader + 64) -Length 4

  $magic = Read-U16 -Bytes $Bytes -Offset $optionalHeader
  if ($magic -eq 0x10b) {
    $directory = $optionalHeader + 96
  } elseif ($magic -eq 0x20b) {
    $directory = $optionalHeader + 112
  } else {
    return
  }
  if (($directory + 16 * 8) -gt ($optionalHeader + $optionalSize)) {
    return
  }

  $debugRva = Read-U32 -Bytes $Bytes -Offset ($directory + 6 * 8)
  $debugSize = Read-U32 -Bytes $Bytes -Offset ($directory + 6 * 8 + 4)
  Zero-Range -Bytes $Bytes -Offset ($directory + 4 * 8) -Length 8
  Zero-Range -Bytes $Bytes -Offset ($directory + 6 * 8) -Length 8

  $sectionTable = $optionalHeader + $optionalSize
  for ($index = 0; $index -lt $sectionCount; $index++) {
    $section = $sectionTable + $index * 40
    if (($section + 40) -gt $Bytes.Length) {
      break
    }
    $virtualSize = Read-U32 -Bytes $Bytes -Offset ($section + 8)
    $virtualAddress = Read-U32 -Bytes $Bytes -Offset ($section + 12)
    $rawSize = Read-U32 -Bytes $Bytes -Offset ($section + 16)
    $rawPointer = Read-U32 -Bytes $Bytes -Offset ($section + 20)
    $span = [Math]::Max($virtualSize, $rawSize)
    if ($debugRva -ne 0 -and $debugSize -ne 0 -and $debugRva -ge $virtualAddress -and $debugRva -lt ($virtualAddress + $span)) {
      Zero-Range -Bytes $Bytes -Offset ([int]($rawPointer + $debugRva - $virtualAddress)) -Length ([int]$debugSize)
      break
    }
  }
}

$bytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Path))
Normalize-EmbeddedHash -Bytes $bytes -Hash $EmbeddedHash
Normalize-PeMutableFields -Bytes $bytes
Normalize-CodeView -Bytes $bytes
$sha = [Security.Cryptography.SHA256]::Create()
($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join ""
