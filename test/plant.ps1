# Practice only, made-up data. Builds a made-up folder tree with planted test cases (download mark, hard link, junction, locked file, leftovers).
$ErrorActionPreference='Stop'
$R='C:\T5P\root'; New-Item -ItemType Directory -Force "$R\sub\deep","$R\empty" | Out-Null
[IO.File]::WriteAllText("$R\plain.txt","made-up plain file`n")
[IO.File]::WriteAllBytes("$R\sub\data.bin",[byte[]](1,2,3,4))
[IO.File]::WriteAllText("$R\sub\deep\leftover.dat","planted leftover`n")
[IO.File]::WriteAllText("$R\marked.txt","file with a download mark`n")
Set-Content -LiteralPath "$R\marked.txt" -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3"
[IO.File]::WriteAllText("$R\hard_a.txt","hard link pair`n"); cmd /c mklink /H "$R\hard_b.txt" "$R\hard_a.txt" | Out-Null
New-Item -ItemType Directory -Force C:\T5P\outside | Out-Null; [IO.File]::WriteAllText('C:\T5P\outside\outside_only.txt',"must not be listed`n")
cmd /c mklink /J "$R\junction_to_outside" C:\T5P\outside | Out-Null
[IO.File]::WriteAllText("$R\locked.txt","locked file`n")
New-Item -ItemType Directory -Force C:\T5P\leftover_dir | Out-Null
New-Item -ItemType Directory -Force C:\T5P\out_exists | Out-Null
'planted'
