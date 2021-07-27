<#PSScriptInfo
	.SYNOPSIS
		Skrypt umozliwiajacy laczenie sie z komputerami za pomoca OpenSSH.
	
	.DESCRIPTION
		Skrypt importuje podany w parametrze [-PathSNJson] plik .json, pobiera z niego informacje niezbedne do nawiazania polaczenia, nastepnie probuje polaczyc sie po kolei z kazdym komputerem. Po polaczeniu (za pomoca protokolu SSH lub SFTP) skrypt wykonuje konkretne zadanie, w zaleznosci od wybranego parametru.
	
	.PARAMETER PathSNJson
		Parametr oblligatoryjny do uruchomienia skryptu. Sciezka do pliku .json wygenerowanego z systemu Arrow.
	
	.PARAMETER ScriptRun
		Po podaniu sciezki (zdalnej), uruchamia skrypt na serwerach.
	
	.PARAMETER ScriptSendAndRun
		Po wybraniu skryptu oraz wpisaniui sciezki docelowej (zdalnej), przesyla go na serwery, uruchamia go, a nastepnie usuwa.
	
	.PARAMETER TypeCommand
		Po wpisaniu komendy, uruchamia ja na serwerach.
	
	.PARAMETER FileSend
		Po wybraniu pliku i podaniu sciezki docelowej, przesyla plik na serwewy.
	
	.PARAMETER FileGet
		Po wpisaniu sciezki pliku, pobiera go serwerow i zapisuje w utworzonym folderze na pulpicie.
	
	.PARAMETER FolderSend
		Po wybraniu folderu i podaniu sciezki docelowej, przesyla folder wraz z wszystkimi plikami, lub same pliki, znajdujacymi sie w wybranym folderze na serwery.
	
	.PARAMETER PlayerVersion
		Po wskazaniu pliku SNPlayer.exe, sprawdza wersje playera na podstawie Hash MD5.
	
	.PARAMETER FreeSpace
		Sprawdza ilosc wolnego miejsca na dyskach serwerow.
	
	.PARAMETER Slides
		Sprawdza ilosc slajdow na serwerach.
	
	.PARAMETER EventLog
		Pobiera najnowsze 50 event log'ow z serwerow i zapisuje je w plikach .csv, w utworzonym folderze na pulpicie.
	
	.PARAMETER BSOD
		Sprawdza czy na serwerach sa pliki .dmp, jezeli wystepuja, obiera plik .zip z skompresowanymi plikami .dmp.
	
	.PARAMETER ReleaseUpdate
		Po wskazaniu pliku SNPlayer.exe, oraz pliku Release.zip do podmiany, sprawdza wersje playera na podstawie Hash MD5. Jezeli nie Hash MD5 sa niezgodne ze soba podmienia folder Release.
	
	.PARAMETER PlayerLog
		Pobiera plik logfile.txt z serwerow i zapisuje je w utworzonym folderze na pulpicie.
	
	.PARAMETER SystemReport
		Tworzy skrypt 'SystemReport.ps1', ktory tworzy raport systemowy serwera z wypisanymi szczegolami: systemu operacyjnego, plyty glownej, procesora, karty graficznej, Bios'a i usług. Nastepnie przesyla skrypt na serwer, uruchamia go, pobiera plik 'SystemReport.html', usuwa wszystkie utworzone pliki.
	
	.PARAMETER WindowsActivated
		Sprawdza status aktywacji Windows'a na serwerach.
	
	.PARAMETER HTML
		Generuje dodatkowo LOG w pliku .html.
	
	.PARAMETER NoCSV
		Nie tworzy pliku .csv.
	
	.PARAMETER ChooseSN
		Filtruje komputery na podstawie wpisanych numerow SN.
	
	.PARAMETER CollectionSN
		Filtruje komputery na podstawie przedzialu utworzonego przez wpisanie dwoch granicznych numerow SN.
	
	.PARAMETER GroupSN
		Filtruje komputery na podstawie wpisanej grupy.
	
	.EXAMPLE
		Polaczenie za pomoca protokolu SSH, sprawdzenie statusu aktywacji systemu Windows, LOG do pliku .csv. Otworzenie pliku LOG.
		
		PS C:\Users\Konkow\Desktop> .\SNScript_v1.3.1.ps1 -PathSNJson "C:\Users\Konkow\Desktop\data_export.json" -WindowsActivated
		
		
		Checking connection with: sn585 - Serwis IT
		WARNING: Host key is not being verified since Force switch is used.
		SSH Connected!
		Processing script...
		Closing SSH connection... True
	
	.EXAMPLE
		Polaczenie za pomoca protokolu SFTP, Wyslanie skryptu GPU_model.ps1 na serwer. Polaczenie za pomoca protokolu SSH, uruchomienie skryptu, pobranie output'u, usuniecie skryptu, LOG do pliku .html. Otworzenie pliku LOG.
		
		PS C:\Users\Konkow\Desktop> .\SNScript_v1.3.1.ps1 -PathSNJson "C:\Users\Konkow\Desktop\data_export.json" -ScriptSendAndRun -NoCSV
		
		Parametr [-HTML] musi byc wlaczony przy uzyciu parametru [-NoCSV], wlaczam...
		
		
		Wybierz plik do przeslania...
		ScriptSendAndRun: C:\Users\Konkow\OneDrive - Screen Network S.A\Dokumenty\WindowsPowerShell\Scripts\GPU_model.ps1
		Sciezka destynacji na serwerze (zdalna): /c:/screennetwork/
		
		
		Checking connection with: sn585 - Serwis IT
		WARNING: Host key is not being verified since Force switch is used.
		SFTP Connected!
		VERBOSE: Uploading C:\Users\Konkow\OneDrive - Screen Network S.A\Dokumenty\WindowsPowerShell\Scripts\GPU_model.ps1
		VERBOSE: Uploading to /c:/screennetwork/GPU_model.ps1 on 10.99.10.82
		Closing SFTP connection... True
		WARNING: Host key is not being verified since Force switch is used.
		SSH Connected!
		Processing script...
		Closing SSH connection... True
	
	.EXAMPLE
		Polaczenie za pomoca protokolu SSH, urchomienie wpisanej komendy,  pobranie output'u, LOG do pliku .csv oraz .html. Otworzenie obu plikow LOG.
		
		PS C:\Users\Konkow\Desktop> .\SNScript_v1.3.1.ps1 -PathSNJson "C:\Users\Konkow\Desktop\data_export.json" -TypeCommand -HTML
		
		Komenda, ktora ma zostac uruchomiona na serwerze (BEZ CUDZYSLOWOW): (Get-WmiObject -Class Win32_VideoController).VideoModeDescription
		
		
		Checking connection with: sn585 - Serwis IT
		WARNING: Host key is not being verified since Force switch is used.
		SSH Connected!
		Processing command...
		Closing SSH connection... True
	
	.NOTES
		Przykladowa sciezka do pliku na komputerze (lokalna): c:\users\user\desktop
		Przykladowa sciezka do pliku na serwerze (zdalna): /c:/screennetwork/admin/
		
		Updates:
		- 1.1.1 - Sprawdzenie polaczenia z VPN przed uruchomieniem skryptu
		- 1.2.0 - Poprawienie bugow
		- 1.3.0 - Dodanie automatycznej instalacji modulu PoshSSH
		        - Poprawienie bugow
		- 1.3.1 - Poprawienie wyswietlania outputu z serwera
		        - Poprawienie skryptu SystemReport
		        - Dodanie parametru -HTML
		        - Dodanie parametru -NoCSV
		        - Automatyczne otwieranie pliku(ow) LOG
		- 1.3.2 - Doanie parametru filtrujacego -ChooseSN
		        - Doanie parametru filtrujacego -CollectionSN
		        - Doanie parametru filtrujacego -GroupSN
                - Dodanie mozliwosci przeslania samych plikow, bez folderu, w parametrze -FolderSend
                - Dodanie pomijania polaczenia jezeli kopmuter pracuje na WinXP
                - Sprawdzenie rozszerzenia pliku podanego w parametrze PathSNJson
                - Zamiana w output'cie kolumny 'Parameter' na 'Localization'
                - Dodane nowe grupy w filtrowaniu -GroupSN
                - Dodane domyslne kodowanie UTF8

                
		===========================================================================
	 	Created on:   	30-Aug-2019 
	 	Created by:   	Konrad Kowalski
	 	Organization: 	KonkowIT
		Filename:     	SN_ScriptSSH
		===========================================================================
	

	.INPUTS
		Plik .json, wygenerowanego z systemu Arrow, z ktorego skrypt pobiera informacje niezbedne do nawiazania polaczenia.
	
	.LINK
		http://gitlab.coderush.pl/screennetwork/arrow/wikis/SN_ScriptSSH
	
	.LINK
		Konfiguracja i uzywanie OpenSSH
		http://gitlab.coderush.pl/screennetwork/arrow/wikis/Konfiguracja-i-u%C5%BCywanie-OpenSSH#konfiguracja-i-u%C5%BCywanie-openssh
		
		SN_ScriptSSH
		http://gitlab.coderush.pl/screennetwork/arrow/wikis/SN_ScriptSSH
#>
[CmdletBinding()]
param
(
	[Parameter(Mandatory = $true)]
	[ValidateNotNullOrEmpty()]
	[String]$PathSNJson,
	[switch]$ScriptRun,
	[switch]$ScriptSendAndRun,
	[switch]$TypeCommand,
	[switch]$FileSend,
	[switch]$FileGet,
	[switch]$FolderSend,
	[switch]$PlayerVersion,
	[switch]$FreeSpace,
	[switch]$Slides,
	[switch]$EventLog,
	[switch]$BSOD,
	[switch]$ReleaseUpdate,
	[switch]$PlayerLog,
	[switch]$SystemReport,
	[switch]$WindowsActivated,
	[switch]$HTML,
	[switch]$NoCSV,
	[switch]$ChooseSN,
	[switch]$CollectionSN,
	[switch]$GroupSN
)

# Default encoding
$PSDefaultParameterValues['*:Encoding'] = 'utf8'

# Sprawdzenie ilosci wybranych parametrow
$paramteres = @($ScriptRun, $ScriptSendAndRun, $TypeCommand, $FileSend, $FileGet, $FolderSend, $PlayerVersion, `
        $FreeSpace, $Slides, $EventLog, $BSOD, $ReleaseUpdate, $PlayerLog, $SystemReport, $WindowsActivated)
$counter = 0
$paramteres | ForEach-Object {
    if ($_ -eq $true) { 
        $counter++ 
    } 
}

if ($counter -eq 1) {
    Write-Verbose "Correct number of parameters"
}
elseif ($counter -eq 0) {
    "`n"
    Write-Host "Brak wybranych parametrow skryptu!" -ForegroundColor Red -BackgroundColor Black 
    "`n"
    Break
}
else {
    "`n"
    Write-Host "Mozesz wybrac tylko jeden parametr uruchomienia skryptu!" -ForegroundColor Red -BackgroundColor Black 
    Write-Host "nie dotyczy parametrow [-PathSNJson], [-HTML], [-NoCSV], [-ChooseSN], [-CollectionSN] oraz [-GroupSN]"
    "`n"
    Break
}

if (($NoCSV -eq $true) -and ($HTML -eq $false)) {
    "`n"
    Write-host "Parametr [-HTML] musi byc wlaczony przy uzyciu parametru [-NoCSV], wlaczam..." -ForegroundColor Blue
    $HTML = $true
}

# preferncje komunikatow Warning
$WarningPreference = "SilentlyContinue"

#########################################################################
########################## ZMIENNE GLOBALNE #############################
#########################################################################

$global:results = @()
$global:resultsHTML = @()

#########################################################################
############################## FUNKCJE ##################################
#########################################################################

function Get-TimeStamp {
    return "{0:dd/mm/yyyy} {0:HH:mm:ss}" -f (Get-Date)
}

Function Get-FileName {   
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.ShowDialog() | Out-Null
    
    return $OpenFileDialog.filename
} 

Function Test-ConnectionQuietFast {
    [CmdletBinding()]
    param(
        [String]$ComputerName,
        [int]$Count = 2,
        [int]$Delay = 300
    )
 
    for ($I = 1; $I -lt $Count; $i++) {
        # Test the connection quiet to the computer with one ping
        If (Test-Connection -ComputerName $ComputerName -Quiet -Count $Count) {
            # Computer can be contacted, return $True
            return $True
        }
 
        # delay between each pings
        Start-Sleep -Milliseconds $Delay
    }
 
    # Computer cannot be contacted, return $False
    $True
}

Function Get-Folder {
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null

    $foldername = New-Object System.Windows.Forms.FolderBrowserDialog
    $foldername.Description = "Select a folder"
    $foldername.rootfolder = "MyComputer"

    if ($foldername.ShowDialog() -eq "OK") {
        $folder += $foldername.SelectedPath
    }
    
    return $folder
}

function ExportToResults {
    [CmdletBinding()]
    param (
        [System.Object]$outputDetails
    )
    
    $hash = [ordered]@{ 
        Date         = $outputDetails.Date; 
        Protocol     = $outputDetails.Protocol; 
        SN           = $outputDetails.SN;
        Localization = $outputDetails.Localization;
        Status       = $outputDetails.Status; 
        Output       = $outputDetails.Output 
    }

    $global:results = [array]$global:results + (New-Object psobject -Property $hash)
}

function ExportToResultsHTML {
    [CmdletBinding()]
    param (
        [System.Object]$outputDetails
    )
    
    $hash = [ordered]@{ 
        Date         = $outputDetails.Date; 
        Protocol     = $outputDetails.Protocol; 
        SN           = $outputDetails.SN; 
        Localization = $outputDetails.Localization; 
        Status       = $outputDetails.Status; 
        Output       = $outputDetails.Output 
    }

    $global:resultsHTML = [array]$global:resultsHTML + (New-Object psobject -Property $hash)
}

#########################################################################
######################## PODSTAWOWE ZMIENNE #############################
#########################################################################

# Sprawdzenie obecnosci Posh-SSH
if ($null -eq (Get-InstalledModule -name "Posh-SSH" -ErrorAction SilentlyContinue)) {
    "`n"
    Write-Host "Brak zainstalowanego modulu Posh-SSH koniecznego do korzystania ze skryptu!" -ForegroundColor Red -BackgroundColor Black
    Start-sleep -s 1
    $arguments = "Write-host 'Instalacja modulu Posh-SSH';install-module -name posh-ssh -force"
    Start-Process powershell -Verb runAs -ArgumentList $arguments -Wait
    "`n"
    
    if ($null -eq (Get-InstalledModule -name "Posh-SSH" -ErrorAction SilentlyContinue)) {
        Write-Host "Modul nie zostal poprawnie zainstalowany, sproboj zrobic to recznie..." -ForegroundColor Red -BackgroundColor Black
        Break
    }
    else {
        Write-Host "Modul Posh-SSH zostal poprawnie zainstalowany" -ForegroundColor Green
    }
}

# Plik .json z komputerami w sieciach
if ($PathSNJson.Contains("`"")) {
    $PathSNJson = $PathSNJson -replace '[""]' 
}

if ((Test-Path $PathSNJson) -and ([IO.Path]::GetExtension($PathSNJson) -eq ".json")) {
    $servers = Get-Content -Raw -Path $PathSNJson | ConvertFrom-Json   
}
elseif ((Test-Path $PathSNJson) -and ([IO.Path]::GetExtension($PathSNJson) -ne ".json")) {
    "`n"
    Write-Host "To nie jest plik .json!" -ForegroundColor Red -BackgroundColor Black 
    "`n"
    Break
}
else {
    "`n"
    Write-Host "Bledna sciezka do pliku .json!" -ForegroundColor Red -BackgroundColor Black 
    "`n"
    Break
}

# Plik LOG
$date = Get-Date -Format yyyy-MM-dd  
$logFileName = "SSH-LOG_" + $date

$LogFileHTML = ( -join ($env:USERPROFILE, "\Desktop\" + $logFileName + ".html"))
$LogFile = ( -join ($env:USERPROFILE, "\Desktop\" + $logFileName + ".csv"))

# Credentials do polaczenia po SSH
$username = "***"
$secpasswd = ConvertTo-SecureString "***" -AsPlainText -Force
$credential = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secpasswd

# Klucz autentykacyjny
$authenticationKey = ( -join ($env:USERPROFILE, "\.ssh\ssh-key"))

#########################################################################
############################ FILTROWANIE SN #############################
#########################################################################

# Wybrane numery SN
if ($ChooseSN) {
    "`n"
    [string]$snNumbers = Read-Host -Prompt "Wpisz numery SN przedzielajac je przecinkiem (bez 'sn' oraz spacji)"
    
    if ($snNumbers -eq ($null -or "")) {
        "`n"
        Write-host "Wpisz prawidlowe numery SN!" -ForegroundColor Red
        "`n"
        Break
    }

    if ($snNumbers.StartsWith('sn') -eq $false) {
        $snNumbers = 'sn' + $snNumbers
    }

    $snNumbers = $snNumbers -replace ',',( -join ([environment]::NewLine, "sn"))
    $filteredServers_Choose = @()

    foreach ($value in $servers) {
        if ($snNumbers.Contains($value.name)) {
            $filteredServers_Choose = $filteredServers_Choose + $value
        }
    }

    $servers = $filteredServers_Choose
}

# Przedzial numerow SN
if ($CollectionSN) {
    "`n"
    [int]$snNumbersStart = Read-Host -Prompt "Wpisz numer poczatkowy zbioru (bez 'sn')"
    [int]$snNumbersEnd = Read-Host -Prompt "Wpisz numer koncowy zbioru (bez 'sn')"

    if (($snNumbersEnd -lt $snNumbersStart) -or ($snNumbersStart -eq $snNumbersEnd) -or (($snNumbersStart -or $snNumbersEnd) -eq ($null -or 0))) {
        "`n"
        Write-Host "Wprowadz prawidlowe wartosci, poczatkowa liczba nie moze byc mniejsza ani rowna koncowej." -ForegroundColor Red
        "`n"
        Break
    }

    [array]$filteredServers_Collection = $snNumbersStart..$snNumbersEnd 
    
    for ($i = 0; $i -le $filteredServers_Collection.Count - 1; $i ++) {
        $filteredServers_Collection[$i] = $filteredServers_Collection[$i].ToString()
        
        if ($filteredServers_Collection[$i].Length -eq 1) {
            $filteredServers_Collection[$i] = "00" + $filteredServers_Collection[$i]
        }

        if ($filteredServers_Collection[$i].Length -eq 2) {
            $filteredServers_Collection[$i] = "0" + $filteredServers_Collection[$i]
        }

        $filteredServers_Collection[$i] = "sn" + $filteredServers_Collection[$i]
    }

    foreach ($value in $servers) {
        if ($filteredServers_Collection.Contains($value.name)) {
            $filteredServers_Collection_Values = [array]$filteredServers_Collection_Values + $value
        }
    }

    $servers = $filteredServers_Collection_Values
}

# Numery SN znajdujace sie w grupie
if ($GroupSN) {
    "`n"
    $snGroup = Read-Host -Prompt "Wpisz nazwe grupy (bez polskich znakow!)"

    if ($snGroup -eq ($null -or "")) {
        "`n"
        Write-Host "Brak wpisanej grupy!" -ForegroundColor Red
        "`n"
        Break
    }

    $snGroup = $snGroup.ToLower()
    $groupList = @{
        1 = "siec_1"
    }

    Foreach ($Key in ($groupList.GetEnumerator() | Where-Object { $_.Value.ToLower() -eq $snGroup })) {
        $snGroupID = $Key.name
    }

    if ($null -eq $snGroupID) {
        "`n"
        Write-Host "Nie znaleziono wyszukiwanej grupy! Sprawdz pisownie" -ForegroundColor Red
        "`n"
        Break
    }


    $filteredServers_Group = @()

    foreach ($value in $servers) {
        if ($value.group_id -eq $snGroupID) {
            $filteredServers_Group = $filteredServers_Group + $value
        }
    }

    if ($filteredServers_Group.Count -eq 0) {
        "`n"
        Write-Host "Brak komputerow z danej grupy!" -ForegroundColor Red
        "`n"
        Break
    }

    $servers = $filteredServers_Group
}

#########################################################################
######################## ZMIENNE DLA PARAMETROW #########################
#########################################################################

# Zmienne dla -ScriptRun
if ($ScriptRun) {
    "`n"
    [String]$executingScriptPath = Read-Host -Prompt "Sciezka do skryptu na serwerze (lokalna)"
}

# Zmienne dla -ScriptSendAndRun
if ($ScriptSendAndRun) {
    "`n"
    Write-Output "Wybierz plik do przeslania..."
    Start-Sleep -s 2
    [String]$filePath = Get-FileName
    Write-Output ( -join ("Script to send path : ", $filePath))
    [String]$sftpPath = Read-Host -Prompt "Sciezka destynacji na serwerze (zdalna)"
    $sftpFilePath = $sftpPath -replace '/', '\'

    if ($sftpFilePath.StartsWith('\')) {
        $sftpFilePath = $sftpFilePath.Substring(1)
    }

    if ($sftpFilePath -notmatch '\\$') {
        $sftpFilePath += '\'
    }

    [String]$executingScriptPath = ( -join ($sftpFilePath, (Split-Path $filePath -Leaf -Resolve)))
}

# Zmienne dla -TypeCommand
if ($TypeCommand) {
    "`n"
    [String]$executingCommand = Read-Host -Prompt "Komenda, ktora ma zostac uruchomiona na serwerze (BEZ CUDZYSLOWOW)"
    if ($executingCommand -eq ($null -or "")) {
        Write-Host "Komenda nie moze byc pusta!" -ForegroundColor Red -BackgroundColor Black
        Start-Sleep -s 3 
        Break
    }

    $executingCommand = $executingCommand -replace "`"", "`'"
}

# Zmienne dla -FileSend
if ($FileSend) {
    "`n"
    Write-Output "Wybierz plik do przeslania..."
    Start-Sleep -s 2
    [String]$filePath = Get-FileName
    Write-Output ( -join ("File to send path : ", $filePath))
    [String]$sftpPath = Read-Host -Prompt "Sciezka destynacji na serwerze (zdalna)"
}

# Zmienne dla -FileGet
if ($FileGet) {
    "`n"
    [String]$sftpPath = Read-Host -Prompt "Sciezka pliku na serwerze, ktory ma zostac pobrany (zdalna)"
    $filePath = ( -join ($env:USERPROFILE, "\Desktop\DownloadedFiles"))
    if (!(Test-Path -path $filePath)) {
        $filePath = New-Item -ItemType Directory -Path $filePath -Force
    }
}

# Zmienne dla -FolderSend
if ($FolderSend) {
    "`n"
    Write-Output "Wybierz folder do przeslania..."
    Start-Sleep -s 2
    [String]$filePath = Get-Folder
    Write-Output ( -join ("Folder to send path : ", $filePath))
    $filePathName = Split-Path $filePath -Leaf -Resolve
    [String]$sftpPath = Read-Host -Prompt "Sciezka destynacji na serwerze (zdalna)"
    
    if (!($sftpPath.EndsWith('/'))) {
        $sftpPath = ( -join ($sftpPath, "/"))
    }

    $newFolderOnServer = Read-Host -Prompt ( -join ("Czy chcesz utworzyc folder `'", $filePathName, "`' na serwerze? [ Y / N ]"))
    
    if ($newFolderOnServer.ToLower() -eq "y") {
        Write-Host "Folder zostanie utworzony"
        $newFolderOnServerResposne = $false
    }
    elseif ($newFolderOnServer.ToLower() -eq "n") {
        Write-Host "Folder nie zostanie utworzony"
        $newFolderOnServerResposne = $true
    }
    else {
        Write-Host "Bledna odpowiedz, folder nie zostanie utworzony"
        $newFolderOnServerResposne = $true
    }
}

# Zmienne dla -PlayerVersion
if ($PlayerVersion) {
    "`n"
    $commandText = "(Get-FileHash 'C:\SCREENNETWORK\player\Release\SNPlayer.exe' -Algorithm MD5).Hash"
    Write-Output "Wskaz plik SNPlayer.exe do porownania..."
    Start-Sleep -s 2
    [String]$snPlayerPath = Get-FileName
    $correctMD5_v3 = (Get-FileHash $snPlayerPath -Algorithm MD5).Hash
    #$correctMD5_v5 = ""
}

# Zmienne dla -FreeSpace
if ($FreeSpace) {
    $commandText = "(Get-PSDrive C ).free/1GB"
}

# Zmienne dla -Slides
if ($Slides) {
    $commandText = "(Get-ChildItem -Path 'C:\SCREENNETWORK\player\sn\kontent' -Recurse).count"
}

# Zmienne dla -EventLog
if ($EventLog) {
    $commandText = "Get-EventLog -LogName System -Newest 50"
    $eventLogFolder = ( -join ($env:USERPROFILE, "\Desktop\EventLOGs"))

    if (!(Test-Path -path $eventLogFolder)) {
        $eventLogFolder = New-Item -ItemType Directory -Path $eventLogFolder  -Force
    }
}

# Zmienne dla -BSOD
if ($BSOD) {
    $sftpPath = "/C:/Windows/Minidump/"
    $sftpArchivePath = "/C:/Users/sn/bsods.zip"
    $filePath = ( -join ($env:USERPROFILE, "\Desktop\Downloaded_BSODs"))

    if (!(Test-Path -path $filePath)) {
        $filePath = New-Item -ItemType Directory -Path $filePath -Force
    }
}

# Zmienne dla -ReleaseUpdate
if ($ReleaseUpdate) {
    "`n"
    Write-Output "Wskaz plik SNPlayer.exe do porownania..."
    Start-Sleep -s 2
    [String]$snPlayerPath = Get-FileName
    $correctMD5_v3 = (Get-FileHash $snPlayerPath -Algorithm MD5).Hash
    Write-Output "Wskaz plik Release.zip do podmiany..."
    Start-Sleep -s 2
    [String]$filePath = Get-FileName
    $commandText = "(Get-FileHash 'C:\SCREENNETWORK\player\Release\SNPlayer.exe' -Algorithm MD5).Hash"
}

# Zmienne dla -PlayerLog
if ($PlayerLog) {
    $sftpPath = '/c:/screennetwork/player/release/logfile.txt'
    $filePath = ( -join ($env:USERPROFILE, "\Desktop\PlayerLOGs"))

    if (!(Test-Path -path $filePath)) {
        $filePath = New-Item -ItemType Directory -Path $filePath -Force
    }
}

# Zmienne dla -SystemReport
if ($SystemReport) {

    # Tworzenie skryptu SystemReport.ps1
    if (Test-Path -Path "C:\temp") {
        Remove-Item -Path "C:\temp" -Recurse -Force -ErrorAction SilentlyContinue
    }

    mkdir "c:\temp" | Out-Null
    New-Item -path "C:\temp\" -name "SystemReport.txt" -ItemType File -Force | Out-Null
    $scriptBlock = @( 
        'if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { '
        '    $arguments = ( -join ("& ", $myinvocation.mycommand.definition))'
        '    Start-Process powershell -Verb runAs -ArgumentList $arguments -WindowStyle Hidden'
        '    Break'
        ' }'
        ''
        '$COMPUTERNAME = $env:computername'
        '$os = Get-WmiObject -Class win32_operatingsystem -computername $COMPUTERNAME | '
        'Select-Object Caption, OSArchitecture, Version, ServicePackMajorVersion, TotalVisibleMemorySize, TotalVirtualMemorySize, BuildNumber | '
        'ConvertTo-Html -fragment -as list -PreContent "Generated $(Get-Date)<br><br><center><h2>Operating System</h2></center>" | Out-String'
        '$mb = Get-WmiObject -class Win32_baseboard -ComputerName $COMPUTERNAME | '
        'Select-Object Manufacturer, Model, Name, Version, SerialNumber | '
        'ConvertTo-Html -Fragment -as list -PreContent "<center><h2>Motherboard</h2></center>" | Out-String'
        '$cpu = Get-WmiObject win32_Processor -ComputerName $COMPUTERNAME | '
        'Select-Object Name, Caption, Manufacturer, MaxClockSpeed, NumberOfCores, L2CacheSize, L3CacheSize | '
        'ConvertTo-Html -Fragment -as list -PreContent "<center><h2>CPU</h2></center>" | Out-String'
        '$GPU = Get-WmiObject win32_videocontroller -ComputerName $COMPUTERNAME | '
        'Select-Object Name, MaxRefreshRate, VideoModeDescription, AdapterRAM, DriverVersion | '
        'ConvertTo-Html -Fragment -as list -PreContent "<center><h2>Graphics Card</h2></center>" | Out-String'
        '$comp = Get-WmiObject -Class win32_computersystem -ComputerName $COMPUTERNAME | '
        'Select-Object Model, Name, SystemType | '
        'ConvertTo-Html -fragment -as table -PreContent "<center><h2>Computer</h2></center>" | Out-String'
        '$bios = Get-WmiObject win32_bios -ComputerName $COMPUTERNAME | '
        'Select-Object Name, Manufacturer, SerialNumber | '
        'ConvertTo-Html -fragment -PreContent "<center><h2>Bios</h2></center>" | Out-String'
        '$stopsvc = Get-WmiObject -Class win32_service -ComputerName $COMPUTERNAME | '
        'Where-Object { $_.StartMode -eq "Auto" -and $_.State -eq "Stopped" } | '
        'Select-Object Name, Caption | '
        'ConvertTo-Html -fragment -PreContent "<center><h2>Stopped Services (StartMode = Automatic)</h2></center>" | Out-String'
        '$startsvc = Get-WmiObject -Class win32_service -ComputerName $COMPUTERNAME | '
        'Where-Object { $_.State -eq "Running" } | '
        'Select-Object Name, Caption, Description | '
        'ConvertTo-Html -fragment -PreContent "<center><h2>Running Services</h2></center>" | Out-String'
        '$final = ConvertTo-Html -Title "$COMPUTERNAME System Report" `'
        '    -PreContent $os, $mb, $cpu, $GPU, $comp, $bios, $stopsvc, $startsvc `'
        '    -Body "<h1><center>$COMPUTERNAME System Report</center></h1>" `'
        '    -CSSUri "Stylesheet.css"     '          
        '$final | out-file ("C:\SystemReport.html")'
    )    
    
    $scriptBlock | ForEach-Object {
        Add-Content C:\temp\SystemReport.txt -Value $_
    }
    
    Copy-Item C:\temp\SystemReport.txt -Destination C:\temp\SystemReport.ps1

    # Zmienne
    $filePath = "C:\temp\SystemReport.ps1"
    $sftpPath = "/C:/"
    $sftpReportPath = "/C:/SystemReport.html"
    $executingScriptPath = "C:\SystemReport.ps1"
    $folderDownloadedPath = ( -join ($env:USERPROFILE, "\Desktop\DownloadedFiles"))
    
    if (!(Test-Path -path $folderDownloadedPath)) {
        $folderDownloadedPath = New-Item -ItemType Directory -Path $folderDownloadedPath -Force
    }
}

# Zmienne dla -WindowsActivated
if ($WindowsActivated) {
    $commandText = "(Get-CimInstance -ClassName SoftwareLicensingProduct | where PartialProductKey).LicenseStatus[0]"
}

# Zmienne dla -HTML
if ($HTML) {
    Add-Type -AssemblyName System.Web
    $styles = @"
<style>    
    table {
        Margin: auto;
        Border: 2px solid rgb(70, 70, 70);
        Font-Family: Tahoma;
        Font-Size: 10pt;
        Background-Color: rgb(252, 252, 252);
        width: 90%;
        padding: 5px;
    }
    
    tr:hover td {
        Background-Color: rgb(7, 140, 212);
        Color: rgb(255, 255, 255);
    }
    
    tr:nth-child(even) {
        Background-Color: rgb(156, 156, 156);
    }
    
    th {
        Text-Align: Center;
        Vertical-Align: Center;
        Font-Size: 12pt;
        font-weight: bold;
        Color: rgb(121, 121, 196);
        Padding: 1px 4px 1px 4px;
    }
    
    td {
        Vertical-Align: Center;
        Text-Align: Left;
        Padding: 5px 4px 5px 4px;
    }
</style>
"@
}

#########################################################################
################################ SKRYPT #################################
#########################################################################

#Sprawdzenie polaczenia z VPN
"`n"
if (!(Test-ConnectionQuietFast -ComputerName 10.99.99.1)) {
    Write-Host "Check VPN connection!" -ForegroundColor Red -BackgroundColor Black
    "`n"
    Start-Sleep -s 3
    Break
}

foreach ($value in $servers) {
    Write-Output ( -join ("Checking connection with: ", $value.name, " - ", $value.placowka)) 

    if($value.player_release -like "2*") {
        #Sprawdzenie czy Windows XP 
        Write-Host "Windows XP" -ForegroundColor Red
        "`n"

        #Export do HTML
        if ($HTML) {
            $details = [ordered] @{
                Date      = Get-TimeStamp
                Protocol  = "-"
                SN        = ($value.name)
                Localization  = $value.placowka
                Status    = "-"
                Output    = "Windows XP"
            }

            ExportToResultsHTML -outputDetails $details
        }

        #Export do CSV
        if (!$NoCSV) {
            $details = [ordered] @{
                Date      = Get-TimeStamp
                Protocol  = "-"
                SN        = ($value.name)
                Localization  = $value.placowka
                Status    = "-"
                Output    = "Windows XP"
            }

            ExportToResults -outputDetails $details
        }
    }
    #Filtr komputerow bez IP
    elseif (($value.ip -ne "NULL") -and (!($value.player_release -like "2*"))) {
        
        #Czyszczenie zmiennych
        $snIP = $null
        $outputSSH = $null
        $OutputSFTP = $null
            
        $snIP = $value.ip

        # SFTP
        if ($FileGet -or $FileSend -or $FolderGet -or $FolderSend -or $ScriptSendAndRun -or $BSOD -or $PlayerLog -or $SystemReport) {
            #Nawiazanie polaczenia
            try {
                New-SFTPSession -ComputerName $snIP -Credential $credential -KeyFile $authenticationKey -ConnectionTimeout 120 -force -ErrorAction Stop | out-null
                $getSFTPSessionId = (Get-SFTPSession | Where-Object { $_.Host -eq $snIP }).SessionId

                if ($null -ne $getSFTPSessionId) {
                    $snStatus = "Online"

                    if ((Get-SFTPSession | Where-Object { $_.Host -eq $snIP }).Connected -eq $true) {
                        Write-Host "SFTP Connected!" -ForegroundColor Green
                    }
    
                    if ($FileSend -or $ScriptSendAndRun -or $SystemReport) {
                        #Przeslanie pliku
                        Set-SFTPFile -SessionId $getSFTPSessionId -RemotePath $sftpPath -LocalFile $filePath -verbose -Overwrite
                        $OutputSFTP = ( -join ("Uploading  `'", $filepath, "`'  to  `'", $sftpPath, "`'"))
                    } 
    
                    if ($FolderSend) {
                        Set-SFTPFolder -SessionId $getSFTPSessionId -RemotePath ( -join ($sftpPath, $filePathName)) -LocalFolder $filePath -verbose -Overwrite
                        $OutputSFTP = ( -join ("Uploading '", $filepath, "'  to  '", ( -join ($sftpPath, $filePathName)), "'")) 
                        
                        if ($newFolderOnServerResposne) {
                            # SSH
                            #Nawiazanie polaczenia
                            New-SSHSession $snIP -KeyFile $authenticationKey -AcceptKey -force -Credential $credential -ConnectionTimeout 120 | out-null
                            $getSSHSessionId = (Get-SSHSession | Where-Object { $_.Host -eq $snIP }).SessionId
                                
                            if ((Get-SSHSession | Where-Object { $_.Host -eq $snIP }).Connected -eq $true) {
                                Write-Host "SSH Connected!" -ForegroundColor Green
                            }
    
                            #Uruchomienie skryptu
                            Write-output "Processing script..."
                            $sftpPathForSSH = $sftpPath -replace '/', '\'

                            if ($sftpPathForSSH.StartsWith('\')) {
                                $sftpPathForSSH = $sftpPathForSSH.Substring(1)
                            }
                             
                            Invoke-SSHCommand -SessionId $getSSHSessionId -Command "Copy-Item -Path $sftpPathForSSH$filePathName'\*' -Destination $sftpPathForSSH -Force" | Out-Null
                            Invoke-SSHCommand -SessionId $getSSHSessionId -Command "Remove-Item $sftpPathForSSH$filePathName -Force -Recurse" | Out-Null
                            
                            #Zakonczenie polaczenia SSH
                            Write-Output ( -join ("Closing SSH connection... ", (Remove-SSHSession -SessionId $getSSHSessionId)))
                        }
                    }
    
                    if ($FileGet -or $BSOD -or $PlayerLog -or $FolderGet -or $FolderSend) {
                        #Pobranie pliku 
                        if (Test-SFTPPath -SessionId $getSFTPSessionId -Path $sftpPath) {
                            
                            if ($FileGet) {
                                $filePathDownloaded = New-Item -ItemType Directory -Path ( -join ($filePath, "`\", $value.name)) -Force
                                Get-SFTPFile -SessionId $getSFTPSessionId -LocalPath $filePathDownloaded -RemoteFile $sftpPath -verbose
                                $OutputSFTP = ( -join ("Downloading '", $sftpPath, "' to '", $filePathDownloaded, "'"))
                                $filePathDownloaded = $null
                            }
    
                            if ($BSOD) {
                                $filePathDownloaded = New-Item -ItemType Directory -Path ( -join ($filePath, "`\", $value.name)) -Force
                                # SSH
                                #Nawiazanie polaczenia
                                New-SSHSession $snIP -KeyFile $authenticationKey -AcceptKey -force -Credential $credential -ConnectionTimeout 120 | out-null
                                $getSSHSessionId = (Get-SSHSession | Where-Object { $_.Host -eq $snIP }).SessionId
                                
                                if ((Get-SSHSession | Where-Object { $_.Host -eq $snIP }).Connected -eq $true) {
                                    Write-Host "SSH Connected!" -ForegroundColor Green
                                }
    
                                #Uruchomienie skryptu
                                Write-output "Processing script..."
                                Invoke-SSHCommand -SessionId $getSSHSessionId -Command "Compress-Archive -Path 'C:\Windows\Minidump\*' -DestinationPath C:\Users\sn\bsods.zip" | Out-Null
    
                                #Pobranie pliku zip
                                if (Test-path -path ( -join ($filePathDownloaded, "\bsods.zip"))) {
                                    Remove-Item -path ( -join ($filePathDownloaded, "\bsods.zip")) -Force
                                }
    
                                Get-SFTPFile -SessionId $getSFTPSessionId -LocalPath $filePathDownloaded -RemoteFile $sftpArchivePath -verbose
                                $OutputSFTP = ( -join ("Downloading BSOD from ", $value.name, " to '", $filePathDownloaded, "'"))
                                $filePathDownloaded = $null
    
                                #Usuniecie pliku zip z serwera
                                Invoke-SSHCommand -SessionId $getSSHSessionId -Command "Remove-Item -path C:\Users\sn\bsods.zip -force -erroraction silentlycontinue" | Out-Null
    
                                #Zakonczenie polaczenia SSH
                                Write-Output ( -join ("Closing SSH connection... ", (Remove-SSHSession -SessionId $getSSHSessionId)))
                            }
    
                            if ($PlayerLog) {
                                Get-SFTPFile -SessionId $getSFTPSessionId -LocalPath $filePath -RemoteFile $sftpPath -verbose
                                $OutputSFTP = ( -join ("Downloading '", $sftpPath, "' to '", $filePath, "'"))
                                if (Test-Path -Path ( -join (($value.name), "_PlayerLOG.txt"))) {
                                    Remove-Item -Path ( -join (($value.name), "_PlayerLOG.txt")) -Force
                                }
    
                                Rename-Item ( -join ($filePath, "\logfile.txt")) -NewName ( -join (($value.name), "_PlayerLOG.txt")) -Force
                            }
                        }
                        elseif (!$BSOD) {
                            Write-host "Bledna sciezka do pliku na serwerze" -ForegroundColor Red
                            $OutputSFTP = "Wrong path or missing file on the server"
                        }
                        elseif ($BSOD) {
                            Write-host "Brak plikow .dmp na serwerze" -ForegroundColor Green
                            $OutputSFTP = "No .dmp files"
                        }
                    } 
    
                    if (!($SystemReport)) {
                        #Zakonczenie polaczenia
                        Write-Output ( -join ("Closing SFTP connection... ", (Remove-SFTPSession -SessionId $getSFTPSessionId)))
                    }
      
                }
            }
            catch [Exception] {
                Write-Host "An error occurred:" -ForegroundColor Red
                     
                if ($_.Exception.Message -eq "No connection could be made because the target machine actively refused it") {
                    Write-Host "SSH is not installed on this server" -ForegroundColor Red
                    $outputSFTP = "SSH is not installed on this server"
                }
                elseif($_.Exception.Message -eq "A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond") {
                    Write-Host "Server is not connected through the VPN" -ForegroundColor Red
                    $outputSFTP = "Server is not connected through the VPN"
                } 
                else {
                    Write-Host $_.Exception.Message -ForegroundColor Red
                    $outputSFTP = $_.Exception.Message
                }
                $snStatus = "ERROR"
            } 

            if (!($SystemReport -or $ScriptSendAndRun)) {
                #Export do HTML
                if ($HTML) {
                    $outputSFTP_HTML = $outputSFTP -join "<br>"
                    $details = [ordered] @{
                        Date      = Get-TimeStamp
                        Protocol  = "SFTP"
                        SN        = ($value.name)
                        Localization  = $value.placowka
                        Status    = $snStatus
                        Output    = $outputSFTP_HTML
                    }

                    ExportToResultsHTML -outputDetails $details
                }

                #Export do CSV
                if (!$NoCSV) {
                    $outputSFTP = ( $outputSFTP -join [environment]::NewLine )
                    $details = [ordered] @{
                        Date      = Get-TimeStamp
                        Protocol  = "SFTP"
                        SN        = ($value.name)
                        Localization  = $value.placowka
                        Status    = $snStatus
                        Output    = $outputSFTP
                    }

                    ExportToResults -outputDetails $details
                }
            }
        }

        # SSH
        if ($ScriptRun -or $ScriptSendAndRun -or $TypeCommand -or $FreeSpace -or $PlayerVersion -or $Slides -or $EventLog -or $ReleaseUpdate -or $SystemReport -or $WindowsActivated) {
            #Nawiazanie polaczenia
            try {
                New-SSHSession $snIP -KeyFile $authenticationKey -AcceptKey -force -Credential $credential -ConnectionTimeout 120 -ErrorAction Stop | out-null
                $getSSHSessionId = (Get-SSHSession | Where-Object { $_.Host -eq $snIP }).SessionId

                if ($null -ne $getSSHSessionId) {
                    $snStatus = "Online"

                    if ((Get-SSHSession | Where-Object { $_.Host -eq $snIP }).Connected -eq $true) {
                        Write-Host "SSH Connected!" -ForegroundColor Green
                    }

                    if ($ScriptRun -or $ScriptSendAndRun -or $SystemReport) {
                        #Uruchomienie skryptu
                        Write-output "Processing script..."
                        [String]$outputSSH = (Invoke-SSHCommand -SessionId $getSSHSessionId -Command ( -join ("& `"", $executingScriptPath, "`" -Verbose"))).output
                        if ($SystemReport) {
                            #Pobranie pliku
                            $filePathDownloaded = New-Item -ItemType Directory -Path ( -join ($folderDownloadedPath, "`\", $value.name)) -Force
                            if (Test-Path -Path $filePathDownloaded) {
                                Get-ChildItem -Path $filePathDownloaded | Remove-Item -force
                            }

                            Get-SFTPFile -SessionId $getSFTPSessionId -LocalPath $filePathDownloaded -RemoteFile $sftpReportPath -verbose | Out-Null 
                            $OutputSFTPArray = New-Object System.Collections.ArrayList
                            $OutputSFTPArray += $OutputSFTP
                            $OutputSFTP2 = ( -join ("Downloading  `'", $sftpReportPath, "`'  to  `'", $filePathDownloaded, "`'")) 
                            $OutputSFTPArray += $OutputSFTP2
                            $filePathDownloaded = $null

                            #Export do HTML
                            if ($HTML) {
                                $outputSFTP_HTML = $OutputSFTPArray -join "<br>"
                                $details = [ordered] @{
                                    Date      = Get-TimeStamp
                                    Protocol  = "SFTP"
                                    SN        = ($value.name)
                                    Localization  = $value.placowka
                                    Status    = $snStatus
                                    Output    = $outputSFTP_HTML
                                }
                
                                ExportToResultsHTML -outputDetails $details
                            }
                
                            #Export do CSV
                            if (!$NoCSV) {
                                $OutputSFTP = ( $OutputSFTP -join [environment]::NewLine )
                                $outputSSH = ( $outputSSH -join [environment]::NewLine )
                                $details = [ordered] @{
                                    Date      = Get-TimeStamp
                                    Protocol  = "SFTP"
                                    SN        = ($value.name)
                                    Localization  = $value.placowka
                                    Status    = $snStatus
                                    Output    = $OutputSFTP
                                }
                
                                ExportToResults -outputDetails $details
                            }

                            #usuniecie plikow SystemReport z serwera
                            Remove-SFTPItem -SessionId $getSSHSessionId -Path '/c:/SystemReport.ps1' -force -Verbose | Out-Null
                            Remove-SFTPItem -SessionId $getSSHSessionId -Path '/c:/SystemReport.html' -force -Verbose | Out-Null
                            $outputSSH = "Removing  `'/C:/SystemReport.ps1`'  and  `'/C:/SystemReport.html`'  from server"

                            #Zakonczenie polaczenia SFTP
                            Write-Output ( -join ("Closing SFTP connection... ", (Remove-SFTPSession -SessionId $getSFTPSessionId)))
                        }
                    }

                    if ($TypeCommand) {
                        #Uruchomienie skryptu
                        Write-output "Processing command..."
                        $outputSSH = (Invoke-SSHCommand -SessionId $getSSHSessionId -Command $executingCommand).Output
                    }

                    if ($PlayerVersion -or $FreeSpace -or $Slides -or $EventLog -or $ReleaseUpdate -or $WindowsActivated) {
                        #Uruchomienie skryptu
                        Write-output "Processing script..."
                        $processedCommand = (Invoke-SSHCommand -SessionId $getSSHSessionId -Command $commandText).output

                        if ($PlayerVersion -or $ReleaseUpdate) {
                            if ($processedCommand[0].trim() -eq $correctMD5_v3) {
                                $outputSSH = "Up-to-date"
                    
                            }
                            else {
                                $outputSSH = "Out-of-date"

                                if ($ReleaseUpdate) {
                                    $outputSSH = ( -join ($outputSSH, ", processing update"))

                                    #Export do HTML
                                    if ($HTML) {
                                        $outputSSH_HTML = $outputSSH -join "<br>"
                                        $details = [ordered] @{
                                            Date      = Get-TimeStamp
                                            Protocol  = "SSH"
                                            SN        = ($value.name)
                                            Localization  = $value.placowka
                                            Status    = $snStatus
                                            Output    = $outputSSH_HTML
                                        }

                                        ExportToResultsHTML -outputDetails $details
                                    }

                                    #Export do CSV
                                    if (!$NoCSV) {
                                        $outputSSH = ( $outputSSH -join [environment]::NewLine )
                                        $details = [ordered] @{
                                            Date      = Get-TimeStamp
                                            Protocol  = "SSH"
                                            SN        = ($value.name)
                                            Localization  = $value.placowka
                                            Status    = $snStatus
                                            Output    = $outputSSH
                                        }

                                        ExportToResults -outputDetails $details
                                    }
                                
                                    #zdjecie playera i wylaczenie Crona
                                    Invoke-SSHCommand -SessionId $getSSHSessionId -Command "Stop-Process -processname snplayer -ErrorAction SilentlyContinue" | Out-Null
                                    Invoke-SSHCommand -SessionId $getSSHSessionId -Command "start-sleep -s 2" | Out-Null
                                    Invoke-SSHCommand -SessionId $getSSHSessionId -Command "& C:\SCREENNETWORK\admin\SNCronOff.ps1" | Out-Null
                                    Invoke-SSHCommand -SessionId $getSSHSessionId -Command "start-sleep -s 3" | Out-Null
                                    Invoke-SSHCommand -SessionId $getSSHSessionId -Command 'Remove-Item -Path "C:\SCREENNETWORK\player\release" -Force -Recurse -ErrorAction SilentlyContinue' | Out-Null

                                    # SFTP
                                    #Nawiazanie polaczenia
                                    New-SFTPSession -ComputerName $snIP -Credential $credential -KeyFile $authenticationKey -ConnectionTimeout 120 -force | out-null
                                    $getSFTPSessionId = (Get-SFTPSession | Where-Object { $_.Host -eq $snIP }).SessionId    
                                    if ((Get-SFTPSession | Where-Object { $_.Host -eq $snIP }).Connected -eq $true) {
                                        Write-Host "SFTP Connected!" -ForegroundColor Green
                                    }

                                    #Przeslanie pliku
                                    Set-SFTPFile -SessionId $getSFTPSessionId -RemotePath /c:/screennetwork/player/ -LocalFile $filePath -verbose
                                    $OutputSFTP = ( -join ("Uploading '", $filePath, "' to '", "/c:/screennetwork/player/", "`'"))

                                    #Export do HTML
                                    if ($HTML) {
                                        $outputSFTP_HTML = $OutputSFTP -join "<br>"
                                        $details = [ordered] @{
                                            Date      = Get-TimeStamp
                                            Protocol  = "SFTP"
                                            SN        = ($value.name)
                                            Localization  = $value.placowka
                                            Status    = $snStatus
                                            Output    = $outputSFTP_HTML
                                        }
                
                                        ExportToResultsHTML -outputDetails $details
                                    }
                
                                    #Export do CSV
                                    if (!$NoCSV) {
                                        $OutputSFTPArray = ( $OutputSFTP -join [environment]::NewLine )
                                        $details = [ordered] @{
                                            Date      = Get-TimeStamp
                                            Protocol  = "SFTP"
                                            SN        = ($value.name)
                                            Localization  = $value.placowka
                                            Status    = $snStatus
                                            Output    = $OutputSFTPArray
                                        }
                
                                        ExportToResults -outputDetails $details
                                    }
                                       
                                    ExportToResults -outputDetails $details

                                    #Zakonczenie polaczenia SFTP
                                    Write-Output ( -join ("Closing SFTP connection... ", (Remove-SFTPSession -SessionId $getSFTPSessionId)))
                                
                                    #Rozpakowanie zipa z release
                                    Invoke-SSHCommand -SessionId $getSSHSessionId -Command "Expand-Archive -Path C:\SCREENNETWORK\player\release.zip -Destination C:\SCREENNETWORK\player" | Out-Null
                                    Invoke-SSHCommand -SessionId $getSSHSessionId -Command "Remove-Item -Path C:\SCREENNETWORK\player\Release.zip -force" | Out-Null
                                    Invoke-SSHCommand -SessionId $getSSHSessionId -Command "Clear-RecycleBin -Confirm:$false -ErrorAction SilentlyContinue" | Out-Null   
                                    Invoke-SSHCommand -SessionId $getSSHSessionId -Command "& C:\SCREENNETWORK\admin\SNCronOn.ps1" | Out-Null    
                                    Start-Sleep -s 2

                                    if ($null -ne (Invoke-SSHCommand -SessionId $getSSHSessionId -Command "Get-Process -processname SNPlayer").output) {
                                        $outputSSH = "Realease successfully updated!"
                                    }
                                }
                            }
                        }

                        if ($FreeSpace) {
                            $processedCommand = $processedCommand -as [string]
                            $outputSSH = $processedCommand.Substring(0, $processedCommand.IndexOf(','))
                            $outputSSH = ( -join ($outputSSH, " GB"))
                        }

                        if ($Slides) {
                            $outputSSH = $processedCommand[0] -as [int]
                        }

                        if ($EventLog) {
                            $eventlogFileName = ( -join (($value.name), "_EventLOG"))
                            $eventLogFile = ( -join ($eventLogFolder, "\", $eventlogFileName, ".csv"))
                            $processedCommand | Out-File -Encoding "UTF8" $eventLogFile
                            $outputSSH = "Downloaded last 50 event logs"
                        }

                        if ($WindowsActivated) {
                            $processedCommand = $processedCommand[0] -as [int]
                            switch ($processedCommand) {
                                0 { $Status = "Unlicensed" }
                                1 { $Status = "Licensed" }
                                default { $Status = "Problem with licesne" }
                            }
                            $outputSSH = $Status
                        }

                    }

                    if ($ScriptSendAndRun) {
                        Invoke-SSHCommand -SessionId $getSSHSessionId -Command ( -join ("remove-item -path ", $executingScriptPath, " -force -erroraction silentlycontinue")) -Verbose | out-null
                    }

                    #Zakonczenie polaczenia
                    Write-Output ( -join ("Closing SSH connection... ", (Remove-SSHSession -SessionId $getSSHSessionId)))
                }
            }
            catch [Exception] {
                Write-Host "An error occurred:" -ForegroundColor Red
                     
                if ($_.Exception.Message -eq "No connection could be made because the target machine actively refused it") {
                    Write-Host "SSH is not installed on this server" -ForegroundColor Red
                    $outputSSH = "SSH is not installed on this server"
                }
                elseif($_.Exception.Message -eq "A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond") {
                    Write-Host "Server is not connected through the VPN" -ForegroundColor Red
                    $outputSSH = "Server is not connected through the VPN"
                } 
                else {
                    Write-Host $_.Exception.Message -ForegroundColor Red
                    $outputSSH = $_.Exception.Message
                }
                $snStatus = "ERROR"
            }  

            if (($null -or "") -eq $outputSSH) {
                $outputSSH = "No output"
            }
                
            #Export do HTML
            if ($HTML) {
                $outputSSH_HTML = $outputSSH -join "<br>"
                $details = [ordered] @{
                    Date      = Get-TimeStamp
                    Protocol  = "SSH"
                    SN        = ($value.name)
                    Localization  = $value.placowka
                    Status    = $snStatus
                    Output    = $outputSSH_HTML
                }

                ExportToResultsHTML -outputDetails $details
            }

            #Export do CSV
            if (!$NoCSV) {
                $outputSSH = ( $outputSSH -join [environment]::NewLine )
                $details = [ordered] @{
                    Date      = Get-TimeStamp
                    Protocol  = "SSH"
                    SN        = ($value.name)
                    Localization  = $value.placowka
                    Status    = $snStatus
                    Output    = $outputSSH
                }

                ExportToResults -outputDetails $details
            }
        }

        #Czyszczenie zmiennych
        $snIP = $null
        $outputSSH = $null
        $outputSSH_HTML = $null
        $OutputSFTP = $null
        $outputSSH_HTML = $null
        "`n"
    }
    #Maszyna jest niepołączona 
    else {
        Write-Host "Not connected!" -ForegroundColor Red
        "`n"

        #Export do HTML
        if ($HTML) {
            $details = [ordered] @{
                Date      = Get-TimeStamp
                Protocol  = "-"
                SN        = ($value.name)
                Localization  = $value.placowka
                Status    = "Not connected"
                Output    = "-"
            }

            ExportToResultsHTML -outputDetails $details
        }

        #Export do CSV
        if (!$NoCSV) {
            $details = [ordered] @{
                Date      = Get-TimeStamp
                Protocol  = "-"
                SN        = ($value.name)
                Localization  = $value.placowka
                Status    = "Not connected"
                Output    = "-"
            }

            ExportToResults -outputDetails $details
        }
    }
}

if ($HTML) {
    $toDecode = $global:resultsHTML | ConvertTo-Html -Title "SNScript LOG" -Head $styles -PreContent ("<center><h2><b>Raport SNScript - " + (Get-Date) + "</b></h2><br>Plik .json: " + $PathSNJson + "<br><br></center>")
    [System.Web.HttpUtility]::HtmlDecode($toDecode) | Set-Content $LogFileHTML 
    invoke-item $LogFileHTML
}

if (!$NoCSV) {
    $global:results | export-csv -Path $LogFile -NoTypeInformation -UseCulture -Encoding Default
    invoke-item $logFile
}

#Usuniecie folderu z plikami tymczasowymi
if (Test-Path -Path "c:\temp") {
    Remove-Item -Path "c:\temp" -Force -Recurse -ErrorAction SilentlyContinue
}