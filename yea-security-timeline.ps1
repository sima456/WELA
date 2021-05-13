<#
.SYNOPSIS
Fast forensics timeline generator for the Windows security event log.

.DESCRIPTION
The YEA security event timeline generator is a fast Forensics PowerShell module to create easy to analyze and as noise-free as possible event timeline for the Windows security log.

.Example
Process the local Windows security event log (Need to run with Administrator privileges):
.\yea-security-timeline.ps1

.Example
Process an offline Windows security event log:

.\DeepBlue.ps1 -path E:\logs\Security.evtx

.LINK
https://github.com/yamatosecurity
#>

# Yamato Event Analyzer (YEA) Security event timeline generator
# Zach Mathis, Yamatosecurity founder
# Twitter: @yamatosecurity
# https://yamatosecurity.connpass.com/
# 
# Inspired by Eric Conrad's DeepBlueCLI (https://github.com/sans-blue-team/DeepBlueCLI)
# Much help from the Windows Event Log Analysis Cheatsheets by Steve Anson (https://www.forwarddefense.com/en/article/references-pdf)

param (
    [bool]$Japanese = $false,
    [bool]$USDateFormat = $false,
    [bool]$EuropeDateFormat = $false,
    [string]$SaveOutput = "",
    [string]$StartTimeline = "",
    [string]$EndTimeline = "",
    [bool]$IsDC = $false,
    [bool]$ShowLogonID = $false,
    [bool]$LiveAnalysis = $false,
    [string]$LogFile = "",
    [bool]$ShowContributors = $false,
    [bool]$EventIDStatistics =  $false,
    [bool]$LogonOverview = $false,
    [bool]$AccountInformation = $false
)

$ProgramStartTime = Get-Date


#Functions:
function Show-Contributors {
    Write-Host 
    Write-Host "Currently there are no conributors."
    Write-Host "Please contribute to this project for fame and glory!"
    Write-Host
}


function Logon-Number-To-String($msgLogonType) {
    switch ( $msgLogonType ) {
        "0" { $msgLogonTypeReadable = "System" }
        "2" { $msgLogonTypeReadable = "Interactive" }
        "3" { $msgLogonTypeReadable = "Network" }
        "4" { $msgLogonTypeReadable = "Batch" }
        "5" { $msgLogonTypeReadable = "Service" }
        "7" { $msgLogonTypeReadable = "Unlock" }
        "8" { $msgLogonTypeReadable = "NetworkCleartext" }
        "9" { $msgLogonTypeReadable = "NewCredentials" }
        "10" { $msgLogonTypeReadable = "RemoteInteractive" }
        "11" { $msgLogonTypeReadable = "CachedInteractive" }
        "12" { $msgLogonTypeReadable = "CachedRemoteInteractive" }
        "13" { $msgLogonTypeReadable = "CachedUnlock" }
        default { $msgLogonTypeReadable = "Unknown" }
    }

    return $msgLogonTypeReadable
}

function Is-Logon-Dangerous ( $msgLogonType ) {
    switch ( $msgLogonType ) {
        "0" { $msgIsLogonDangerous = "" }
        "2" { $msgIsLogonDangerous = "(Dangerous! Credential information is stored in memory and maybe be stolen for account hijacking.)" }
        "3" { $msgIsLogonDangerous = "" }
        "4" { $msgIsLogonDangerous = "" }
        "5" { $msgIsLogonDangerous = "" }
        "7" { $msgIsLogonDangerous = "" }
        "8" { $msgIsLogonDangerous = "(Dangerous! Unhashed passwords were used for authentication.)"}
        "9" { $msgIsLogonDangerous = "(Dangerous! Credential information is stored in memory and maybe be stolen for account hijacking.)" }
        "10" { $msgIsLogonDangerous = "(Dangerous! Credential information is stored in memory and maybe be stolen for account hijacking.)" }
        "11" { $msgIsLogonDangerous = "" }
        "12" { $msgIsLogonDangerous = "" }
        "13" { $msgIsLogonDangerous = "" }
        default { $msgIsLogonDangerous = "" }
    }

    return $msgIsLogonDangerous
}

function Is-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

Function Format-FileSize {
    Param ([int]$size)
    If ($size -gt 1TB) {[string]::Format("{0:0.00} TB", $size / 1TB)}
    ElseIf ($size -gt 1GB) {[string]::Format("{0:0.00} GB", $size / 1GB)}
    ElseIf ($size -gt 1MB) {[string]::Format("{0:0.00} MB", $size / 1MB)}
    ElseIf ($size -gt 1KB) {[string]::Format("{0:0.00} kB", $size / 1KB)}
    ElseIf ($size -gt 0) {[string]::Format("{0:0.00} B", $size)}
    Else {""}
}

function Check-Administrator  
{  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}


#Global variables

$YEAVersion = "0.1"

$EventIDsToAnalyze = "4624,4625,4672,4634,4647,4720,4732,1102,4648,4776"
# Logs to filter for:
# 4624 - LOGON
# 4625 - FAILED LOGON
# 4672 - ADMIN LOGON (Special privileges assigned to a new logon)
# 4634 - LOGOFF
# 4647 - LOGOFF
# 4720 - User account created
# 4732 - User added to group
# 1102 - LOG CLEARED
# 4648 - EXPLICIT LOGON
# 4776 - NTLM LOGON TO LOCAL ACCOUNT (TODO)

# Additional logs to filter for if a DC
# 4768 - TGT ISSUED
# 4769 - SERVICE TICKET ISSUED
# 4776 - NTLM auth. non-standard tool used?

$TotalLogsNoFilters = 0
$BadWorkstations = @("kali", "SLINGSHOT") #Highlight with the red alert background when the workstation comes from a pentesting distro.

#Set the output colors
#16 possible colors are Black, DarkBlue, DarkGreen, DarkCyan, DarkRed, DarkMagenta, DarkYellow, Gray, DarkGray, Blue, Green, Cyan, Red, Magenta, Yellow, White
#Only 6 readable colors with default black background: Green, Red, Cyan, Magenta, Gray, Yellow

$EventID_4624_Color = "Green"       #Successful logon
$EventID_4648_Color = "Yellow"       #Explicit logon to another user
$EventID_4672_Color = "Yellow"       #Admin logon
$EventID_4625_Color = "Red"         #Failed logon 
$EventID_4634_Color = "Gray"        #Logoff
$EventID_4647_Color = "Gray"        #Logoff
$EventID_4720_Color = "Yellow"     #Account Created
$EventID_4732_Color = "Yellow"     #User added to a group
$EventID_1102_Color = "Red"     #Log cleared
$ParameterColor = "Cyan"

$LogNoise = 0
$TotalPiecesOfData = 0
$AlertedEvents = 0
$SkippedLogs = 0
$TotalLogs = 0

$HostLanguage = Get-WinSystemLocale | Select-Object Name


#Set the date format
$DateFormat = "yyyy-MM-dd HH:mm:ss.ff"

if ( $USDateFormat -eq $true ) {
    $DateFormat = "MM/dd/yyyy HH:mm:ss.ff"
} 

if ( $EuropeDateFormat -eq $true ) {
    $DateFormat = "dd.MM.yyyy HH:mm:ss.ff"
} 

function EventInfo ($eventIDNumber) {
    
    [hashtable]$return = @{}

    if ( $HostLanguage.Name -eq "ja-JP" -or $Japanese -eq $true ) {

        switch ( $eventIDNumber ) {
            "1100" { $EventTitle = 'イベント ログ サービスがシャットダウンしました。' }   
            "1101" { $EventTitle = 'Audit Events Have Been Dropped By The Transport' }
            "1102" { $EventTitle = 'Event log was cleared' ; $TimelineDetect = "Yes" ; $Comment = 'Should not happen normally so this is a good event to look out for.' }
            "1107" { $EventTitle = 'Event processing error' }
            "4608" { $EventTitle = 'Windows started up' }
            "4610" { $EventTitle = 'An authentication package has been loaded by the Local Security Authority' }
            "4611" { $EventTitle = 'A trusted logon process has been registered with the Local Security Authority' }
            "4614" { $EventTitle = 'A notification package has been loaded by the Security Account Manager' }
            "4616" { $EventTitle = 'System time was changed' }
            "4622" { $EventTitle = 'A security package has been loaded by the Local Security Authority' }
            "4624" { $EventTitle = 'Account logon' ; $TimelineDetect = "Yes" }
            "4625" { $EventTitle = 'Failed logon' ; $TimelineDetect = "Yes" }
            "4634" { $EventTitle = 'Logoff' ; $TimelineDetect = "Yes" } 
            "4647" { $EventTitle = 'Logoff' ; $TimelineDetect = "Yes" }  
            "4648" { $EventTitle = 'Explicit logon' ; $TimelineDetect = "Yes" }
            "4672" { $EventTitle = 'Admin logon' ; $TimelineDetect = "Yes" }
            "4688" { $EventTitle = 'New process started' }
            "4696" { $EventTitle = 'Primary token assigned to process' }
            "4692" { $EventTitle = 'Backup of data protection master key was attempted' }
            "4697" { $EventTitle = 'Service installed' }
            "4717" { $EventTitle = 'System security access was granted to an account' }
            "4719" { $EventTitle = 'System audit policy was changed' }
            "4720" { $EventTitle = 'User account created' ; $TimelineDetect = "Yes" }
            "4722" { $EventTitle = 'User account enabled' }  
            "4724" { $EventTitle = 'Password reset' }  
            "4725" { $EventTitle = 'User account disabled' }
            "4726" { $EventTitle = 'User account deleted' } 
            "4728" { $EventTitle = 'User added to security global group' }
            "4729" { $EventTitle = 'User removed from security global group' }
            "4732" { $EventTitle = 'User added to security local group' }
            "4733" { $EventTitle = 'User removed from security local group' }
            "4735" { $EventTitle = 'Security local group was changed' }
            "4727" { $EventTitle = 'Security global group was changed' }
            "4738" { $EventTitle = 'User account''s properties changed' }
            "4739" { $EventTitle = 'Domain policy channged' }
            "4776" { $EventTitle = 'NTLM logon to local user' }
            "4778" { $EventTitle = 'RDP session reconnected or user switched back through Fast Userr Switching' }
            "4779" { $EventTitle = 'RDP session disconnected or user switched away through Fast User Switching' }
            "4797" { $EventTitle = 'Attempt to query the account for a blank password' }  
            "4798" { $EventTitle = 'User''s local group membership was enumerated' }
            "4799" { $EventTitle = 'Local group membership was enumerated' } 
            "4781" { $EventTitle = 'User name was changed' }
            "4800" { $EventTitle = 'Workstation was locked' }
            "4801" { $EventTitle = 'Workstation was unlocked' }
            "4826" { $EventTitle = 'Boot configuration data loaded' }
            "4902" { $EventTitle = 'Per-user audit policy table was created' } 
            "4904" { $EventTitle = 'Attempt to register a security event source' }
            "4905" { $EventTitle = 'Attempt to unregister a security event source' } 
            "4907" { $EventTitle = 'Auditing settings on object was changed' } 
            "4944" { $EventTitle = 'Policy active when firewall started' }
            "4945" { $EventTitle = 'Rule listed when the firewall started' ; $Comment = "Too much noise when firewall starts" }
            "4946" { $EventTitle = 'Rule added to firewall exception list' }
            "4947" { $EventTitle = 'Rule modified in firewall exception list' }
            "4948" { $EventTitle = 'Rule deleted in firewall exception list' }
            "4954" { $EventTitle = 'New setting applied to firewall group policy' }
            "4956" { $EventTitle = 'Firewall active profile changed' }
            "5024" { $EventTitle = 'Firewall started' }
            "5033" { $EventTitle = 'Firewall driver started' } 
            "5038" { $EventTitle = 'Code integrity determined that the image hash of a file is not valid' }
            "5058" { $EventTitle = 'Key file operation' } 
            "5059" { $EventTitle = 'Key migration operation' }
            "5061" { $EventTitle = 'Cryptographic operation' } 
            "5140" { $EventTitle = 'Network share object was accessed' }
            "5142" { $EventTitle = 'A network share object was added' }
            "5144" { $EventTitle = 'A network share object was deleted' }
            "5379" { $EventTitle = 'Credential Manager credentials were read' }
            "5381" { $EventTitle = 'Vault credentials were read' }
            "5382" { $EventTitle = 'Vault credentials were read' }
            "5478" { $EventTitle = 'IPsec Services started' }
            "5889" { $EventTitle = 'An object was added to the COM+ Catalog' }
            "5890" { $EventTitle = 'An object was added to the COM+ Catalog' }
            default { $EventTitle = "不明" }

        }
    }
    
    else {
        
        switch ( $eventIDNumber ) {
            "1100" { $EventTitle = 'Event logging service was shut down' ; $Comment = 'Good for finding signs of anti-forensics but most likely false positives when the system shuts down.' }  
            "1101" { $EventTitle = 'Audit Events Have Been Dropped By The Transport' }
            "1102" { $EventTitle = 'Event log was cleared' ; $TimelineDetect = "Yes" ; $Comment = 'Should not happen normally so this is a good event to look out for.' }
            "1107" { $EventTitle = 'Event processing error' }
            "4608" { $EventTitle = 'Windows started up' }
            "4610" { $EventTitle = 'An authentication package has been loaded by the Local Security Authority' }
            "4611" { $EventTitle = 'A trusted logon process has been registered with the Local Security Authority' }
            "4614" { $EventTitle = 'A notification package has been loaded by the Security Account Manager' }
            "4616" { $EventTitle = 'System time was changed' }
            "4622" { $EventTitle = 'A security package has been loaded by the Local Security Authority' }
            "4624" { $EventTitle = 'Account logon' ; $TimelineDetect = "Yes" }
            "4625" { $EventTitle = 'Failed logon' ; $TimelineDetect = "Yes" }
            "4634" { $EventTitle = 'Logoff' ; $TimelineDetect = "Yes" } 
            "4647" { $EventTitle = 'Logoff' ; $TimelineDetect = "Yes" }  
            "4648" { $EventTitle = 'Explicit logon' ; $TimelineDetect = "Yes" }
            "4672" { $EventTitle = 'Admin logon' ; $TimelineDetect = "Yes" }
            "4688" { $EventTitle = 'New process started' }
            "4696" { $EventTitle = 'Primary token assigned to process' }
            "4692" { $EventTitle = 'Backup of data protection master key was attempted' }
            "4697" { $EventTitle = 'Service installed' }
            "4717" { $EventTitle = 'System security access was granted to an account' }
            "4719" { $EventTitle = 'System audit policy was changed' }
            "4720" { $EventTitle = 'User account created' ; $TimelineDetect = "Yes" }
            "4722" { $EventTitle = 'User account enabled' }  
            "4724" { $EventTitle = 'Password reset' }  
            "4725" { $EventTitle = 'User account disabled' }
            "4726" { $EventTitle = 'User account deleted' } 
            "4728" { $EventTitle = 'User added to security global group' }
            "4729" { $EventTitle = 'User removed from security global group' }
            "4732" { $EventTitle = 'User added to security local group' }
            "4733" { $EventTitle = 'User removed from security local group' }
            "4735" { $EventTitle = 'Security local group was changed' }
            "4727" { $EventTitle = 'Security global group was changed' }
            "4738" { $EventTitle = 'User account''s properties changed' }
            "4739" { $EventTitle = 'Domain policy channged' }
            "4776" { $EventTitle = 'NTLM logon to local user' }
            "4778" { $EventTitle = 'RDP session reconnected or user switched back through Fast Userr Switching' }
            "4779" { $EventTitle = 'RDP session disconnected or user switched away through Fast User Switching' }
            "4797" { $EventTitle = 'Attempt to query the account for a blank password' }  
            "4798" { $EventTitle = 'User''s local group membership was enumerated' }
            "4799" { $EventTitle = 'Local group membership was enumerated' } 
            "4781" { $EventTitle = 'User name was changed' }
            "4800" { $EventTitle = 'Workstation was locked' }
            "4801" { $EventTitle = 'Workstation was unlocked' }
            "4826" { $EventTitle = 'Boot configuration data loaded' }
            "4902" { $EventTitle = 'Per-user audit policy table was created' } 
            "4904" { $EventTitle = 'Attempt to register a security event source' }
            "4905" { $EventTitle = 'Attempt to unregister a security event source' } 
            "4907" { $EventTitle = 'Auditing settings on object was changed' } 
            "4944" { $EventTitle = 'Policy active when firewall started' }
            "4945" { $EventTitle = 'Rule listed when the firewall started' ; $Comment = "Too much noise when firewall starts" }
            "4946" { $EventTitle = 'Rule added to firewall exception list' }
            "4947" { $EventTitle = 'Rule modified in firewall exception list' }
            "4948" { $EventTitle = 'Rule deleted in firewall exception list' }
            "4954" { $EventTitle = 'New setting applied to firewall group policy' }
            "4956" { $EventTitle = 'Firewall active profile changed' }
            "5024" { $EventTitle = 'Firewall started' }
            "5033" { $EventTitle = 'Firewall driver started' } 
            "5038" { $EventTitle = 'Code integrity determined that the image hash of a file is not valid' }
            "5058" { $EventTitle = 'Key file operation' } 
            "5059" { $EventTitle = 'Key migration operation' }
            "5061" { $EventTitle = 'Cryptographic operation' } 
            "5140" { $EventTitle = 'Network share object was accessed' }
            "5142" { $EventTitle = 'A network share object was added' }
            "5144" { $EventTitle = 'A network share object was deleted' }
            "5379" { $EventTitle = 'Credential Manager credentials were read' }
            "5381" { $EventTitle = 'Vault credentials were read' }
            "5382" { $EventTitle = 'Vault credentials were read' }
            "5478" { $EventTitle = 'IPsec Services started' }
            "5889" { $EventTitle = 'An object was added to the COM+ Catalog' }
            "5890" { $EventTitle = 'An object was added to the COM+ Catalog' }
            default { $EventTitle = "Unknown" }
        }
    }

    $return.EventTitle = $EventTitle
    $return.Comment = $Comment
    $return.TimelineDetect = $TimelineDetect
    return $return
}


function Create-EventIDStatistics {

    #TODO:
    # - Implement save-output
    # - Add comments to event IDs
    # - Explicitly output results in a table
    # - Translate everything

    Write-Host
    Write-Host "Creating Event ID Statistics"
    Write-Host "Please be patient."
    Write-Host
    
    $WineventFilter = @{}
    
    if ( $StartTimeline -ne "" ) { 
        $StartTimeline = [DateTime]::ParseExact($StartTimeline, 'yyyy-MM-dd HH:mm:ss', $null) 
        $WineventFilter.Add( "StartTime" , $StartTimeline )   
    }

    if ( $EndTimeline -ne "" ) { 
        $EndTimeline = [DateTime]::ParseExact($EndTimeline, 'yyyy-MM-dd HH:mm:ss', $null) 
        $WineventFilter.Add( "EndTime" , $EndTimeline )
    }

    #Live Analysis
    if ( $LogFile -eq "" ) {

        $WineventFilter.Add("LogName", "Security")
        $logs = Get-WinEvent -FilterHashtable $WineventFilter -Oldest
        $eventlist = @{}
        $TotalNumberOfLogs = 0

        foreach( $event in $logs ) {

            $id = $event.id.toString()

            if ( $eventlist[$id] -eq $null ) {

                $eventlist[$id] = 1

            } 
            
            else {

                $eventlist[$id] += 1
            }

            $TotalNumberOfLogs++
        }

        #Print results
        $filesize = Format-FileSize( (get-item "C:\Windows\System32\winevt\Logs\Security.evtx").length )
        $FirstEventTimestamp = $logs[0].TimeCreated.ToString($DateFormat) 
        $LastEventTimestamp = $logs[-1].TimeCreated.ToString($DateFormat)  
    
        Write-Host "Total Event Logs: $TotalNumberOfLogs"
        Write-Host "File Size: $filesize"
        Write-Host "First event: $FirstEventTimestamp"
        Write-Host "Last event: $LastEventTimestamp"
    
        $sorted = $eventlist.GetEnumerator() | sort Value -Descending    #sorted gets turn into an array    
        [System.Collections.ArrayList]$ArrayWithHeader = @()
        
        for ( $i = 0 ; $i -le $sorted.count ; $i++) {
                 
            $Name = $sorted[$i].Name
            $Value = $sorted[$i].Value
            $EventInfo = EventInfo($Name)
            $PercentOfLogs = [math]::Round( ( $Value / $TotalNumberOfLogs * 100 ), 1 )
            $CountPlusPercent = "$value ($PercentOfLogs%)" 
            $val = [pscustomobject]@{'Count' = $CountPlusPercent ; 'ID' = $Name ; 'Event' = $EventInfo.EventTitle ; 'Timeline Detection' = $EventInfo.TimelineDetect } #; 'Comment' = $EventInfo.Comment
            $ArrayWithHeader.Add($val) > $null

        }

        $ProgramEndTime = Get-Date
        $TotalRuntime = [math]::Round(($ProgramEndTime - $ProgramStartTime).TotalSeconds)
        $TempTimeSpan = New-TimeSpan -Seconds $TotalRuntime
        $RuntimeHours = $TempTimeSpan.Hours.ToString()
        $RuntimeMinutes = $TempTimeSpan.Minutes.ToString()
        $RuntimeSeconds = $TempTimeSpan.Seconds.ToString()

        Write-Host
        Write-Host "Processing time: $RuntimeHours hours $RuntimeMinutes minutes $RuntimeSeconds seconds"

        $ArrayWithHeader

    }

    #Offline Log Analysis
    Else {

        $WineventFilter.Add( "Path", $LogFile ) 
        $logs = Get-WinEvent -FilterHashtable $WineventFilter -Oldest
        $eventlist = @{}
        $TotalNumberOfLogs = 0

        foreach( $event in $logs ) {

            $id = $event.id.toString()

            if ( $eventlist[$id] -eq $null ) {

                $eventlist[$id] = 1

            } 
            
            else {

                $eventlist[$id] += 1

            }

            $TotalNumberOfLogs++

        }

        #Print results        
        $filesize = Format-FileSize( (get-item $LogFile).length )
        $FirstEventTimestamp = $logs[0].TimeCreated.ToString($DateFormat) 
        $LastEventTimestamp = $logs[-1].TimeCreated.ToString($DateFormat)  

        Write-Host "Total Event Logs: $TotalNumberOfLogs"
        Write-Host "File Size: $filesize"
        Write-Host "First event: $FirstEventTimestamp"
        Write-Host "Last event: $LastEventTimestamp"
    
        $sorted = $eventlist.GetEnumerator() | sort Value -Descending    #sorted gets turn into an array    
        [System.Collections.ArrayList]$ArrayWithHeader = @()
        
        for ( $i = 0 ; $i -le $sorted.count ; $i++) {
                 
            $Name = $sorted[$i].Name
            $Value = $sorted[$i].Value
            $EventInfo = EventInfo($Name)
            $PercentOfLogs = [math]::Round( ( $Value / $TotalNumberOfLogs * 100 ), 1 )
            $CountPlusPercent = "$value ($PercentOfLogs%)" 
            $val = [pscustomobject]@{'Count' = $CountPlusPercent ; 'ID' = $Name ; 'Event' = $EventInfo.EventTitle ; 'Timeline Detection' = $EventInfo.TimelineDetect } #; 'Comment' = $EventInfo.Comment
            $ArrayWithHeader.Add($val) > $null

        }

        $ProgramEndTime = Get-Date
        $TotalRuntime = [math]::Round(($ProgramEndTime - $ProgramStartTime).TotalSeconds)
        $TempTimeSpan = New-TimeSpan -Seconds $TotalRuntime
        $RuntimeHours = $TempTimeSpan.Hours.ToString()
        $RuntimeMinutes = $TempTimeSpan.Minutes.ToString()
        $RuntimeSeconds = $TempTimeSpan.Seconds.ToString()

        Write-Host
        Write-Host "Processing time: $RuntimeHours hours $RuntimeMinutes minutes $RuntimeSeconds seconds"

        $ArrayWithHeader

    }


}

function Create-LogonOverview {

    Write-Host
    Write-Host "Creating Logon Overview"
    Write-Host "Please be patient."
    Write-Host
    
    $WineventFilter = @{}
    $EventIDsToAnalyze = 4624,4634,4647
    $WineventFilter.Add("ID", $EventIDsToAnalyze)
    
    if ( $StartTimeline -ne "" ) { 
        $StartTimeline = [DateTime]::ParseExact($StartTimeline, 'yyyy-MM-dd HH:mm:ss', $null) 
        $WineventFilter.Add( "StartTime" , $StartTimeline )   
    }

    if ( $EndTimeline -ne "" ) { 
        $EndTimeline = [DateTime]::ParseExact($EndTimeline, 'yyyy-MM-dd HH:mm:ss', $null) 
        $WineventFilter.Add( "EndTime" , $EndTimeline )
    }

    #Live Analysis
    if ( $LogFile -eq "" ) {

        $WineventFilter.Add("LogName", "Security")
        $logs = Get-WinEvent -FilterHashtable $WineventFilter -Oldest
        $eventlist = @{}
        $TotalNumberOfLogs = 0

        [System.Collections.ArrayList]$ArrayWithHeader = @()

        foreach( $event in $logs ) {
            
            #Successful logon
            if ($event.Id -eq "4624"){ 

                $eventXML = [xml]$event.ToXml()

                foreach($data in $eventXML.Event.EventData.data){
            
                    switch ( $data.name ){
                        
                        "LogonType" { $msgLogonType = $data.'#text' }
                        "TargetUserName" { $msgTargetUserName = $data.'#text' }
                        "WorkstationName" { $msgWorkstationName = $data.'#text' }
                        "IpAddress" { $msgIpAddress = $data.'#text' }
                        "IpPort" { $msgIpPort = $data.'#text' }
                        "TargetLogonID" { $msgTargetLogonID = $data.'#text' }  
                    }
                }

                $msgLogonTypeReadable = Logon-Number-To-String($msgLogonType) #Convert logon numbers to readable strings
                $msgIsLogonDangerous = Is-Logon-Dangerous($msgLogonType) #Check to see if the logon was dangerous (saving credentials in memory)
                $Timestamp = $event.TimeCreated.ToString($DateFormat) 
                $val = [pscustomobject]@{'Timestamp' = $timestamp ; 'ID' = $Name ; 'Event' = $EventInfo.EventTitle ; 'Timeline Detection' = $EventInfo.TimelineDetect }
                $ArrayWithHeader.Add($val) > $null
            }

            #Logoff
            if ($event.Id -eq "4634"){ 

                $eventXML = [xml]$event.ToXml()

                foreach($data in $eventXML.Event.EventData.data){
            
                    switch ( $data.name ){
                        
                        "LogonType" { $msgLogonType = $data.'#text' }
                        "TargetUserName" { $msgTargetUserName = $data.'#text' }
                        "WorkstationName" { $msgWorkstationName = $data.'#text' }
                        "IpAddress" { $msgIpAddress = $data.'#text' }
                        "IpPort" { $msgIpPort = $data.'#text' }
                        "TargetLogonID" { $msgTargetLogonID = $data.'#text' }  
                    }
                }
            
        
                $msgLogonTypeReadable = Logon-Number-To-String($msgLogonType) #Convert logon numbers to readable strings
                $msgIsLogonDangerous = Is-Logon-Dangerous($msgLogonType) #Check to see if the logon was dangerous (saving credentials in memory)
                $timestamp = $event.TimeCreated.ToString($DateFormat) 
            }

            #Logoff
            if ($event.Id -eq "4647"){ 

                $eventXML = [xml]$event.ToXml()

                foreach($data in $eventXML.Event.EventData.data){
            
                    switch ( $data.name ){
                        
                        "LogonType" { $msgLogonType = $data.'#text' }
                        "TargetUserName" { $msgTargetUserName = $data.'#text' }
                        "WorkstationName" { $msgWorkstationName = $data.'#text' }
                        "IpAddress" { $msgIpAddress = $data.'#text' }
                        "IpPort" { $msgIpPort = $data.'#text' }
                        "TargetLogonID" { $msgTargetLogonID = $data.'#text' }  
                    }
                }
            
        
                $msgLogonTypeReadable = Logon-Number-To-String($msgLogonType) #Convert logon numbers to readable strings
                $msgIsLogonDangerous = Is-Logon-Dangerous($msgLogonType) #Check to see if the logon was dangerous (saving credentials in memory)
                $timestamp = $event.TimeCreated.ToString($DateFormat) 
            }
      
            $TotalNumberOfLogs++
        }



    }

    #Offline Log Analysis
    Else {
    
    }

}

function Create-Timeline{

if ( $LogFile -eq "" ) {

    If ( $StartTimeline -eq "" -and $EndTimeline -eq "" ) { #No dates specified
        $filter = "@{Logname=""Security"";ID=$EventIDsToAnalyze}"
        #$filter = @{}
        #$filter.Add("LogName", "Security")
        #$filter.Add("ID", $EventIDsToAnalyze)
    }
    
    ElseIf ( $StartTimeline -ne "" -and $EndTimeline -eq "" ) {  #Start date specified but no end date
        
        $StartingTime = [DateTime]::ParseExact($StartTimeline, 'yyyy-MM-dd', $null)

        $filter = @{}
        $filter.Add("StartTime", $StartingTime)
        $filter.Add("LogName", "Security")
        #$filter.Add("ID", "4624,4625,4672,4634,4647,4720,4732,1102,4648") #filtering on IDs does not work when specifying a start date..
        
        #$filter = "@{Logname=""Security"";StartDate=$StartingTime}"
    }



    <#
    TODO: fix starttimeline and endtimeline
    If ( $StartTimeline -eq "" -and $EndTimeline -ne "" ) {  #Start date specified but no end date
        
        $StartingTime = [DateTime]::ParseExact($StartTimeline, 'yyyy-MM-dd', $null)

        $filter = @{}
        $filter.Add("StartTime", $StartingTime)
        $filter.Add("LogName", "Security")
        #$filter.Add("ID", "4624,4625,4672,4634,4647,4720,4732,1102,4648") #filter not working when specifying a start date..
        
        #$filter = "@{Logname=""Security"";ID=$EventIDsToAnalyze;StartTime=$yesterday;EndTime=(Get-Date)}"
    }
    #>
    

    try {
        if ( $LogFile -eq "" ) {
            Write-Host
            Write-Host "Running a live scan on the Security event log"
            Write-Host

            $logs = iex "Get-WinEvent $filter -Oldest -ErrorAction Stop"

        }
 
        #Bug: starttime not working: can filter on IDs when 
        #$filter = "@{Logname=""Security"";ID=$EventIDsToAnalyze}"
        #and $logs = iex "Get-WinEvent -FilterHashTable $filter -Oldest -ErrorAction Stop"
        #when is change to $logs Get-WinEvent -FilterHashTable $filter -Oldest -ErrorAction Stop   I get
        #Get-WinEvent error:  Cannot bind parameter 'FilterHashtable'. Cannot convert the "@{Logname="Security";ID=4624,4625,4672,4634,4647,4720,4732,1102,4648}" value of type "System.String" to type "System.Collections.Hashtable".
        #filter.add method gives me Get-WinEvent error:  Cannot bind parameter 'FilterHashtable'. Cannot convert the "System.Collections.Hashtable" value of type "System.String" to type "System.Collections.Hashtable". error when
        #$filter.Add("ID", $EventIDsToAnalyze) is specified.  
        #Get-WinEvent error:  There is not an event log on the localhost computer that matches "System.Collections.Hashtable". when commented out


    }
    catch {
        Write-Host "Get-WinEvent $filter -ErrorAction Stop"
        Write-Host "Get-WinEvent error: " $_.Exception.Message "`n"
        Write-Host "Exiting...`n"
        exit
    }       

} 
ElseIf ( $LogFile -ne "" ) {
    $filter =  "@{Path=""$LogFile"";ID=$EventIDsToAnalyze}"
    $filter2 =  "@{Path=""$LogFile""}"
    Write-Host
    Write-Host "Creating timeline for $LogFile"
    $filesize = Format-FileSize( (get-item $LogFile).length )
    Write-Host "File Size: $filesize"

    $filesizeMB = (Get-Item $LogFile).Length / 1MB
    $filesizeMB = $filesizeMB * 0.1
    $ApproxTimeInSeconds = $filesizeMB * 60
    $TempTimeSpan = New-TimeSpan -Seconds $ApproxTimeInSeconds
    $RuntimeHours = $TempTimeSpan.Hours.ToString()
    $RuntimeMinutes = $TempTimeSpan.Minutes.ToString()
    $RuntimeSeconds = $TempTimeSpan.Seconds.ToString()
    Write-Host "Please be patient. It should take approximately: " -NoNewline
    Write-Host "$RuntimeHours hours $RuntimeMinutes minutes $RuntimeSeconds seconds"

    Write-Host

    try {
        $logs = iex "Get-WinEvent $filter -Oldest -ErrorAction Stop"

    }
    catch {
        Write-Host "Get-WinEvent $filter -ErrorAction Stop"
        Write-Host "Get-WinEvent error: " $_.Exception.Message "`n"
        Write-Host "Exiting...`n"
        exit
    }
}


#Start reading in the logs.
foreach($event in $logs){
    $TotalLogs += 1

    $printMSG = ""

    #Successful logon
    if ($event.Id -eq "4624"){ 

       $eventXML = [xml]$event.ToXml()

       foreach($data in $eventXML.Event.EventData.data){
            switch ( $data.name ){
                "LogonType" { $msgLogonType = $data.'#text' }
                "TargetUserName" { $msgTargetUserName = $data.'#text' }
                "WorkstationName" { $msgWorkstationName = $data.'#text' }
                "IpAddress" { $msgIpAddress = $data.'#text' }
                "IpPort" { $msgIpPort = $data.'#text' }
                "TargetLogonID" { $msgTargetLogonID = $data.'#text' }  
                default { $LogNoise += 1 }
            }
            $TotalPiecesOfData += 1
        
            $msgLogonTypeReadable = Logon-Number-To-String($msgLogonType) #Convert logon numbers to readable strings

            $msgIsLogonDangerous = Is-Logon-Dangerous($msgLogonType) #Check to see if the logon was dangerous (saving credentials in memory)
       }
       
       $timestamp = $event.TimeCreated.ToString($DateFormat) 
       if ($msgTargetUserName -ne "SYSTEM" -and        #Username is not system
           $msgWorkstationName-ne "-" -and             #Workstation Name is not blank
           $msgIpAddress -ne "-")                     #IP Address is not blank
           
           {

           if ( $ShowLogonID -eq $true) {
                $printMSG = " 4624 - LOGON Type $msgLogonType ($msgLogonTypeReadable) to User: $msgTargetUserName from Workstation: $msgWorkstationName IP Address: $msgIpAddress Port: $msgIpPort Logon ID: $msgTargetLogonID $msgIsLogonDangerous"
           } Else {
                $printMSG = " 4624 - LOGON Type $msgLogonType ($msgLogonTypeReadable) to User: $msgTargetUserName from Workstation: $msgWorkstationName IP Address: $msgIpAddress Port: $msgIpPort $msgIsLogonDangerous"
           }


           if ($previousMsg -ne $printMSG -and $printMSG -ne "") {
                $AlertedEvents += 1
                if ( $SaveOutput -eq "") {
                    Write-Host $timestamp -NoNewline
                    Write-Host "  4624 - LOGON" -NoNewline -ForegroundColor $EventID_4624_Color 
                    Write-Host " Type " -NoNewline
                    Write-Host $msgLogonType -NoNewline -ForegroundColor $ParameterColor 
                    Write-Host " (" -NoNewline
                    Write-Host $msgLogonTypeReadable -NoNewline -ForegroundColor $ParameterColor
                    Write-Host ") to User: " -NoNewline 
                    Write-Host $msgTargetUserName -NoNewline -ForegroundColor $ParameterColor
                    Write-Host " from Workstation: " -NoNewline
                    if ( $BadWorkstations.Contains($msgWorkstationName) ) {
                        Write-Host $msgWorkstationName -NoNewline -ForegroundColor White -BackgroundColor Red
                    } Else {
                        Write-Host $msgWorkstationName -NoNewline -ForegroundColor $ParameterColor
                    }
                    Write-Host " IP address: " -NoNewline
                    Write-Host $msgIpAddress -NoNewline -ForegroundColor $ParameterColor
                    Write-Host " Port: " -NoNewline
                    Write-Host $msgIpPort -NoNewline -ForegroundColor $ParameterColor
                    if ( $ShowLogonID -eq $true) {
                        Write-Host " Logon ID: " -NoNewline
                        Write-Host $msgTargetLogonID -NoNewline -ForegroundColor $ParameterColor
                    } 
                    Write-Host " " -NoNewline
                    Write-Host $msgIsLogonDangerous -ForegroundColor White -BackgroundColor Red

                }
                Else {
                    Write-Output "$timestamp $printMSG" | Out-File $SaveOutput -Append
                }
           }              
       }     
    }

    #Special Logon
    if ($event.Id -eq "4672"){

       $eventXML = [xml]$event.ToXml()

       foreach($data in $eventXML.Event.EventData.data){
            
            switch ( $data.name ){
                "SubjectUserName" { $msgSubjectUserName = $data.'#text' }
                "SubjectLogonId" { $msgSubjectLogonId = $data.'#text' }
                "SubjectDomainName" { 
                    $msgSubjectDomainName = $data.'#text' 
                    $LogNoise += 1
                }  #Used just to filter noise

                default { $LogNoise += 1 }
                #Can also print SubjectDomainName and PrivilegeList but not including for now
            }

            $TotalPiecesOfData += 1
            
       } 

       $timestamp = $event.TimeCreated.ToString($DateFormat) 


            #Filter out SYSTEM, DWM-X, DefaultAppPool, IUSR and machine accounts (ending in $) Not using the SubectUserName anymore as an attacker could create a username as DWM-1, etc.. and bypass detection.
            <#
            if ($msgSubjectUserName -ne "SYSTEM" -and 
            $msgSubjectUserName -ne "IUSR" -and 
            $msgSubjectUserName -ne "DWM-1" -and 
            $msgSubjectUserName -ne "DWM-2" -and 
            $msgSubjectUserName -ne "DWM-3" -and 
            $msgSubjectUserName -ne "DWM-4" -and 
            $msgSubjectUserName -ne "DWM-5" -and
            $msgSubjectUserName -ne "DWM-6" -and
            $msgSubjectUserName -ne "LOCAL SERVICE" -and 
            $msgSubjectUserName -ne "NETWORK SERVICE" -and
            $msgSubjectUserName -ne "DefaultAppPool" -and
            $msgSubjectUserName[-1] -ne "$" 
            ){
                $printMSG = " 4672 - ADMIN LOGON by user: $msgSubjectUserName Logon ID: $msgSubjectLogonId"
            }
            #>

       if ($msgSubjectDomainName -ne "NT AUTHORITY" -and
            $msgSubjectDomainName -ne "Window Manager" -and 
            $msgSubjectDomainName -ne "IIS APPPOOL" -and 
            $msgSubjectUserName[-1] -ne "$" 
            ){
                if ( $ShowLogonID -eq $true ) {
                    $printMSG = " 4672 - ADMIN LOGON by User: $msgSubjectUserName Logon ID: $msgSubjectLogonId"
                } else {
                    $printMSG = " 4672 - ADMIN LOGON by User: $msgSubjectUserName"
                }
       }


       if ( $previousMsg -ne $printMSG -and $printMSG -ne "" ){ 

           $AlertedEvents += 1
           if ( $SaveOutput -eq "") {
                Write-Host $timestamp -NoNewline
                Write-Host "  4672 - ADMIN LOGON" -NoNewline -ForegroundColor $EventID_4672_Color 
                Write-Host " by User: " -NoNewline
                Write-Host $msgSubjectUserName -NoNewline -ForegroundColor $ParameterColor 
                if ( $ShowLogonID -eq $true ) {
                    Write-Host " Logon ID: " -NoNewline
                    Write-Host $msgSubjectLogonId -ForegroundColor $ParameterColor
                } else {
                    Write-Host ""
                }
           }
           Else {
                Write-Output "$timestamp $printMSG" | Out-File $SaveOutput -Append
           }
       }
        
    } 



    #Event 4634 - LOGOFF
    if ($event.Id -eq "4634"){

       $eventXML = [xml]$event.ToXml()

       foreach($data in $eventXML.Event.EventData.data){
            switch ( $data.name ){
                "TargetUserName" { $msgTargetUserName = $data.'#text' }
                "TargetLogonId" { $msgTargetLogonId = $data.'#text' }
                "LogonType" { $msgLogonType = $data.'#text' } 
                "TargetDomainName" { 
                    $LogNoise += 1
                    $msgTargetDomainName = $data.'#text' } 
                default { $LogNoise += 1 }
            }
       
       $TotalPiecesOfData += 1
       }

       $msgLogonTypeReadable = Logon-Number-To-String($msgLogonType) #Convert logon numbers to readable strings
 
       $timestamp = $event.TimeCreated.ToString($DateFormat) 
        
       if ( $ShowLogonID -eq $true ) {
            $printMSG = " 4634 - LOGOFF Type $msgLogonType ($msgLogonTypeReadable) from User: $msgTargetUserName Logon ID: $msgTargetLogonId"
       } Else {
            $printMSG = " 4634 - LOGOFF Type $msgLogonType ($msgLogonTypeReadable) from User: $msgTargetUserName"
       }
       

       if ($previousMsg -ne $printMSG -and $printMSG -ne "" -and 
           $msgTargetDomainName -ne "Window Manager" -and #Filter DWM-X logs
           $msgTargetDomainName -ne "Font Driver Host" -and   #Filter UMFD-X logs
           $msgTargetUserName[-1] -ne "$" 
          ){
            
            $AlertedEvents += 1

            if ( $SaveOutput -eq "") {
                Write-Host $timestamp -NoNewline
                Write-Host "  4634 - LOGOFF" -NoNewline -ForegroundColor $EventID_4634_Color 
                Write-Host " Type: " -NoNewline
                Write-Host $msgLogonType -NoNewline -ForegroundColor $ParameterColor 
                Write-Host " (" -NoNewline
                Write-Host $msgLogonTypeReadable -NoNewline -ForegroundColor $ParameterColor
                Write-Host ") from User: " -NoNewline
                Write-Host $msgTargetUserName -NoNewline -ForegroundColor $ParameterColor
                if ( $ShowLogonID -eq $true ) {
                    Write-Host " Logon ID: " -NoNewline
                    Write-Host $msgTargetLogonID -ForegroundColor $ParameterColor
                } Else {
                    Write-Host ""
                }
             }
             Else {
                Write-Output "$timestamp $printMSG" | Out-File $SaveOutput -Append
             }
       }     
        
    } 

    #Event 4647 - LOGOFF
    if ($event.Id -eq "4647"){

       $eventXML = [xml]$event.ToXml()

       foreach($data in $eventXML.Event.EventData.data){
            switch ( $data.name ){
                "TargetUserName" { $msgTargetUserName = $data.'#text' }
                "TargetLogonId" { $msgTargetLogonId = $data.'#text' } 
                "TargetUserSid" { $msgTargetSid = $data.'#text' }
                default { $LogNoise += 1 }
            }

            $TotalPiecesOfData += 1
                   
       }
       
       $timestamp = $event.TimeCreated.ToString($DateFormat) 
       
       if ( $ShowLogonID -eq $true ) {
            $printMSG = " 4647 - LOGOFF from User: $msgTargetUserName Logon ID: $msgTargetLogonId"
       } Else {
            $printMSG = " 4647 - LOGOFF from User: $msgTargetUserName"
       }
              
       

       if ($previousMsg -ne $printMSG -and $printMSG -ne "") {
            $AlertedEvents += 1

            if ( $SaveOutput -eq "") {
                Write-Host $timestamp -NoNewline
                Write-Host "  4647 - LOGOFF" -NoNewline -ForegroundColor $EventID_4647_Color 
                Write-Host " from User: " -NoNewline
                Write-Host $msgTargetUserName -NoNewline -ForegroundColor $ParameterColor
                if ( $ShowLogonID -eq $true ) {
                    Write-Host " Logon ID: " -NoNewline
                    Write-Host $msgTargetLogonID -ForegroundColor $ParameterColor
                } else {
                    Write-Host ""
                }
             }
             Else {
                Write-Output "$timestamp $printMSG" | Out-File $SaveOutput -Append
             }  
       }    
        
    } 

    #Event 4625 - FAILED LOGON
    if ($event.Id -eq "4625"){

       $eventXML = [xml]$event.ToXml()

       foreach($data in $eventXML.Event.EventData.data){
            switch ( $data.name ){
                "LogonType" { $msgLogonType = $data.'#text' }
                "TargetUserName" { $msgTargetUserName = $data.'#text' }
                "WorkstationName" { $msgWorkstationName = $data.'#text' }
                "IpAddress" { $msgIpAddress = $data.'#text' }
                "IpPort" { $msgIpPort = $data.'#text' }
                #"FailureReason" { $msgFailureReason = $data.'#text' }
                "LogonProcessName" { $msgLogonProcessName = $data.'#text' }
                "AuthenticationPackageName" { $msgAuthenticationPackageName = $data.'#text' }
                "Status" { $msgStatus = $data.'#text' }
                "SubStatus" { $msgSubStatus = $data.'#text' }
                default { $LogNoise += 1 }
                 
            }
        }

        $TotalPiecesOfData += 1

        $msgLogonTypeReadable = Logon-Number-To-String($msgLogonType) #Convert logon numbers to readable strings

        <# Switching to checking status code and sub status code instead of failurereason for more granular info
            switch ( $msgFailureReason ) {
                "%%2305" { $msgFailureReasonReadable = "The specified user account has expired." }
                "%%2309" { $msgFailureReasonReadable = "The specified account's password has expired." }
                "%%2310" { $msgFailureReasonReadable = "Account currently disabled." }
                "%%2311" { $msgFailureReasonReadable = "Account logon time restriction violation." }
                "%%2312" { $msgFailureReasonReadable = "User not allowed to logon at this computer." }
                "%%2313" { $msgFailureReasonReadable = "Unknown user name or bad password." }
                default { $msgLogonTypeReadable = "Unknown" }
            }
            #>

        switch ( $msgStatus ) {
                "0xc000006d" { $msgFailureReasonReadable = "UNKNOWN USERNAME OR PASSWORD" }
                "0xc000006e" { $msgFailureReasonReadable = "UNKNOWN USERNAME OR PASSWORD" }
                "0xc000005e" { $msgFailureReasonReadable = "NO LOGON SERVERS AVAILABLE" }
                "0xc000006f" { $msgFailureReasonReadable = "OUTSIDE AUTHORIZED HOURS" }
                "0xc0000070" { $msgFailureReasonReadable = "UNAUTHORIZED WORKSTATION" }
                "0xc0000071" { $msgFailureReasonReadable = "PASSWORD EXPIRED" }
                "0xc0000072" { $msgFailureReasonReadable = "ACCOUNT DISABLED" }
                "0xc00000dc" { $msgFailureReasonReadable = "SERVER IN WRONG STATE" }
                "0xc0000133" { $msgFailureReasonReadable = "CLOCK OUT OF SYNC WITH DC" }
                "0xc000015b" { $msgFailureReasonReadable = "NO LOGON RIGHT" }
                "0xc000018c" { $msgFailureReasonReadable = "TRUST RELATIONSHIP BETWEEN PRIMARY DOMAIN AND TRUSTED DOMAIN FAILED" }
                "0xc0000192" { $msgFailureReasonReadable = "NETLOGON SERVICE NOT STARTED" }
                "0xc0000193" { $msgFailureReasonReadable = "ACCOUNT EXPIRED" }
                "0xc0000224" { $msgFailureReasonReadable = "USER REQUIRED TO CHANGE PASSWORD" }
                "0xc0000225" { $msgFailureReasonReadable = "WINDOWS BUG" }
                "0xc0000234" { $msgFailureReasonReadable = "ACCOUNT LOCKED" }
                default { $msgFailureReasonReadable = "UNKNOWN STATUS CODE: $msgStatus Please report to Yamato Security"}    

            }

        #Override the fail reason with more specific substatus
        switch ( $msgSubStatus ) {
            "0xc0000064" { $msgFailureReasonReadable = "UNKNOWN USERNAME" }
            "0xc000006a" { $msgFailureReasonReadable = "WRONG PASSWORD" }   
        }

        $timestamp = $event.TimeCreated.ToString($DateFormat) 

        $printMSG = " 4625 - FAILED LOGON Type: $msgLogonType ($msgLogonTypeReadable) from User: $msgTargetUserName Workstation: $msgWorkstationName IP Address: $msgIpAddress Port: $msgIpPort Logon Process: $msgLogonProcessName Auth: $msgAuthenticationPackageName Reason: $msgFailureReasonReadable"

       if ($previousMsg -ne $printMSG -and $printMSG -ne "" -and
           $msgTargetUserName -ne "-" ) {
             $AlertedEvents += 1
             if ( $SaveOutput -eq "") {
                Write-Host $timestamp -NoNewline
                Write-Host "  4625 - " -NoNewline -ForegroundColor $EventID_4625_Color 
                Write-Host "FAILED LOGON" -NoNewline -ForegroundColor White -BackgroundColor Red
                Write-Host " Type: " -NoNewline
                Write-Host $msgLogonType -NoNewline -ForegroundColor $ParameterColor
                Write-Host " (" -NoNewline
                Write-Host $msgLogonTypeReadable -NoNewline -ForegroundColor $ParameterColor
                Write-Host ") from User: " -NoNewline
                Write-Host $msgTargetUserName -NoNewline -ForegroundColor $ParameterColor
                Write-Host " Workstation: " -NoNewline
                if ( $BadWorkstations.Contains($msgWorkstationName) ) {
                        Write-Host "$msgWorkstationName" -NoNewline -ForegroundColor White -BackgroundColor Red
                    } Else {
                        Write-Host $msgWorkstationName -NoNewline -ForegroundColor $ParameterColor
                    }
                Write-Host " IP Address: " -NoNewline
                Write-Host $msgIpAddress -NoNewline -ForegroundColor $ParameterColor
                Write-Host " Port: " -NoNewline
                Write-Host $msgIpPort -NoNewline -ForegroundColor $ParameterColor
                Write-Host " Logon Process: " -NoNewline 
                Write-Host $msgLogonProcessName -NoNewline -ForegroundColor $ParameterColor
                Write-Host " Auth: " -NoNewline
                Write-Host $msgAuthenticationPackageName -NoNewline -ForegroundColor $ParameterColor
                Write-Host " Reason: " -NoNewline
                Write-Host $msgFailureReasonReadable -ForegroundColor White -BackgroundColor Red

             }
             Else {
                Write-Output "$timestamp $printMSG" | Out-File $SaveOutput -Append
             }    
       }

    } 


    #Event 4720 - Account Created
    if ($event.Id -eq "4720"){

       $eventXML = [xml]$event.ToXml()

       foreach($data in $eventXML.Event.EventData.data){
            switch ( $data.name ){
                "SamAccountName" { $msgSamAccountName = $data.'#text' }
                "DisplayName" { $msgDisplayName = $data.'#text' }
                "AccountExpires" { $msgAccountExpires = $data.'#text' }
                "TargetSid" { $msgTargetSid = $data.'#text' }
                default { $LogNoise += 1 }
                 
            }
            $TotalPiecesOfData += 1
                       
            if ( $msgDisplayName -eq "%%1793" ) {
                $msgDisplayName = "<value not set>"
            }

            if ( $msgAccountExpires -eq "%%1794" ) {
                $msgAccountExpires = "<never>"
            }
 
            $timestamp = $event.TimeCreated.ToString($DateFormat) 
            $printMSG = " 4720 - ACCOUNT CREATED User: $msgSamAccountName Display Name: $msgDisplayName Account Expires: $msgAccountExpires SID: $msgTargetSid" 

       }

       if ($previousMsg -ne $printMSG -and $printMSG -ne "") {
            $AlertedEvents += 1
            if ( $SaveOutput -eq "") {
                Write-Host $timestamp -NoNewline
                Write-Host "  4720 - ACCOUNT CREATED" -NoNewline -ForegroundColor $EventID_4720_Color 
                Write-Host " User: " -NoNewline
                Write-Host $msgSamAccountName -NoNewline -ForegroundColor $ParameterColor
                Write-Host " Display Name: " -NoNewline
                if ( $msgDisplayName -eq "<value not set>") {
                    Write-Host $msgDisplayName -NoNewline -ForegroundColor White -BackgroundColor Red
                } Else {
                    Write-Host $msgDisplayName -NoNewline -ForegroundColor $ParameterColor
                }
                Write-Host " Account Expires: " -NoNewline
                if ( $msgAccountExpires -eq "<never>" ) {
                    Write-Host $msgAccountExpires -NoNewline -ForegroundColor White -BackgroundColor Red
                } Else {
                    Write-Host $msgAccountExpires -NoNewline -ForegroundColor $ParameterColor
                }
                Write-Host " SID: " -NoNewline
                Write-Host $msgTargetSid -ForegroundColor $ParameterColor
             }
             Else {
                Write-Output "$timestamp $printMSG" | Out-File $SaveOutput -Append
             }     
       }

    }

    
    #User added a group
    if ($event.Id -eq "4732"){

       $eventXML = [xml]$event.ToXml()

       foreach($data in $eventXML.Event.EventData.data){
            switch ( $data.name ){
                "MemberSid" { $msgMemberSid = $data.'#text' }
                "TargetDomainName" { $msgTargetDomainName = $data.'#text' }
                "TargetUserName" { $msgTargetUserName = $data.'#text' }
                "TargetSid" { $msgTargetSid = $data.'#text' } 
                default { $LogNoise += 1 }
            }
            $TotalPiecesOfData += 1
                       
            $timestamp = $event.TimeCreated.ToString($DateFormat) 
            $group = $msgTargetDomainName
            $group += "\"
            $group += $msgTargetUserName
            $printMSG = " 4732 - USER ADDED TO GROUP User SID: $msgMemberSid was added to group: $group" 

       }
 
       if ($previousMsg -ne $printMSG -and $printMSG -ne "") {
             $AlertedEvents += 1
             if ( $SaveOutput -eq "") {
                Write-Host $timestamp -NoNewline
                Write-Host "  4732 - USER ADDED TO GROUP" -NoNewline -ForegroundColor $EventID_4732_Color 
                Write-Host " User SID: " -NoNewline
                Write-Host $msgMemberSid -NoNewline -ForegroundColor $ParameterColor
                Write-Host " was added to group: " -NoNewline
                if ( $msgTargetUserName -eq "Administrators" ) {
                    Write-Host $group -ForegroundColor White -BackgroundColor Red
                } Else {
                    Write-Host $group -ForegroundColor $ParameterColor
                }
             }
             Else {
                Write-Output "$timestamp $printMSG" | Out-File $SaveOutput -Append
             }   
       }

    }  

    #Log cleared
    if ($event.Id -eq "1102"){

       $eventXML = [xml]$event.ToXml()

       foreach($data in $eventXML.Event.EventData.data){
            switch ( $data.name ){
                "SubjectUserName" { $msgSubjectUserName = $data.'#text' }
                "SubjectLogonId" { $msgSubjectLogonId = $data.'#text' }
                default { $LogNoise += 1 }
                 
            }
            $TotalPiecesOfData += 1
       }
                  
       $timestamp = $event.TimeCreated.ToString($DateFormat) 
       $printMSG = " 1102 - EVENT LOG CLEARED" 

        if ($previousMsg -ne $printMSG -and $printMSG -ne "") {
             $AlertedEvents += 1
             if ( $SaveOutput -eq "") {
                Write-Host $timestamp -NoNewline
                Write-Host "  1102 - " -NoNewline -ForegroundColor $EventID_1102_Color
                Write-Host "EVENT LOG CLEARED" -ForegroundColor White -BackgroundColor red 
             }
             Else {
                Write-Output "$timestamp $printMSG" | Out-File $SaveOutput -Append
             }      
       }   
       
    }  

    #Logon using explicit credentials
    if ($event.Id -eq "4648"){
       $eventXML = [xml]$event.ToXml()

       foreach($data in $eventXML.Event.EventData.data){
            switch ( $data.name ){
                "SubjectUserName" { $msgSubjectUserName = $data.'#text' } 
                #"SubjectDomainName" { $msgSubjectDomainName = $data.'#text' }  #Would this be useful to add? It seems to always be the same
                "TargetUserName" { $msgTargetUserName = $data.'#text' }
                "TargetDomainName" { $msgTargetDomainName = $data.'#text' }
                "SubjectLogonId" { $msgSubjectLogonId = $data.'#text' } 
                "TargetServerName" { $msgTargetServerName = $data.'#text' }
                "IpAddress" { $msgIpAddress = $data.'#text' }
                "IpPort" { $msgIpPort = $data.'#text' }
                "ProcessName" { $msgProcessName = $data.'#text' }
                default { $LogNoise += 1 }
            }

            $TotalPiecesOfData += 1
       }
       
       $timestamp = $event.TimeCreated.ToString($DateFormat) 
       $isMachine = $msgSubjectUserName[-1]
       
       if ( $msgIpAddress -ne "-" -and $isMachine -ne "$") { #don't print local events as there are too many. also filtering machine account noise
            $AlertedEvents += 1
       
            if ( $ShowLogonID -eq $true ) {
                $printMSG = " 4648 - EXPLICIT LOGON Subject User: $msgSubjectUserName Target User: $msgTargetUserName Target Server: $msgTargetServerName Target Domain: $msgTargetDomainName IP Address: $msgIpAddress Port: $msgIpPort Process: $msgProcessName Logon ID: $msgSubjectLogonId" 
            } else {
                $printMSG = " 4648 - EXPLICIT LOGON Subject User: $msgSubjectUserName Target User: $msgTargetUserName Target Server: $msgTargetServerName Target Domain: $msgTargetDomainName IP Address: $msgIpAddress Port: $msgIpPort Process: $msgProcessName"
            }     
       }
       
       
       if ( $previousMsg -ne $printMSG -and $printMSG -ne "" ) {

                if ( $SaveOutput -eq "") {
                    Write-Host $timestamp -NoNewline
                    Write-Host "  4648 - EXPLICIT LOGON" -NoNewline -ForegroundColor $EventID_4648_Color
                    Write-Host " User: " -NoNewline
                    Write-Host $msgSubjectUserName -NoNewline -ForegroundColor $ParameterColor
                    Write-Host " Target User: " -NoNewline
                    Write-Host $msgTargetUserName -NoNewline -ForegroundColor $ParameterColor
                    Write-Host " Target Server: " -NoNewline
                    Write-Host $msgTargetServerName -NoNewline -ForegroundColor $ParameterColor
                    Write-Host " Target Domain: " -NoNewline
                    Write-Host $msgTargetDomainName -NoNewline -ForegroundColor $ParameterColor
                    Write-Host " IP Address: " -NoNewline
                    Write-Host $msgIpAddress -NoNewline -ForegroundColor $ParameterColor
                    Write-Host " Port: " -NoNewline
                    Write-Host $msgIpPort -NoNewline -ForegroundColor $ParameterColor
                    Write-Host " Process: " -NoNewline
                    Write-Host $msgProcessName -NoNewline  -ForegroundColor $ParameterColor
                    if ( $ShowLogonID -eq $true ) {
                        Write-Host " Logon ID: " -NoNewline
                        Write-Host $msgSubjectLogonId
                    } else {
                        Write-Host ""
                    }
                }
                Else {
                    Write-Output "$timestamp $printMSG" | Out-File $SaveOutput -Append
                } 
            
       }
       
    } 

     
    if ($printMSG -ne ""){
        $previousMsg = $printMSG #Sometimes duplicate logs happen alot, so if the previous message is the same we will filter.
    }
    Else {
        $SkippedLogs += 1
    }

}

$GoodData = $TotalPiecesOfData - $LogNoise
$LogEventDataReduction = [math]::Round( ( ($TotalLogs - $AlertedEvents) / $TotalLogs * 100 ), 1 )
$PercentOfLogNoise = [math]::Round( ( $LogNoise / $TotalPiecesOfData * 100 ), 1 )
$ProgramEndTime = Get-Date
$TotalRuntime = [math]::Round(($ProgramEndTime - $ProgramStartTime).TotalSeconds)


Write-Host
Write-Host "Total analyzed logs: $TotalLogs"
Write-Host "Useless logs: $SkippedLogs"
Write-Host "Alerted events: $AlertedEvents"
Write-Host "Log event data reduction: $LogEventDataReduction" -NoNewline
Write-Host "%"
Write-Host
Write-Host "Useful Data in filtered logs: $GoodData"
Write-Host "Noisy Data in filtered logs: $LogNoise"
Write-Host "Log Noise: $PercentOfLogNoise" -NoNewline
Write-Host "%"
Write-Host

$TempTimeSpan = New-TimeSpan -Seconds $TotalRuntime
$RuntimeHours = $TempTimeSpan.Hours.ToString()
$RuntimeMinutes = $TempTimeSpan.Minutes.ToString()
$RuntimeSeconds = $TempTimeSpan.Seconds.ToString()
Write-Output "Processing time: $RuntimeHours hours $RuntimeMinutes minutes $RuntimeSeconds seconds"
}

function Perform-LiveAnalysis {
    Write-Host "perform live analyis"

}

function Perform-LiveAnalysisChecks{
    if ( $IsWindows -eq $true -or $env:OS -eq "Windows_NT" ) {
        
        #Check if running as an admin
        $isAdmin = Check-Administrator
        Write-Host $isAdmin

        if ( $isAdmin -eq $false ){
            if ( $HostLanguage.Name -eq "ja-JP" -or $Japanese -eq $true ) {
                Write-Host
                Write-Host "エラー： Powershellを管理者として実行する必要があります。"
                Write-Host
                Exit
            } else {
                Write-Host
                Write-Host "Error: You need to be running Powershell as Administrator."
                Write-Host
                Exit
            }
        }

        #Running as admin on Windows
        Perform-LiveAnalysis
               
        
    } else { #Trying to run live analysis on Mac or Linux
        if ( $HostLanguage.Name -eq "ja-JP" -or $Japanese -eq $true ) {
            Write-Host
            Write-Host "エラー： ライブ調査はWindowsにしか対応していません。"
            Write-Host
            Exit
        } else {
            Write-Host
            Write-Host "Error: Live Analysis is only supported on Windows"
            Write-Host
            Exit
        }
    }
}



#Main

if ( $ShowContributors -eq $true ) {
    Show-Contributors
    exit
}


if ( $LiveAnalysis -eq $true -and $IsDC -eq $true ) {
    if ($HostLanguage.Name -eq "ja-JP" -or $Japanese -eq $true) {
        Write-Host
        Write-Host "注意：ドメインコントローラーでライブ調査をしない方が良いです。ログをオフラインにコピーしてから解析して下さい。" -ForegroundColor White -BackgroundColor Red
        exit
    }
    Write-Host
    Write-Host "Warning: You probably should not be doing live analysis on a Domain Controller. Please copy log files offline for analysis." -ForegroundColor White -BackgroundColor Red
    exit
}

if ( $LiveAnalysis -eq $true -and $LogFile -ne "" ) {
    if ($HostLanguage.Name -eq "ja-JP" -or $Japanese -eq $true) {
        Write-Host
        Write-Host "エラー：「-LiveAnalysis `$true」 と「-LogFile」を同時に指定できません。" -ForegroundColor White -BackgroundColor Red
        exit
    }
    Write-Host
    Write-Host "Error: you cannot specify -LiveAnalysis `$true and -LogFile at the same time." -ForegroundColor White -BackgroundColor Red
    exit
}



if ( $LiveAnalysis -eq $false -and $LogFile -eq ""  -and $EventIDStatistics -eq $false -and $LogonOverview -eq $false -and $AccountInformation -eq $false -and ($HostLanguage.Name -eq "ja-JP" -or $Japanese -eq $true) ) {
 
    Write-Host 
    Write-Host "YEAセキュリティイベントタイムライン作成ツール" -ForegroundColor Green
    Write-Host "バージョン: $YEAVersion" -ForegroundColor Green
    Write-Host "作者: 白舟（田中ザック） (@yamatosecurity)" -ForegroundColor Green
    Write-Host 

    Write-Host "解析ソースを一つ指定して下さい：" 
    Write-Host "   -LiveAnalysis `$true" -NoNewline -ForegroundColor Green
    Write-Host " : ホストOSのログでタイムラインを作成する"

    Write-Host "   -LogFile <path-to-logfile>" -NoNewline -ForegroundColor Green
    Write-Host " : オフラインの.evtxファイルでタイムラインを作成する"


    Write-Host
    Write-Host "解析タイプを一つ指定して下さい:"

    Write-Host "   -EventIDStatistics `$true" -NoNewline -ForegroundColor Green
    Write-Host " : イベントIDの統計情報を出力する" 

    Write-Host "   -AccountInformation `$true" -NoNewline -ForegroundColor Green
    Write-Host " : ユーザ名とSIDのアカウント情報を出力する"

    Write-Host "   -LogonStatistics `$true" -NoNewline -ForegroundColor Green
    Write-Host " : ログオンの統計を出力する"

    Write-Host "   -LogonOverview `$true" -NoNewline -ForegroundColor Green
    Write-Host " : ユーザログオンの簡単なタイムラインを出力する"

    Write-Host "   -CreateHumanReadableTimeline `$true" -NoNewline -ForegroundColor Green
    Write-Host " : 読みやすいタイムラインを出力する"

    Write-Host 
    Write-Host "出力オプション："

    Write-Host "   -SaveOutput <出力パス>" -NoNewline -ForegroundColor Green
    Write-Host " : テキストファイルに出力する"

    Write-Host "   -StartTimeline ""<YYYY-MM-DD HH:MM:SS>""" -NoNewline -ForegroundColor Green
    Write-Host " : タイムラインの始まりを指定する"

    Write-Host "   -EndTimeline ""<YYYY-MM-DD HH:MM:SS>""" -NoNewline -ForegroundColor Green
    Write-Host " : タイムラインの終わりを指定する"

    Write-Host "   -USDateFormat `$true" -NoNewline -ForegroundColor Green
    Write-Host " : 日付をMM-DD-YYYY形式で出力する (デフォルト： YYYY-MM-DD)"

    Write-Host "   -EuropeDateFormat `$true" -NoNewline -ForegroundColor Green
    Write-Host " : 日付をDD-MM-YYYY形式で出力する (デフォルト： YYYY-MM-DD)" 

    Write-Host "   -UTC `$true" -NoNewline -ForegroundColor Green
    Write-Host " : 時間をUTC形式で出力する"
     
    Write-Host "   -Japanese `$true" -NoNewline -ForegroundColor Green
    Write-Host " : 日本語で出力する"

    Write-Host
    Write-Host "-LiveAnalysisと-LogFileの解析・出力オプション:"

    Write-Host "   -IsDC `$true" -NoNewline -ForegroundColor Green
    Write-Host " : ドメインコントローラーのログの場合は指定して下さい (デフォルト： `$false)"

    Write-Host "   -ShowLogonID `$true" -NoNewline -ForegroundColor Green
    Write-Host " : ログオンIDを出力する"

    Write-Host
    Write-Host "その他:"

    Write-Host "   -ShowContributors `$true" -NoNewline -ForegroundColor Green
    Write-Host " : コントリビューターの一覧表示" 

    Write-Host

    exit

}

if ( $LiveAnalysis -eq $false -and $LogFile -eq "" -and $EventIDStatistics -eq $false -and $LogonOverview -eq $false -and $AccountInformation -eq $false ) {

    Write-Host 
    Write-Host "YEA Security Event Timeline Generator" -ForegroundColor Green
    Write-Host "Version: $YEAVersion" -ForegroundColor Green
    Write-Host "Author: Zach Mathis (@yamatosecurity)" -ForegroundColor Green
    Write-Host 

    Write-Host "Please specify some options:" 
    Write-Host

    Write-Host "Analysis Source (Specify one):"

    Write-Host "   -LiveAnalysis `$true" -NoNewline -ForegroundColor Green
    Write-Host " : Creates a timeline based on the live host's log"

    Write-Host "   -LogFile <path-to-logfile>" -NoNewline -ForegroundColor Green
    Write-Host " : Creates a timelime from an offline .evtx file"

    Write-Host
    Write-Host "Analysis Type (Specify one):"

    Write-Host "   -EventIDStatistics `$true" -NoNewline -ForegroundColor Green
    Write-Host " : Output event ID statistics" 

    Write-Host "   -AccountInformation `$true" -NoNewline -ForegroundColor Green
    Write-Host " : Output the usernames and SIDs of accounts"
    
    Write-Host "   -LogonStatistics `$true" -NoNewline -ForegroundColor Green
    Write-Host " : Output logon statistics"

    Write-Host "   -LogonOverview `$true" -NoNewline -ForegroundColor Green
    Write-Host " : Output a simple timeline of user logons"

    Write-Host "   -CreateBriefHumanReadableTimeline `$true" -NoNewline -ForegroundColor Green
    Write-Host " : Creates a human readable timeline with minimal noise"

    Write-Host "   -CreateFullHumanReadableTimeline `$true" -NoNewline  -ForegroundColor Green
    Write-Host " : Creates a human readable timeline with all details"

    Write-Host 
    Write-Host "Analysis Options:"

    Write-Host "   -SaveOutput <outputfile-path>" -NoNewline -ForegroundColor Green
    Write-Host " : Output results to a text file"

    Write-Host "   -StartTimeline ""<YYYY-MM-DD HH:MM:SS>""" -NoNewline -ForegroundColor Green
    Write-Host " : Specify the start of the timeline"

    Write-Host "   -EndTimeline ""<YYYY-MM-DD HH:MM:SS>""" -NoNewline -ForegroundColor Green
    Write-Host " : Specify the end of the timeline"

    Write-Host "   -USDateFormat `$true" -NoNewline -ForegroundColor Green
    Write-Host " : Output the dates in MM-DD-YYYY format (Default: YYYY-MM-DD)"

    Write-Host "   -EuropeDateFormat `$true" -NoNewline -ForegroundColor Green
    Write-Host " : Output the dates in DD-MM-YYYY format (Default: YYYY-MM-DD)"

    Write-Host "   -UTC `$true" -NoNewline -ForegroundColor Green
    Write-Host " : Output in UTC time"
     
    Write-Host "   -Japanese `$true" -NoNewline -ForegroundColor Green
    Write-Host " : Output in Japanese"

    Write-Host
    Write-Host "-LiveAnalysis and -LogFile Analysis Options:"

    Write-Host "   -IsDC `$true" -NoNewline -ForegroundColor Green
    Write-Host " : Specify if the logs are from a DC (Default: `$false)"

    Write-Host "   -ShowLogonID `$true" -NoNewline -ForegroundColor Green
    Write-Host " : Specify if you want to see Logon IDs"

    Write-Host
    Write-Host "Other:"

    Write-Host "   -ShowContributors `$true" -NoNewline -ForegroundColor Green
    Write-Host " : Show the contributors" 


    Write-Host

    exit

}

#Create-Timeline
<#
if ( $LiveAnalysis -eq $true ) {
    Perform-LiveAnalysisChecks
}
#>

if ( $EventIDStatistics -eq $true ) {

    Create-EventIDStatistics

}

if ( $LogonOverview -eq $true ) {

    Create-LogonOverview

}