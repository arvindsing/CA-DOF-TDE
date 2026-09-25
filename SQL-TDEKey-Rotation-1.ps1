<#
================================================================================
AZURE SQL MANAGED INSTANCE TDE COMPLIANCE AND KEY-ROTATION VALIDATION
================================================================================

PURPOSE
This script validates the complete customer-managed TDE chain across three layers:

1. Azure Key Vault
   - Confirms DNS resolution and TCP 443 connectivity.
   - Confirms the vault is accessible through the Azure control plane.
   - Confirms purge-protection status.
   - Identifies the newest enabled, active, and non-expired version of the approved key.
   - Reports the immediately preceding eligible key version for historical reference.

2. Azure SQL Managed Instance control plane
   - Confirms the SQL MI managed identity exists.
   - Reads the current TDE protector and automatic-rotation setting.
   - Confirms the currently active protector version.
   - Lists versions registered with SQL MI.
   - Compares the current protector with the latest eligible Key Vault version.

3. SQL database engine
   - Connects to master using the supplied PSCredential.
   - Queries sys.databases and sys.dm_database_encryption_keys.
   - Confirms user databases are ONLINE, encrypted, and at encryption_state = 3.
   - Retrieves encryptor type, algorithm, key length, modification date, and thumbprint.
   - Confirms thumbprint consistency across encrypted user databases.

SAFETY MODEL
- ValidateOnly is the default mode and does not modify the TDE protector.
- Execute can register and activate the latest eligible key version.
- If automatic rotation is enabled, the script does not manually update the protector unless
  ForceManualUpdateWhenAutoRotationEnabled is explicitly supplied.
- Historical key versions are never disabled, deleted, expired, or purged by this script.
- The current protector KeyId is retained in the JSON report as a rollback/reference value.

THUMBPRINT INTERPRETATION
The SQL encryptor thumbprint and the Azure Key Vault KeyId use different representations.
This script therefore validates:
- exact Key Vault version alignment through the SQL MI control-plane protector KeyId, and
- SQL-side thumbprint consistency across encrypted databases.
It does not incorrectly compare the raw SQL thumbprint string directly with the Key Vault URI.

EXIT CODES
0 = Success or no change required
1 = Blocking validation failure
2 = Change required, automatic-rotation propagation pending, or execution not performed

OPERATIONAL RECOMMENDATIONS
- Run ValidateOnly before every approved TDE change.
- Retain the JSON report with the operational change record.
- Keep previous Key Vault versions enabled and accessible according to backup-retention needs.
- Investigate multiple SQL thumbprints unless a protection change is actively in progress.
- Use Execute only after reviewing all blocking checks and change-control approval.
================================================================================
#>

<#
.SYNOPSIS
Validates and optionally synchronizes Azure SQL Managed Instance TDE with the latest Azure Key Vault key version.

.DESCRIPTION
Performs Azure control-plane, Key Vault, auto-rotation, registered-key, and SQL database-engine validation.
It records the current protector as the rollback reference, reports the immediately preceding Key Vault version,
checks SQL-side TDE thumbprint consistency, and optionally registers and activates the latest eligible key version.

.NOTES
Required modules: Az.Accounts, Az.KeyVault, Az.Sql
Exit codes: 0 success/no change, 1 failure, 2 change or auto-rotation propagation pending.
#>
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
 [Parameter(Mandatory=$true)][string]$SubscriptionId,
 [Parameter(Mandatory=$true)][string]$ResourceGroupName,
 [Parameter(Mandatory=$true)][string]$ManagedInstanceName,
 [Parameter(Mandatory=$true)][string]$VaultName,
 [Parameter(Mandatory=$true)][string]$KeyName,
 [Parameter(Mandatory=$true)][string]$SqlServer,
 [Parameter(Mandatory=$true)][System.Management.Automation.PSCredential]$SqlCredential,
 [int]$SqlPort=3342,
 [ValidateSet('ValidateOnly','Execute')][string]$Mode='ValidateOnly',
 [switch]$ForceManualUpdateWhenAutoRotationEnabled,
 [string]$OutputDirectory='C:\SQLMITDE\TDE'
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script:Results=[System.Collections.Generic.List[object]]::new()
$script:BlockingFailure=$false
$operationId=[guid]::NewGuid().ToString()
$startedUtc=(Get-Date).ToUniversalTime()
$changeRequired=$false
$actionTaken='None'
$currentKeyId=$null;$currentVersion=$null;$latestKeyId=$null;$latestVersion=$null
$previousKeyId=$null;$previousVersion=$null;$autoRotationEnabled=$false
$sqlEvidence=@();$sqlThumbprints=@()

function Add-Result {
 param([string]$Check,[ValidateSet('PASS','FAIL','WARNING','INFO')][string]$Status,[string]$Message,[bool]$Blocking=$false,[object]$Evidence=$null)
 if(($Status-eq'FAIL')-and$Blocking){$script:BlockingFailure=$true}
 $script:Results.Add([pscustomobject]@{TimestampUtc=(Get-Date).ToUniversalTime().ToString('o');Check=$Check;Status=$Status;Blocking=$Blocking;Message=$Message;Evidence=$Evidence})
 $c=switch($Status){'PASS'{'Green'}'FAIL'{'Red'}'WARNING'{'Yellow'}default{'Cyan'}}
 Write-Host ('[{0}] {1}: {2}'-f$Status,$Check,$Message)-ForegroundColor $c
}
function Require-Module([string]$Name){
 $m=Get-Module -ListAvailable $Name|Sort-Object Version -Descending|Select-Object -First 1
 if($null-eq$m){throw "Required module '$Name' is not installed."}
 Import-Module $Name -ErrorAction Stop
 Add-Result "Module $Name" PASS "Loaded version $($m.Version)."
}
function Get-PropertyValue([object]$Object,[string[]]$Names){
 foreach($n in $Names){$p=$Object.PSObject.Properties[$n];if(($null-ne$p)-and($null-ne$p.Value)-and(-not[string]::IsNullOrWhiteSpace([string]$p.Value))){return $p.Value}}
 return $null
}
function Get-KeyVersion([AllowNull()][string]$Id){
 if([string]::IsNullOrWhiteSpace($Id)){return $null};$v=$Id.Trim().TrimEnd('/')
 if($v-match'/keys/[^/]+/([^/?#]+)$'){return $Matches[1]}
 $s=$v.Split('/',[System.StringSplitOptions]::RemoveEmptyEntries);if($s.Count-gt0){return $s[$s.Count-1]};return $v
}
function Get-RegisteredKeyId([object]$Key){[string](Get-PropertyValue $Key @('KeyId','ManagedInstanceKeyVaultKeyName','ManagedInstanceKeyName','ServerKeyName'))}

Write-Host '';Write-Host ('='*76)-ForegroundColor Cyan
Write-Host 'SQL MI TDE KEY VERSION AND DATABASE-ENGINE VALIDATION'-ForegroundColor Cyan
Write-Host ('='*76)-ForegroundColor Cyan
Write-Host "Operation ID : $operationId";Write-Host "Mode : $Mode"
if(-not(Test-Path -LiteralPath $OutputDirectory)){New-Item $OutputDirectory -ItemType Directory -Force|Out-Null}

# STEP 1: Load required Azure modules and validate the active Azure context.
try{
 Require-Module Az.Accounts;Require-Module Az.KeyVault;Require-Module Az.Sql
 if($null-eq(Get-AzContext)){throw 'No Azure context. Run Connect-AzAccount first.'}
 Set-AzContext -SubscriptionId $SubscriptionId|Out-Null
 $ctx=Get-AzContext;Add-Result 'Azure authentication' PASS "Authenticated as '$($ctx.Account.Id)' in subscription '$($ctx.Subscription.Id)'."

 # STEP 2: Validate Key Vault DNS, TCP connectivity, control-plane access, and purge protection.
 $vaultHost="$VaultName.vault.azure.net"
 try{Resolve-DnsName $vaultHost -ErrorAction Stop|Out-Null;Add-Result 'Key Vault DNS' PASS "$vaultHost resolved."}catch{Add-Result 'Key Vault DNS' FAIL $_.Exception.Message $true}
 $tcp=Test-NetConnection $vaultHost -Port 443 -WarningAction SilentlyContinue
 if($tcp.TcpTestSucceeded){Add-Result 'Key Vault TCP' PASS "$vaultHost is reachable on TCP 443."}else{Add-Result 'Key Vault TCP' FAIL 'TCP 443 failed.' $true}
 $vault=Get-AzKeyVault -VaultName $VaultName -ErrorAction Stop
 Add-Result 'Key Vault access' PASS "Retrieved '$VaultName'."
 if($vault.EnablePurgeProtection){Add-Result 'Purge protection' PASS 'Enabled.'}else{Add-Result 'Purge protection' WARNING 'Not enabled.'}

 # STEP 3: Select the latest eligible key and retain the immediate predecessor.
 $now=(Get-Date).ToUniversalTime()
 $versions=@(Get-AzKeyVaultKey -VaultName $VaultName -Name $KeyName -IncludeVersions -ErrorAction Stop|Where-Object{
  ($_.Enabled-eq$true)-and(($null-eq$_.NotBefore)-or($_.NotBefore.ToUniversalTime()-le$now))-and(($null-eq$_.Expires)-or($_.Expires.ToUniversalTime()-gt$now))
 }|Sort-Object Created -Descending)
 if($versions.Count-eq0){throw "No eligible version for '$KeyName'."}
 $latest=$versions[0];$latestKeyId=[string]$latest.Id;$latestVersion=Get-KeyVersion $latestKeyId
 if($versions.Count-gt1){$previous=$versions[1];$previousKeyId=[string]$previous.Id;$previousVersion=Get-KeyVersion $previousKeyId}
 Add-Result 'Latest eligible Key Vault version' PASS "Latest version: $latestVersion" $false $latest
 if($previousVersion){Add-Result 'Previous Key Vault version' INFO "Immediate predecessor: $previousVersion" $false $previous}else{Add-Result 'Previous Key Vault version' INFO 'No earlier eligible version was returned.'}

 # STEP 4: Validate SQL MI managed identity and retrieve the current TDE protector.
 $mi=Get-AzSqlInstance -ResourceGroupName $ResourceGroupName -Name $ManagedInstanceName -ErrorAction Stop
 if($null-ne$mi.Identity.PrincipalId){Add-Result 'SQL MI managed identity' PASS "PrincipalId: $($mi.Identity.PrincipalId)"}else{Add-Result 'SQL MI managed identity' FAIL 'PrincipalId missing.' $true}
 $protector=Get-AzSqlInstanceTransparentDataEncryptionProtector -ResourceGroupName $ResourceGroupName -InstanceName $ManagedInstanceName -ErrorAction Stop
 $arp=$protector.PSObject.Properties['AutoRotationEnabled'];if(($null-ne$arp)-and($null-ne$arp.Value)){$autoRotationEnabled=[bool]$arp.Value}
 if($autoRotationEnabled){Add-Result 'TDE auto-rotation' PASS 'AutoRotationEnabled is True.'}else{Add-Result 'TDE auto-rotation' INFO 'AutoRotationEnabled is False or unavailable.'}
 $currentKeyId=[string](Get-PropertyValue $protector @('KeyId','ManagedInstanceKeyVaultKeyName','ManagedInstanceKeyName','ServerKeyName'))
 $currentVersion=Get-KeyVersion $currentKeyId
 Add-Result 'Current TDE protector' PASS "Current version: $currentVersion" $false $protector
 # STEP 5: Inventory key versions registered with SQL MI.
 $registered=@(Get-AzSqlInstanceKeyVaultKey -ResourceGroupName $ResourceGroupName -InstanceName $ManagedInstanceName -ErrorAction Stop)
 Add-Result 'Registered SQL MI keys' PASS "$($registered.Count) entries returned." $false $registered

 # STEP 6: Compare normalized key versions to avoid false URI-format mismatches.
 $matches=(-not[string]::IsNullOrWhiteSpace($currentVersion))-and$currentVersion.Equals($latestVersion,[System.StringComparison]::OrdinalIgnoreCase)
 if($matches){Add-Result 'Protector comparison' PASS 'SQL MI uses the latest eligible Key Vault version.';$actionTaken='NoChange'}
 else{
  $changeRequired=$true;Add-Result 'Protector comparison' WARNING "Current $currentVersion; latest $latestVersion."
  if($autoRotationEnabled-and(-not$ForceManualUpdateWhenAutoRotationEnabled)){$actionTaken='PendingAutoRotation';Add-Result 'Auto-rotation action' WARNING 'No manual update performed because auto-rotation is enabled.'}
  elseif($Mode-eq'ValidateOnly'){$actionTaken='ChangeRequired';Add-Result 'Execution mode' WARNING 'ValidateOnly: no changes made.'}
  else{
   if($script:BlockingFailure){throw 'Blocking checks failed.'}
   if($PSCmdlet.ShouldProcess($ManagedInstanceName,"Set TDE protector to $latestVersion")){
    $registeredVersions=@($registered|ForEach-Object{Get-KeyVersion (Get-RegisteredKeyId $_)})
    if($registeredVersions-notcontains$latestVersion){Add-AzSqlInstanceKeyVaultKey -ResourceGroupName $ResourceGroupName -InstanceName $ManagedInstanceName -KeyId $latestKeyId -ErrorAction Stop|Out-Null}
    Set-AzSqlInstanceTransparentDataEncryptionProtector -ResourceGroupName $ResourceGroupName -InstanceName $ManagedInstanceName -Type AzureKeyVault -KeyId $latestKeyId -Force -ErrorAction Stop|Out-Null
    $after=Get-AzSqlInstanceTransparentDataEncryptionProtector -ResourceGroupName $ResourceGroupName -InstanceName $ManagedInstanceName
    $afterVersion=Get-KeyVersion ([string](Get-PropertyValue $after @('KeyId','ManagedInstanceKeyVaultKeyName','ManagedInstanceKeyName','ServerKeyName')))
    if(-not$afterVersion.Equals($latestVersion,[System.StringComparison]::OrdinalIgnoreCase)){throw "Post-check expected $latestVersion, found $afterVersion."}
    Add-Result 'Post-update validation' PASS "Active protector is $afterVersion.";$actionTaken='Updated'
   }else{$actionTaken='NotExecuted'}
  }
 }

 # STEP 7: Query the SQL database engine and validate live TDE state.
 # SQL database-engine validation
 Add-Type -AssemblyName System.Data
 $b=New-Object System.Data.SqlClient.SqlConnectionStringBuilder
 $b['Data Source']="tcp:$SqlServer,$SqlPort";$b['Initial Catalog']='master';$b['User ID']=$SqlCredential.UserName;$b['Password']=$SqlCredential.GetNetworkCredential().Password;$b['Encrypt']=$true;$b['TrustServerCertificate']=$false;$b['Connect Timeout']=30
 $cn=New-Object System.Data.SqlClient.SqlConnection($b.ConnectionString)
 try{
  $cn.Open();Add-Result 'SQL MI connectivity' PASS "Connected to $($SqlServer):$SqlPort."
  $q=@"
SELECT d.name DatabaseName,d.state_desc DatabaseState,CAST(d.is_encrypted AS int) IsEncrypted,
dek.encryption_state EncryptionState,dek.encryptor_type EncryptorType,
CONVERT(varchar(256),dek.encryptor_thumbprint,1) EncryptorThumbprint,
dek.key_algorithm KeyAlgorithm,dek.key_length KeyLength,dek.modify_date DekModifyDate
FROM sys.databases d LEFT JOIN sys.dm_database_encryption_keys dek ON d.database_id=dek.database_id
WHERE d.database_id>4 ORDER BY d.name;
"@
  $cmd=$cn.CreateCommand();$cmd.CommandText=$q;$cmd.CommandTimeout=60
  $da=New-Object System.Data.SqlClient.SqlDataAdapter($cmd);$dt=New-Object System.Data.DataTable;[void]$da.Fill($dt)
  $sqlEvidence=@($dt.Rows|ForEach-Object{[pscustomobject]@{DatabaseName=[string]$_.DatabaseName;DatabaseState=[string]$_.DatabaseState;IsEncrypted=[int]$_.IsEncrypted;EncryptionState=[int]$_.EncryptionState;EncryptorType=[string]$_.EncryptorType;EncryptorThumbprint=[string]$_.EncryptorThumbprint;KeyAlgorithm=[string]$_.KeyAlgorithm;KeyLength=$_.KeyLength;DekModifyDate=$_.DekModifyDate}})
  $sqlEvidence|Format-Table -AutoSize -Wrap
  $bad=@($sqlEvidence|Where-Object{$_.DatabaseState-ne'ONLINE'-or$_.IsEncrypted-ne1-or$_.EncryptionState-ne3})
  if($bad.Count-eq0-and$sqlEvidence.Count-gt0){Add-Result 'SQL TDE encryption state' PASS 'All user databases are ONLINE and encryption_state = 3.'}else{Add-Result 'SQL TDE encryption state' FAIL "Invalid databases: $($bad.DatabaseName-join', ')." $true $bad}

  # STEP 8: Confirm one consistent encryptor thumbprint across encrypted databases.
  $sqlThumbprints=@($sqlEvidence|Where-Object{-not[string]::IsNullOrWhiteSpace($_.EncryptorThumbprint)}|Select-Object DatabaseName,EncryptorType,EncryptorThumbprint,KeyAlgorithm,KeyLength,DekModifyDate)
  $unique=@($sqlThumbprints|Select-Object -ExpandProperty EncryptorThumbprint -Unique)
  if($unique.Count-eq1){Add-Result 'SQL TDE thumbprint consistency' PASS "All encrypted databases use thumbprint '$($unique[0])'." $false $sqlThumbprints}
  elseif($unique.Count-gt1){Add-Result 'SQL TDE thumbprint consistency' WARNING "$($unique.Count) distinct thumbprints found." $false $sqlThumbprints}
  else{Add-Result 'SQL TDE thumbprint consistency' FAIL 'No SQL TDE thumbprint returned.' $true}
  $da.Dispose();$cmd.Dispose()
 }finally{if($cn.State-ne[System.Data.ConnectionState]::Closed){$cn.Close()};$cn.Dispose()}
}
catch{Add-Result 'TDE synchronization workflow' FAIL $_.Exception.Message $true;$actionTaken='Failed'}
finally{
 # STEP 9: Produce an operator-friendly recommendation before writing JSON evidence.
 $databaseCount=@($sqlEvidence).Count
 $healthyDatabaseCount=@($sqlEvidence|Where-Object{$_.DatabaseState-eq'ONLINE'-and$_.IsEncrypted-eq1-and$_.EncryptionState-eq3}).Count
 $uniqueThumbprintCount=@($sqlThumbprints|Select-Object -ExpandProperty EncryptorThumbprint -Unique).Count
 Write-Host ''
 Write-Host ('='*76)-ForegroundColor Cyan
 Write-Host 'EXECUTIVE SUMMARY AND RECOMMENDATION'-ForegroundColor Cyan
 Write-Host ('='*76)-ForegroundColor Cyan
 Write-Host "Managed Instance          : $ManagedInstanceName"
 Write-Host "Key Vault                 : $VaultName"
 Write-Host "Key Name                  : $KeyName"
 Write-Host "Auto-Rotation Enabled     : $autoRotationEnabled"
 Write-Host "Current Protector Version : $currentVersion"
 Write-Host "Latest Eligible Version   : $latestVersion"
 Write-Host "Previous Eligible Version : $previousVersion"
 Write-Host "Healthy Databases         : $healthyDatabaseCount of $databaseCount"
 Write-Host "Unique SQL Thumbprints    : $uniqueThumbprintCount"
 Write-Host "Workflow Action           : $actionTaken"
 Write-Host ''
 if($script:BlockingFailure){
  Write-Host 'RECOMMENDATION: ACTION REQUIRED' -ForegroundColor Red
  Write-Host 'Resolve blocking failures before attempting a TDE protector change.' -ForegroundColor Red
 }
 elseif($actionTaken-eq'PendingAutoRotation'){
  Write-Host 'RECOMMENDATION: MONITOR AUTO-ROTATION' -ForegroundColor Yellow
  Write-Host 'Auto-rotation is enabled but the latest version has not yet been adopted. Revalidate after propagation.' -ForegroundColor Yellow
 }
 elseif($actionTaken-eq'ChangeRequired'){
  Write-Host 'RECOMMENDATION: APPROVED CHANGE REQUIRED' -ForegroundColor Yellow
  Write-Host 'ValidateOnly found a newer eligible key version and made no changes.' -ForegroundColor Yellow
 }
 elseif(($actionTaken-eq'NoChange')-and($healthyDatabaseCount-eq$databaseCount)-and($uniqueThumbprintCount-eq1)){
  Write-Host 'RECOMMENDATION: NO ACTION REQUIRED' -ForegroundColor Green
  Write-Host 'The protector is current, database encryption is healthy, and SQL thumbprints are consistent.' -ForegroundColor Green
  Write-Host 'Continue monitoring and retain historical key versions for restore dependencies.' -ForegroundColor Green
 }
 elseif($actionTaken-eq'Updated'){
  Write-Host 'RECOMMENDATION: UPDATE COMPLETED' -ForegroundColor Green
  Write-Host 'Retain the JSON evidence with the approved change record and continue monitoring.' -ForegroundColor Green
 }
 else{
  Write-Host 'RECOMMENDATION: REVIEW DETAILED RESULTS' -ForegroundColor Yellow
 }

 $reportPath=Join-Path $OutputDirectory ("TDE-KeySync-{0}.json"-f(Get-Date -Format 'yyyyMMdd-HHmmss'))
 [ordered]@{OperationId=$operationId;StartedUtc=$startedUtc.ToString('o');CompletedUtc=(Get-Date).ToUniversalTime().ToString('o');SubscriptionId=$SubscriptionId;ResourceGroupName=$ResourceGroupName;ManagedInstanceName=$ManagedInstanceName;VaultName=$VaultName;KeyName=$KeyName;AutoRotationEnabled=$autoRotationEnabled;CurrentProtectorKeyId=$currentKeyId;CurrentProtectorVersion=$currentVersion;LatestKeyId=$latestKeyId;LatestVersion=$latestVersion;PreviousKeyId=$previousKeyId;PreviousVersion=$previousVersion;ChangeRequired=$changeRequired;ActionTaken=$actionTaken;SqlEvidence=$sqlEvidence;SqlThumbprints=$sqlThumbprints;DatabaseCount=$databaseCount;HealthyDatabaseCount=$healthyDatabaseCount;UniqueThumbprintCount=$uniqueThumbprintCount;Results=$script:Results}|ConvertTo-Json -Depth 15|Set-Content $reportPath -Encoding UTF8
 Write-Host "Report: $reportPath" -ForegroundColor Cyan
}
if($script:BlockingFailure){Write-Host 'RESULT: FAILED'-ForegroundColor Red;exit 1}
if($actionTaken-in@('ChangeRequired','PendingAutoRotation','NotExecuted')){Write-Host "RESULT: $actionTaken"-ForegroundColor Yellow;exit 2}
Write-Host "RESULT: $actionTaken"-ForegroundColor Green;exit 0
