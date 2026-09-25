<#
.SYNOPSIS
Azure SQL MI TDE Pre-Check Script
#>
[CmdletBinding()]
param(
    [string]$SqlServer = "demoarvsqlmi.public.150f743ea655.database.windows.net",
    [int]$Port = 3342,
    [string]$Username = "demoarv",
    [Parameter(Mandatory=$true)]
    [SecureString]$Password,
    [string]$Database = 'demoarv',
    [int]$ConnectionTimeout = 15
)

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script:PreCheckFailed=$false
$script:WarningFound=$false

function Write-CheckResult {
 param([string]$CheckName,[string]$Status,[string]$Message)
 Write-Host ("[{0}] {1}: {2}" -f $Status,$CheckName,$Message)
 if($Status -eq 'FAIL'){ $script:PreCheckFailed=$true }
 if($Status -eq 'WARNING'){ $script:WarningFound=$true }
}

Write-Host 'SQL MI TDE Encryption Pre-Check'

try {
 Resolve-DnsName -Name $SqlServer -ErrorAction Stop | Out-Null
 Write-CheckResult 'DNS Resolution' 'PASS' "$SqlServer resolved successfully"
} catch {
 Write-CheckResult 'DNS Resolution' 'WARNING' $_.Exception.Message
}

$tcp = Test-NetConnection -ComputerName $SqlServer -Port $Port -WarningAction SilentlyContinue
if(-not $tcp.TcpTestSucceeded){
 Write-CheckResult 'TCP Connectivity' 'FAIL' 'Cannot reach SQL MI endpoint'
 exit 1
}
Write-CheckResult 'TCP Connectivity' 'PASS' "Connected to port $Port"

$ptr=[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
try {
 $plain=[System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
 $csb=New-Object System.Data.SqlClient.SqlConnectionStringBuilder
 $csb['Data Source']="tcp:$SqlServer,$Port"
 $csb['Initial Catalog']=$Database
 $csb['User ID']=$Username
 $csb['Password']=$plain
 $csb['Encrypt']=$true
 $csb['TrustServerCertificate']=$false
 $csb['Connect Timeout']=$ConnectionTimeout

 $conn=New-Object System.Data.SqlClient.SqlConnection($csb.ConnectionString)
 $conn.Open()
 Write-CheckResult 'SQL Authentication' 'PASS' 'Authentication successful'

 $cmd=$conn.CreateCommand()
 $cmd.CommandText='SELECT @@SERVERNAME AS ServerName, DB_NAME() AS DatabaseName'
 $r=$cmd.ExecuteReader()
 if($r.Read()){ Write-CheckResult 'SQL Query Execution' 'PASS' 'Smoke test query executed successfully' }
 $r.Close()

 $tde=@"
SELECT d.name AS DatabaseName,
       d.state_desc AS DatabaseState,
       dek.encryption_state AS EncryptionState,
       dek.encryptor_type AS EncryptorType,
       CONVERT(varchar(256),dek.encryptor_thumbprint,1) AS EncryptorThumbprint
FROM sys.databases d
LEFT JOIN sys.dm_database_encryption_keys dek
 ON d.database_id=dek.database_id
WHERE d.database_id > 4
ORDER BY d.name;
"@
 $cmd2=$conn.CreateCommand(); $cmd2.CommandText=$tde
 $da=New-Object System.Data.SqlClient.SqlDataAdapter($cmd2)
 $dt=New-Object System.Data.DataTable
 [void]$da.Fill($dt)
 $dt | Format-Table -AutoSize
 Write-CheckResult 'TDE Query' 'PASS' "Returned $($dt.Rows.Count) database records"

 $conn.Close()
}
catch {
 Write-CheckResult 'SQL TDE Validation' 'FAIL' $_.Exception.Message
}
finally {
 if($ptr -ne [System.IntPtr]::Zero){
   [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
 }
}
