$url = "https://download.splunk.com/products/universalforwarder/releases/9.1.1/windows/splunkforwarder-9.1.1-64e843ea36b1-x64-release.msi"
Invoke-WebRequest -Uri $url -OutFile splunkforwarder-9.1.1-64e843ea36b1-x64-release.msi

$username = Read-Host -Prompt 'Enter username for forwarder'
$password = Read-Host -Prompt 'Enter password for forwarder'
$server = Read-Host -Prompt 'Enter Splunk Server IP'
$reciever = $server + ":" + 9997
$management = $server + ":" + 8089

msiexec.exe /i splunkforwarder-9.1.1-64e843ea36b1-x64-release.msi AGREETOLICENSE=yes SPLUNKUSERNAME=$username SPLUNKPASSWORD=$password RECEIVING_INDEXER=$reciever DEPLOYMENT_SERVER=$management WINEVENTLOG_APP_ENABLE=1 WINEVENTLOG_SEC_ENABLE=1 WINEVENTLOG_SYS_ENABLE=1 ENABLEADMON=1 /quiet