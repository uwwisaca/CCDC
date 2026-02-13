$DestinationFolder = ".\Sysinternals"
New-Item -Path $DestinationFolder -ItemType Directory -Force
$links = (Invoke-WebRequest -Uri 'https://live.sysinternals.com').Links
foreach ($item in $links) {
	if ($item.href -match '\.exe$') {
		$fileName = $item.href.Split('/')[-1]
		Write-Host "Downloading: $fileName"
		Invoke-WebRequest -Uri ("https://live.sysinternals.com" + $item.href) -Outfile "$DestinationFolder\$fileName" -ErrorAction SilentlyContinue
	}

}



