$services = Get-CimInstance Win32_Service | Where-Object -Property StartName -EQ "LocalSystem" | Select-Object Name
$accessToken = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$sids = @($accessToken.Groups | ForEach-Object { $_.Value })
$sids += $accessToken.User.Value

foreach ($service in $services) {
    $serviceInfo = sc.exe sdshow $($service.Name)
    $sddl = ($serviceInfo | Where-Object { $_ -match '^\s*[OGDS]:'}) -join ''
    $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($sddl)

    foreach ($ace in $descriptor.DiscretionaryAcl){

        if ($ace.SecurityIdentifier.Value -notin $sids) {
            continue
        }

        if (($ace.AccessMask -band 0x0002) -eq 0) {
            continue
        }

        if  ($ace.AceType -eq 'AccessDenied') {
            break
        } elseif ($ace.AceType -eq 'AccessAllowed') {
            Write-Output "Service $($service.Name) is potentially vulnerable to Insecure Service Permissions"
        }
    }
}
