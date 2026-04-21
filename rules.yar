rule Suspicious_PowerShell
{
    strings:
        $a = "powershell"
        $b = "invoke-expression"
        $c = "downloadstring"

    condition:
        2 of them
}

rule Ransomware_Behavior
{
    strings:
        $a = "CryptEncrypt"
        $b = "CryptAcquireContext"
        $c = "bitcoin"

    condition:
        2 of them
}

rule Suspicious_Network
{
    strings:
        $a = "http://"
        $b = "https://"
        $c = "socket"

    condition:
        2 of them
}

