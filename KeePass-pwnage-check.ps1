# Set the execution policy in order to run the script: Set-ExecutionPolicy Unrestricted -Scope Process

# This script facilitates checking of KeePass passwords for pwnage - or in other words, it checks if they've been leaked online.

# Inline comments describe what individual code blocks do... 


# Make sure TLS 1.2 is used. This is necessary for our API calls.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Define a function that allows the user to select files.
function FileSelector {
# This function lets the user interractively select a CSV file.
# Credit: https://4sysops.com/archives/how-to-create-an-open-file-folder-dialog-box-with-powershell/
    $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ 
        InitialDirectory = [Environment]::GetFolderPath('Desktop') 
        Filter = 'Comma Separated Value (*.csv)|*.csv'
    }
    $null = $FileBrowser.ShowDialog()
    return $FileBrowser
}

# Define a function that hashes strings.
function Get-StringHash([string] $string,$HashName = "sha1") {
# This function hashes our password using the Windows libraries.
# Credit: https://gallery.technet.microsoft.com/scriptcenter/Get-StringHash-aa843f71

$StringBuilder = New-Object System.Text.StringBuilder 
[System.Security.Cryptography.HashAlgorithm]::Create($HashName).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($string))|%{ 
[Void]$StringBuilder.Append($_.ToString("x2")) 
} 
$StringBuilder.ToString() 
}

# Define a function that checks the password hash.
function Get-KAnonymity-Results([string] $string) {
# This function queries the haveibeenpwned API. We will only pass the short hash of our passwords to it later.
    try {
        Invoke-RestMethod -Uri https://api.pwnedpasswords.com/range/$string
    } catch {
        Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ "-"$_.Exception.Response.StatusDescription
    }
}

# Get the user to select a file and add it to a variable.
$selectedFile = FileSelector

# Import the CSV data to a variable.
$database = Import-Csv -Path $selectedFile.FileName

# Expand our schema with some new empty fields for hashes and pwned status.
$database | Add-Member -MemberType NoteProperty "sha1" -Value $null
$database | Add-Member -MemberType NoteProperty "sha1Short" -Value $null
$database | Add-Member -MemberType NoteProperty "pwned" -Value $null

# Loop through our data, creating a new object.
$dataset = foreach ($entry in $database) {
    $entry # Add the original entry.
    $entry.sha1 = Get-StringHash $entry.Password # Add the sha1 password
    $entry.sha1Short = $entry.sha1.Substring(0,5) # Make a short version of the hash, which we'll send to haveibeenpwned.

    # Call the API using the short version of the hashed password.
    $hashResults = Get-KAnonymity-Results $entry.sha1Short
    # Stich the short hash to the results and look for any matches to the long hash.
    $pwned = Select-String -InputObject $hashResults -Pattern $entry.sha1.Substring(5) -AllMatches  | % { $_.Matches } | % { $_.Value }
    
    # Populate the pwned field according to our results.
    if ($pwned) {
        $entry.pwned = "pwned!"
        Write-Host "Password for" $entry.Account "pwned"
    } else { $entry.pwned = "no pwnage found!" }
}

# Build a string for exporting the results to a new file. It will be based on the old file name and location.
$selectedFileAsItem = Get-Item $selectedFile.FileName
$exportPath = [string]$selectedFileAsItem.DirectoryName + [string]$selectedFileAsItem.BaseName + "_pwned" + [string]$selectedFileAsItem.Extension

# Export to CSV.
$dataset | Export-Csv -Path $exportPath -NoTypeInformation

# Pointer to the results.
Write-Host "Check the full results at $exportPath"

# Reminder that pwned passwords don't necessarily mean pwned accounts.
Write-Host "Please note that this script only checks the security of your passwords! It does not match them to any accounts or usernames."
