<#
.Synopsis
   Script to Automated Email Reminders when Users Passwords due to Expire.
.DESCRIPTION
   Script to Automated Email Reminders when Users Passwords due to Expire.
   Original author: Robert Pearman / WindowsServerEssentials.com
   Version 2.9 August 2018
   Requires: Windows PowerShell Module for Active Directory
   For assistance and ideas, visit the TechNet Gallery Q&A Page. http://gallery.technet.microsoft.com/Password-Expiry-Email-177c3e27/view/Discussions#content

   Alternativley visit my youtube channel, https://www.youtube.com/robtitlerequired

   Videos are available to cover most questions, some videos are based on the earlier version which used static variables, however most of the code
   can still be applied to this version, for example for targeting groups, or email design.

   Please take a look at the existing Q&A as many questions are simply repeating earlier ones, with the same answers!

.NOTES
   Version 3.1 February 2022
   Author: Victor Menezes (MCP)
#>
##################################################################################################################
#Please Configure the following variables:
    # Specify where to search for users
    $SearchBase="OU=Company,DC=example,DC=com"
    # Enter Your SMTP Server Hostname or IP Address
    $smtpServer="smtp.server.address"
    # Notify Users if Expiry Less than X Days
    [int]$expireInDays=5
    # Notification Interval
    [array]$interval=5,3,1
    # From Address, eg "IT Support <support@domain.com>"
    $from="TEST <test.it@example.com>"
    # Email image
    $image="c:\image-path\example.jpg"
    # Set to Enabled or Disable Logging
    $logging="Enabled"
    # Log File Path
    $logPath="c:\log-path\logs\"
    # Testing Enabled
    $testing="Disable"
    # Test Recipient, eg recipient@domain.com
    $testRecipient="test.rec@example.com"
    # Output more detailed status to console
    $status="Enabled"
    # Set to Enabled or Disable log file report
    $reportstatus="Enabled"
    # Log file recipient
    $reportto="log@example.com"
###################################################################################################################
# Time / Date Info
$start = [datetime]::Now
$midnight = $start.Date.AddDays(1)
$timeToMidnight = New-TimeSpan -Start $start -end $midnight.Date
$midnight2 = $start.Date.AddDays(2)
$timeToMidnight2 = New-TimeSpan -Start $start -end $midnight2.Date
# System Settings
$textEncoding = [System.Text.Encoding]::UTF8
$date = Get-Date -format ddMMyyyy
$today = $start
# End System Settings

# Load AD Module
try{
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch{
    Write-Warning "Unable to load Active Directory PowerShell Module"
}
# Set Output Formatting - Padding characters
$padVal = "20"
Write-Output "Script iniciado"
Write-Output "*** Resumo das configurações ***"
$smtpServerLabel = "Servidor SMTP".PadRight($padVal," ")
$expireInDaysLabel = "Dias em que a senha vai expirar".PadRight($padVal," ")
$fromLabel = "Rementente dos e-mails".PadRight($padVal," ")
$testLabel = "Modo teste".PadRight($padVal," ")
$testRecipientLabel = "Destinatário do e-mail de teste".PadRight($padVal," ")
$logLabel = "Registro em log".PadRight($padVal," ")
$logPathLabel = "Caminho do arquivo de log".PadRight($padVal," ")
$reportToLabel = "Destinatário do arquivo de log".PadRight($padVal," ")
$interValLabel = "Intervalo de notificação por e-mail".PadRight($padval," ")
# Testing Values
if (($testing) -eq "Enabled")
{
    if(($testRecipient) -eq $null)
    {
        Write-Output "No Test Recipient Specified"
        Exit
    }
}
# Output Summary Information
Write-Output "$smtpServerLabel : $smtpServer"
Write-Output "$expireInDaysLabel : $expireInDays"
Write-Output "$fromLabel : $from"
Write-Output "$logLabel : $logging"
Write-Output "$logPathLabel : $logPath"
Write-Output "$testLabel : $testing"
Write-Output "$testRecipientLabel : $testRecipient"
Write-Output "$reportToLabel : $reportto"
Write-Output "$interValLabel : $interval"
Write-Output "*".PadRight(25,"*")
#
# Import Credential
$password = Get-Content -path "C:\password-file-path\smtp-pwd.txt" | ConvertTo-SecureString
$username = "test.it@example.com"
$credential = New-Object System.Management.Automation.PSCredential($username, $password)
#
# Get Users From AD who are Enabled, Passwords Expire and are Not Currently Expired
# To target a specific OU - use the -searchBase Parameter -https://docs.microsoft.com/en-us/powershell/module/addsadministration/get-aduser
# You can target specific group members using Get-AdGroupMember, explained here https://www.youtube.com/watch?v=4CX9qMcECVQ 
# based on earlier version but method still works here.
$users = get-aduser -SearchBase $SearchBase -filter {(Enabled -eq $true) -and (PasswordNeverExpires -eq $false)} -properties Name, PasswordNeverExpires, PasswordExpired, PasswordLastSet, UserPrincipalName | where { $_.passwordexpired -eq $false }
# Count Users
$usersCount = ($users | Measure-Object).Count
Write-Output "Found $usersCount User Objects"
# Collect Domain Password Policy Information
$defaultMaxPasswordAge = (Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop).MaxPasswordAge.Days 
Write-Output "Domain Default Password Age: $defaultMaxPasswordAge"
# Collect Users
$colUsers = @()
# Process Each User for Password Expiry
Write-Output "Process User Objects"
foreach ($user in $users)
{
    # Store User information
    $Name = $user.Name
    $emailAddress = $user.UserPrincipalName
    $passwordSetDate = $user.PasswordLastSet
    $samAccountName = $user.SamAccountName
    $pwdLastSet = $user.PasswordLastSet
    # Check for Fine Grained Password
    $maxPasswordAge = $defaultMaxPasswordAge
    $PasswordPol = (Get-AduserResultantPasswordPolicy $user) 
    if (($PasswordPol) -ne $null)
    {
        $maxPasswordAge = ($PasswordPol).MaxPasswordAge.Days
    }
    # Create User Object
    $userObj = New-Object System.Object
    $expireson = $pwdLastSet.AddDays($maxPasswordAge)
    $daysToExpire = New-TimeSpan -Start $today -End $Expireson
    # Round Expiry Date Up or Down
    if(($daysToExpire.Days -eq "0") -and ($daysToExpire.TotalHours -le $timeToMidnight.TotalHours))
    {
        $userObj | Add-Member -Type NoteProperty -Name UserMessage -Value "HOJE."
    }
    if(($daysToExpire.Days -eq "0") -and ($daysToExpire.TotalHours -gt $timeToMidnight.TotalHours) -or ($daysToExpire.Days -eq "1") -and ($daysToExpire.TotalHours -le $timeToMidnight2.TotalHours))
    {
        $userObj | Add-Member -Type NoteProperty -Name UserMessage -Value "AMANHÃ."
    }
    if(($daysToExpire.Days -ge "1") -and ($daysToExpire.TotalHours -gt $timeToMidnight2.TotalHours))
    {
        $days = $daysToExpire.TotalDays
        $days = [math]::Round($days)
        $userObj | Add-Member -Type NoteProperty -Name UserMessage -Value "em $days dias."
    }
    $daysToExpire = [math]::Round($daysToExpire.TotalDays)
    $userObj | Add-Member -Type NoteProperty -Name UserName -Value $samAccountName
    $userObj | Add-Member -Type NoteProperty -Name Name -Value $Name
    $userObj | Add-Member -Type NoteProperty -Name EmailAddress -Value $emailAddress
    $userObj | Add-Member -Type NoteProperty -Name PasswordSet -Value $pwdLastSet
    $userObj | Add-Member -Type NoteProperty -Name DaysToExpire -Value $daysToExpire
    $userObj | Add-Member -Type NoteProperty -Name ExpiresOn -Value $expiresOn
    # Add userObj to colusers array
    $colUsers += $userObj
}
# Count Users
$colUsersCount = ($colUsers | Measure-Object).Count
Write-Output "$colusersCount Usuários listados"
# Select Users to Notify
$notifyUsers = $colUsers | where { $_.DaysToExpire -le $expireInDays}
$notifiedUsers = @()
$notifyCount = ($notifyUsers | Measure-Object).Count
Write-Output "$notifyCount Usuários com a senha expirando em $expireInDays dias"
# Process notifyusers
foreach ($user in $notifyUsers)
{
    # Email Address
    $samAccountName = $user.UserName
    $emailaddress = $user.EmailAddress
    # Set Greeting Message
    $name = $user.Name
    $messageDays = $user.UserMessage
    # Subject Setting
    $subject="Senha expirando $messageDays"
    # Email Body Set Here, Note You can use HTML, including Images.
    # examples here https://youtu.be/iwvQ5tPqgW0 
    $body ="
    Olá, $name,
    <p> Informamos que a sua senha está programada para expirar $messageDays <br>
    Para evitar problemas de falta de acesso ou bloqueio do usuário, defina uma nova senha agora mesmo. <br>
	Link: https://password-change-url.example.com <br>
	<p> Observação: Os critérios abaixo devem ser respeitados para a criação da nova senha: <br>
	<p> - Mínimo X caracteres (recomendamos XX); <br>
	- Conter pelo menos X letras maiúsculas; <br>
	- Conter pelo menos X letras minúsculas; <br>
	- Conter pelo menos X números; <br>
	- Conter pelo menos X caracteres especiais (!@#$*); <br>
	- Não pode ser uma senha já utilizada previamente; <br>
	- Não deve conter o seu nome ou sobrenome. <br>
    <p>Agradecemos a atenção,<br>
    <p><b>Equipe de T.I.</b><br>
    <img src='cid:example.jpg'>
    </P>"
    # If Testing Is Enabled - Email Administrator
    if (($testing) -eq "Enabled")
    {
        $emailaddress = $testRecipient
    } # End Testing
    # If a user has no email address listed
    if(($emailaddress) -eq $null)
    {
        $emailaddress = $testRecipient    
    }# End No Valid Email
    $samLabel = $samAccountName.PadRight($padVal," ")
    try{
        # If using interval paramter - follow this section
        if($interval)
        {
            $daysToExpire = [int]$user.DaysToExpire
            # check interval array for expiry days
            if(($interval) -Contains($daysToExpire))
            {
                # if using status - output information to console
                if (($status) -eq "Enabled")
                {
                    Write-Output "Enviando e-mail: $samLabel : $emailAddress"
                }
                # Send message - if you need to use SMTP authentication watch this video https://youtu.be/_-JHzG_LNvw
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 # Set this PowerShell session to be using TLS 1.2
        Send-Mailmessage -smtpServer $smtpServer -usessl -Port 587 -from $from -to $emailaddress -subject $subject -body $body -bodyasHTML -Attachments $image -priority High -Encoding $textEncoding -Credential $credential -ErrorAction Stop
                $user | Add-Member -MemberType NoteProperty -Name SendMail -Value "Enviado"
            }
            else
            {
                # if using status - output information to console
                # No Message sent
                if (($status) -eq "Disable")
                {
                    Write-Output "Enviando e-mail: $samLabel : $emailAddress : Fora do intervalo de notificação"
                }
                $user | Add-Member -MemberType NoteProperty -Name SendMail -Value "Fora do intervalo de notificação"
            }
        }
        else
        {
            # if not using interval paramter - follow this section
            # if using status - output information to console
            if (($status) -eq "Enabled")
            {
                Write-Output "Enviando e-mail: $samLabel : $emailAddress"
            }
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 # Set this PowerShell session to be using TLS 1.2
        Send-Mailmessage -smtpServer $smtpServer -usessl -Port 587 -from $from -to $emailaddress -subject $subject -body $body -bodyasHTML -priority High -Encoding $textEncoding -Credential $credential -ErrorAction Stop
            $user | Add-Member -MemberType NoteProperty -Name SendMail -Value "Enviado"
        }
    }
    catch{
        # error section
        $errorMessage = $_.exception.Message
        # if using status - output information to console
        if (($status) -eq "Enabled")
        {
           $errorMessage
        }
        $user | Add-Member -MemberType NoteProperty -Name SendMail -Value $errorMessage    
    }
    $notifiedUsers += $user
}
if (($logging) -eq "Enabled")
{
    # Create TXT or CSV Log File
    Write-Output "Criando arquivo de log"
    $logFileName = "log-$(Get-Date -format yyyyMMdd-HHmmss).txt"
    if(($logPath.EndsWith("\")))
    {
       $logPath = $logPath -Replace ".$"
    }
    $logFile = $logPath, $logFileName -join "\"
    Write-Output "Log Output: $logfile"
    # Create TXT or CSV File and Headers
        New-Item $logfile -ItemType File
        $notifiedUsers | Out-File -Encoding UTF8 -FilePath $logFile
    if (($reportstatus) -eq "Enabled")
    {
        $reportSubject = "Relatório de usuários com a senha expirando"
        $reportBody = "Relatório em anexo."
        try{
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 # Set this PowerShell session to be using TLS 1.2
        Send-Mailmessage -smtpServer $smtpServer -usessl -Port 587 -from $from -to $reportto -subject $reportSubject -body $reportBody -bodyasHTML -priority High -Encoding $textEncoding -Credential $credential -Attachments $logFile -ErrorAction Stop 
        }
        catch{
            $errorMessage = $_.Exception.Message
            Write-Output $errorMessage
        }
    }
}
$notifiedUsers | select UserName,Name,EmailAddress,PasswordSet,DaysToExpire,ExpiresOn | sort DaystoExpire | FT -autoSize

$stop = [datetime]::Now
$runTime = New-TimeSpan $start $stop
Write-Output "Script Runtime: $runtime"
# End