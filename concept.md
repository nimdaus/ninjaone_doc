# INTRODUCTION
Whether it’s your first time working with APIs or you're an experienced developer, our example code will help you get up and running with NinjaOne’s APIs. Through our API Tours, you'll explore four core use cases, showcasing some of the most common and powerful API interactions in Python and PowerShell 5.1.

In each tour, we'll guide you through:

- Authentication and Security – Connecting to the NinjaOne API securely with OAuth and token management.
- Device Management – Retrieving, updating, and managing device data.
- Ticketing – Creating and handling tickets programmatically to streamline workflows.
- Automation – Executing commands and scripts across devices for efficient IT operations.

We’ll also show you how to test your code against mocked API environments using dummy data, giving you a safe space to build and troubleshoot with confidence before going live.

## Pre-requisites:
* On Windows check you're running Powershell 5.1.
** ```$PSVersionTable.PSVersion```
* Check you're running a modern Python 3 version, e.g., 3.11+
** ```python3 --version```

## Table of Contents
1. [Introduction](#introduction)
   - [Prerequisites](#prerequisites)
3. [Mock Server](#mock-server)
   - [Testing Code](#testing-code)
   - [Step-by-Step Guide](#step-by-step-guide)
4. [API Tours](#api-tours)
   - [Authentication and Listing Devices](#authentication-and-listing-devices)
     - [Generate an API Key](#generate-an-api-key)
     - [PowerShell 5.1](#powershell-51)
       - [API Key Example](#api-key-pull-list-example)
         - [Authentication: Getting an Access Token](#authentication-getting-an-access-token)
         - [Get-DevicesList: Making a Request](#get-deviceslist-making-a-request)
       - [OAuth2 Example](#oauth2-pull-list-example)
         - [Authentication: Getting an Access Token](#authentication-getting-an-access-token)
         - [Get-DevicesList: Making a Request](#get-deviceslist-making-a-request)
     - [Python3](#python3-1)
       - [API Key Example](#api-key-pull-list-example-1)
         - [Authentication: Getting an Access Token](#authentication-getting-an-access-token)
         - [Get-DevicesList: Making a Request](#get-deviceslist-making-a-request)
       - [OAuth2 Example](#oauth2-pull-list-example-1)
         - [Authentication: Getting an Access Token](#authentication-getting-an-access-token)
         - [Get-DevicesList: Making a Request](#get-deviceslist-making-a-request)
   - [Creating a Ticket](#creating-a-ticket)
     - [Generate an API Key](#generate-an-api-key)
     - [PowerShell 5.1](#powershell-51-1)
         - [Authentication: Getting an Access Token](#authentication-getting-an-access-token)
         - [Get-DevicesList: Making a Request](#get-deviceslist-making-a-request)
     - [Python3](#python3-2)
         - [Authentication: Getting an Access Token](#authentication-getting-an-access-token)
         - [Get-DevicesList: Making a Request](#get-deviceslist-making-a-request)
   - [Triggering a Script](#triggering-a-script)
     - [Generate an API Key](#generate-an-api-key)
     - [PowerShell 5.1](#powershell-51-2)
         - [Authentication: Getting an Access Token](#authentication-getting-an-access-token)
         - [Get-DevicesList: Making a Request](#get-deviceslist-making-a-request)
     - [Python3](#python3-3)
         - [Authentication: Getting an Access Token](#authentication-getting-an-access-token)
         - [Get-DevicesList: Making a Request](#get-deviceslist-making-a-request)
   - [Updating Device Custom Fields](#updating-device-custom-fields)
     - [Generate an API Key](#generate-an-api-key)
     - [PowerShell 5.1](#powershell-51-3)
         - [Authentication: Getting an Access Token](#authentication-getting-an-access-token)
         - [Get-DevicesList: Making a Request](#get-deviceslist-making-a-request)
     - [Python3](#python3-4)
         - [Authentication: Getting an Access Token](#authentication-getting-an-access-token)
         - [Get-DevicesList: Making a Request](#get-deviceslist-making-a-request)

# Mock server
## Testing code
A mock server simulates an API by returning predefined static or dynamic responses based on the structure and details in an API specification, like OpenAPI. It allows developers to test and interact with the API's endpoints without needing a fully functional backend, making it easier to build and test front-end applications or integration points early in development.

To use [Prism by Stoplight](https://stoplight.io/open-source/prism) with an OpenAPI spec file, you'll first need to install Prism and have the [NinjaOne OpenAPI file](www.api.NinjaOne.com) ready to go. Here’s a quick guide on how to set it up and start mocking your API:

### Step 1: Install Prism
You can install Prism as a binary to avoid requiring npm and Node.js:

powershell
```Invoke-WebRequest -Uri https://github.com/stoplightio/prism/releases/latest/download/prism-cli-win.exe -OutFile prism-cli-win.exe```
bash
```curl -L https://raw.githack.com/stoplightio/prism/master/install | sh```

### Step 2: Start the Mock Server
With Prism installed, point it to your OpenAPI file to mock the API responses. For example, if you have an OpenAPI file named api-spec.yaml:

powershell
```.\prism-cli-win.exe mock api-spec.yaml```
bash
```prism mock api-spec.yaml```
This will start a mock server at http://127.0.0.1:4010. You can make requests to the server using the endpoints and responses defined in api-spec.yaml.

To enable dynamic responses (to vary outputs), use the --dynamic flag:

powershell
```.\prism-cli-win.exe mock api-spec.yaml --dynamic```
bash
```prism mock api-spec.yaml --dynamic```

### Step 3: Test the Mocked Endpoints
You can now test your API endpoints by sending requests to the mock server. For instance, if your OpenAPI spec defines a /users endpoint, you can access it with:

powershell
```Invoke-WebRequest -Uri http://127.0.0.1:4010/v2/devices```
bash
```curl http://127.0.0.1:4010/v2/devices```
Prism will return the mock response defined for /devices in the NinjaOne OpenAPI spec file, allowing you to test the NinjaOne API’s behavior and interactions.

# API tour for authentication (and listing devices)
## Generate an API key
LINK TO NINJAONE DOCUMENTATION

The first step is from your NinjaOne portal to navigate to Administration > Applications > API and to add a new Client App ID. For more information, see the NinjaOne Dojo.

In this example we'll be using a:
* Machine-to-Machine application
* Monitoring only permissions
* client credentials
## Powershell 5.1
### API Key pull list example
#### Authentication: Geting an Access Token
To authenticate with client credentials to NinjaOne we'll formulate a request using our access variables to generate an access token that we'll then use to pull a list of devices.
Noteworthy in this example:
* protect your client_secret using securestring and nullifying the variable after usage to maintain security
```
$headers = @{
    "Content-Type" = "application/x-www-form-urlencoded"
}
$region = Read-Host "Enter a region, e.g., CA"
$client_id = Read-Host "Enter the client_id"
$client_secret = Read-Host "Enter the client_secret" -AsSecureString
$grant_type = "client_credentials"
$scope = Read-Host "Enter *SPACE* separated scope, e.g., control management monitoring"
$scope = [System.Net.WebUtility]::UrlEncode($scope)
$plain_client_secret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($client_secret))

$response = Invoke-WebRequest -Uri "https://$($region).ninjarmm.com/ws/oauth/token" -Method POST -Headers $headers -ContentType "application/x-www-form-urlencoded" -Body "grant_type=$($grant_type)&client_id=$($client_id)&client_secret=$($plain_client_secret)&scope=$($scope)"
$plainClientSecret = $null

$response_data = $response.Content | ConvertFrom-Json
$access_token = $response_data.access_token
```
#### Get-DevicesList: Making a Request
with the access token in place, we can use it to make a request to NinjaOne API for a list of devices in our account.
Noteworthy in this example:
* The | ("pipe") passes the output from one command to another
* `$response | ConvertFrom-Json | ConvertTo-Json -Depth 100` is used to "pretty print" the NinjaOne API response for easier human reading.
```
$headers = @{
    "Accept" = "application/json"
    "Authorization" = "Bearer $access_token"
}
$response = Invoke-WebRequest -Uri "https://$($region).ninjarmm.com/v2/devices" -Method GET -Headers $headers
$response | ConvertFrom-Json | ConvertTo-Json -Depth 100
```
### Oauth2 pull list example

```
$region = Read-Host "Enter a region, e.g., CA"
$client_id = Read-Host "Enter the client_id"
$client_secret = Read-Host "Enter the client_secret" -AsSecureString
$response_type = "code"
$scope = Read-Host "Enter *SPACE* separated scope, e.g., control management monitoring"
$scope = [uri]::EscapeDataString($scope) #this encoded right
$plain_client_secret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($client_secret))
$redirect_uri = Read-Host "Enter the route from app registration, e.g., https://localhost *OR* https://webhook.site/00000000-0000-0000-0000-000000000000"

$uri = "https://$($region).ninjarmm.com/oauth/authorize?" +
    "response_type=$($response_type)&" +
    "client_id=$($client_id)&" +
    "client_secret=$($plain_client_secret)&" +
    "redirect_uri=$($redirect_uri)&" +
    "scope=$scope"

Start-Process $uri

$auth_code = Read-Host "Enter the authorization code from receipt" -AsSecureString
$plain_auth_code = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($auth_code))

$headers = @{
    "Content-Type" = "application/x-www-form-urlencoded"
}
$grant_type	= "authorization_code"

$body = "grant_type=$($grant_type)&" +
    "client_id=$($client_id)&" +
    "client_secret=$($plain_client_secret)&" +
    "code=$($plain_auth_code)&" +
    "redirect_uri=$($redirect_uri)"


$response = Invoke-WebRequest -Uri "https://$($region).ninjarmm.com/ws/oauth/token" -Method POST -Headers $headers -Body $body
$response_data = $response.Content | ConvertFrom-Json
$access_token = $response_data.access_token

$headers = @{
    "Accept" = "application/json"
    "Authorization" = "Bearer $access_token"
}

$response = Invoke-WebRequest -Uri "https://$($region).ninjarmm.com/v2/devices" -Method GET -Headers $headers
$response | ConvertFrom-Json | ConvertTo-Json -Depth 100
```

## Python3
### API Key pull list example

```
import requests
import getpass
import json

region = input("Enter region: ")
client_id = input("Enter client_id: ")
client_secret = getpass.getpass("Enter your client_secret: ")
grant_type = "client_credentials"
scope = input("Enter *SPACE* separated scope, e.g., control management monitoring: ")

url = f"https://{region}.ninjarmm.com/ws/oauth/token"

payload = {
    "grant_type": f"{grant_type}",
    "client_id": f"{client_id}",
    "client_secret": f"{client_secret}",
    "scope": f"{scope}"
}
headers = {"Content-Type": "application/x-www-form-urlencoded"}

response = requests.post(url, data=payload, headers=headers)
client_secret = None

response = response.json()
access_token = response["access_token"]

url = f"https://{region}.ninjarmm.com/v2/devices"

headers = {
    "Accept": "application/json",
    "Authorization": f"Bearer {access_token}"
}

response = requests.get(url, headers=headers)

print(json.dumps(response.json(), indent=4))
```
### Oauth2 pull list example
import requests
import getpass
import json
import webbrowser

region = input("Enter region: ")
client_id = input("Enter client_id: ")
client_secret = getpass.getpass("Enter your client_secret(no visible input): ")
response_type = "code"
redirect_uri = input("Enter redirect_uri: ")
scope = input("Enter *SPACE* separated scope, e.g., control management monitoring: ")

auth_url = (
    f"https://{region}.ninjarmm.com/ws/oauth/authorize?"
    f"response_type={response_type}&"
    f"client_id={client_id}&"
    f"client_secret={client_secret}&"
    f"redirect_uri={redirect_uri}&"
    f"scope={scope}"
)

print("Opening browser for authentication...")
webbrowser.open(auth_url, new=1, autoraise=True)

print(f"\nIf the browser does not open, please navigate to the following URL to authenticate:\n{auth_url}")

code = input("Please enter the NinjaOne authorization code from the redirect URL: ")

url = f"https://{region}.ninjarmm.com/ws/oauth/token"

payload = {
    "grant_type": "authorization_code",
    "client_id": f"{client_id}",
    "client_secret": f"{client_secret}",
    "code": f"{code}",
    "redirect_uri": f"{redirect_uri}"
}

headers = {"Content-Type": "application/x-www-form-urlencoded"}
response = requests.post(url, data=payload, headers=headers)

response_data = response.json()

access_token = response_data["access_token"]

url = f"https://{region}.ninjarmm.com/v2/devices"

headers = {
    "Accept": "application/json",
    "Authorization": "Bearer {access_token}"
}

response = requests.get(url, headers=headers)
print(json.dumps(response.json(), indent=4))





# API tour for creating a ticket
## Generate an API key
LINK TO NINJAONE DOCUMENTATION

The first step is from your NinjaOne portal to navigate to Administration > Applications > API and to add a new Client App ID. For more information, see the NinjaOne Dojo.

In this example we'll be using a:
* Web application
* Management only permissions
* Authorization Code
## Powershell 5.1
### Oauth2 example
```
function Throw-ErrorResponseWithResultCode {
    param (
        [Parameter(Mandatory=$true)]
        [pscustomobject]$Response,
        
        [Parameter(Mandatory=$true)]
        [string]$Message
    )

    # Construct the resultCode message only if resultCode is present
    $resultCodeMessage = if ($Response.PSObject.Properties["resultCode"]) { 
        "`nStated reason: $($Response.resultCode)" 
    } else { 
        "" 
    }
    
    # Throw the formatted error message with customizable message
    throw "`n$Message`nUnexpected Status Code: $($Response.StatusCode)$resultCodeMessage"
}

# Function to Display Tables
function Display-Table {
    param (
        [array]$Data,
        [string]$SortKey,
        [string]$SecondColumnKey,
        [string]$Title
    )
    Write-Host "`n$Title`n" -ForegroundColor Cyan
    $sortedData = $Data | Sort-Object $SortKey
    $displayData = $sortedData | Select-Object @{Name=$SortKey; Expression={$_.($SortKey)}}, @{Name=$SecondColumnKey; Expression={$_.($SecondColumnKey)}}
    $displayData | Format-Table -AutoSize
}

# Function to Prompt for Integer Input with Default
function Prompt-Int {
    param (
        [string]$Message,
        [int]$Default
    )
    $input = Read-Host "$Message (Default: $Default)"
    if ([string]::IsNullOrWhiteSpace($input)) {
        return $Default
    } elseif ($input -match '^\d+$') {
        return [int]$input
    } else {
        Write-Host "Invalid input. Please enter a valid integer." -ForegroundColor Yellow
        return Prompt-Int -Message $Message -Default $Default
    }
}

# Function to Prompt for Choice Input with Default
function Prompt-Choice {
    param (
        [string]$Message,
        [Parameter(Mandatory=$true)] $Default,
        [Parameter(Mandatory=$true)] [array]$Choices
    )

    # Display choices with numbers
    Write-Host $Message
    for ($i = 0; $i -lt $Choices.Length; $i++) {
        Write-Host "$($i + 1): $($Choices[$i])"
    }

    # Find the index of the default choice (if it exists in $Choices)
    $defaultIndex = $Choices.IndexOf($Default) + 1
    $input = Read-Host "Select an option by number (Default: $defaultIndex)"

    # If no input, return the default choice
    if ([string]::IsNullOrWhiteSpace($input)) {
        return $Default
    }

    # Validate input as an integer within range
    if ([int]::TryParse($input, [ref]$null) -and $input -ge 1 -and $input -le $Choices.Length) {
        return $Choices[$input - 1]
    } else {
        Write-Host "Invalid choice. Please select a valid number." -ForegroundColor Yellow
        return Prompt-Choice -Message $Message -Default $Default -Choices $Choices
    }
}

$region = Read-Host "Enter a region, e.g., CA"
$client_id = Read-Host "Enter the client_id"
$client_secret = Read-Host "Enter the client_secret" -AsSecureString
$response_type = "code"
$scope = Read-Host "Enter *SPACE* separated scope, e.g., control management monitoring"
$scope = [uri]::EscapeDataString($scope) #this encoded right
$plain_client_secret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($client_secret))
$redirect_uri = Read-Host "Enter the route from app registration, e.g., https://localhost *OR* https://webhook.site/00000000-0000-0000-0000-000000000000"

$uri = "https://$($region).ninjarmm.com/oauth/authorize?" +
    "response_type=$($response_type)&" +
    "client_id=$($client_id)&" +
    "client_secret=$($plain_client_secret)&" +
    "redirect_uri=$($redirect_uri)&" +
    "scope=$scope"

Start-Process $uri

$auth_code = Read-Host "Enter the authorization code from receipt" -AsSecureString
$plain_auth_code = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($auth_code))

$headers = @{
    "Content-Type" = "application/x-www-form-urlencoded"
}
$grant_type	= "authorization_code"

$body = "grant_type=$($grant_type)&" +
    "client_id=$($client_id)&" +
    "client_secret=$($plain_client_secret)&" +
    "code=$($plain_auth_code)&" +
    "redirect_uri=$($redirect_uri)"

$response = Invoke-WebRequest -Uri "https://$($region).ninjarmm.com/ws/oauth/token" -Method POST -Headers $headers -Body $body
if ($response.StatusCode -eq 200) {
    $response_data = $response.Content | ConvertFrom-Json
    $access_token = $response_data.access_token
} else {
    Throw-ErrorResponseWithResultCode -Response $response -Message "Authorization Failed"
}

$headers = @{
    "Accept" = "application/json"
    "Authorization" = "Bearer $access_token"
}

# Fetch Ticket Forms
$response = Invoke-WebRequest -Uri "https://$region.ninjarmm.com/v2/ticketing/ticket-form" -Method GET -Headers $headers -ErrorAction Stop
if ($response.StatusCode -eq 200) {
    $ticket_forms = $response.Content | ConvertFrom-Json
    Display-Table -Data $ticket_forms -SortKey 'id' -SecondColumnKey 'name' -Title "Ticket Forms"
    $form_id = Prompt-Int -Message "Enter the Ticket Form ID to use" -Default 1
} else {
    Throw-ErrorResponseWithResultCode -Response $response -Message "Ticket Form Collection Failed"
}

# Fetch Statuses
$response = Invoke-WebRequest -Uri "https://$region.ninjarmm.com/v2/ticketing/statuses" -Method GET -Headers $headers -ErrorAction Stop
if ($response.StatusCode -eq 200) {
    $statuses = $response.Content | ConvertFrom-Json
    Display-Table -Data $statuses -SortKey 'statusId' -SecondColumnKey 'displayName' -Title "Ticket Statuses"
    $status_id = Prompt-Int -Message "Enter the Status ID to assign to the ticket" -Default 1000
} else {
    Throw-ErrorResponseWithResultCode -Response $response -Message "Ticket Status Collection Failed"
}

# Fetch Organizations
$response = Invoke-WebRequest -Uri "https://$region.ninjarmm.com/v2/organizations" -Method GET -Headers $headers -ErrorAction Stop
if ($response.StatusCode -eq 200) {
    $organizations = $response.Content | ConvertFrom-Json
    Display-Table -Data $organizations -SortKey 'id' -SecondColumnKey 'name' -Title "Organizations"
    $client_id = Prompt-Int -Message "Enter the Organization ID to associate with the ticket" -Default 1
} else {
    Throw-ErrorResponseWithResultCode -Response $response -Message "Organization Collection Failed"
}

# Fetch Ticket Attributes
$response = Invoke-WebRequest -Uri "https://$region.ninjarmm.com/v2/ticketing/attributes" -Method GET -Headers $headers -ErrorAction Stop
if ($response.StatusCode -eq 200) {
    Write-Host $response 
    $ticket_attributes = $response.Content | ConvertFrom-Json
    Display-Table -Data $ticket_attributes -SortKey 'id' -SecondColumnKey 'description' -Title "Ticket Attributes"
    $attribute_id = Prompt-Int -Message "Enter the Ticket Attribute ID to associate with the ticket" -Default $null
    $selected_attribute = $ticket_attributes | Where-Object { $_.id -eq $attribute_id }
    $attribute_values = $selected_attribute.content.values
    Write-Host "`nAvailable Values for Attribute '$($selected_attribute.name)':`n" -ForegroundColor Cyan
    $attribute_values | Select-Object @{Name='Value ID'; Expression={$_.id}}, @{Name='Name'; Expression={$_.name}}, @{Name='Active'; Expression={$_.active}}, @{Name='System'; Expression={$_.system}} | Format-Table -AutoSize    
    $attribute_value = Prompt-Int -Message "Enter the Ticket Attribute Value to associate with the ticket attribute" -Default $null
} else {
    Throw-ErrorResponseWithResultCode -Response $response -Message "Ticket Attribute Collection Failed"
}

# Collect Ticket Details from User
$subject = Read-Host "Enter the Subject of the ticket"
$description = Read-Host "Enter the Description of the ticket"
$description_public = Prompt-Choice -Message "Is the description public?" -Default $true -Choices @($true, $false)
$priority = Prompt-Choice -Message "Choose the Priority" -Default "NONE" -Choices @("NONE", "HIGH", "LOW", "MEDIUM")
$ticket_type = Prompt-Choice -Message "Choose the Type" -Default "PROBLEM" -Choices @("PROBLEM", "QUESTION", "INCIDENT", "TASK")

# Create the Payload
$payload = @{
    clientId = $client_id
    ticketFormId = $form_id
    subject = $subject
    description = @{
        public = $description_public
        body = $description
        htmlBody = "<p>$description</p>"
    }
    status = "$status_id"
    type = $ticket_type
    priority = $priority
    attributes = @(
        @{
            attributeId = $attribute_id
            value = $attribute_value
        }
    )
} | ConvertTo-Json -Depth 10

# POST Request to Create the Ticket
$response = Invoke-WebRequest -Uri "https://$region.ninjarmm.com/v2/ticketing/ticket" -Method POST -Headers $headers -Body $payload -ContentType "application/json" -ErrorAction Stop
if (($response.StatusCode -eq 200 -or $response.StatusCode -eq 201) -and $response.Content.Count -gt 0) {
    Write-Host "Ticket created successfully!" -ForegroundColor Green
    Write-Host "Ticket contents" -ForegroundColor Cyan
    $response.Content | ConvertFrom-Json | Format-List
} else {
    Throw-ErrorResponseWithResultCode -Response $response -Message "Ticket Creation Failed"
}

```

## Python3
### Oauth2 example
```
import requests
import getpass
import json
import webbrowser

def throw_error_response_with_result_code(response, message):
    result_code_message = f"\nStated reason: {response.json().get('resultCode')}" if 'resultCode' in response.json() else ""
    raise Exception(f"\n{message}\nUnexpected Status Code: {response.status_code}{result_code_message}")

def display_table(data, sort_key, second_column_key, title):
    print(f"\n{title}\n")
    sorted_data = sorted(data, key=lambda x: x[sort_key])
    for item in sorted_data:
        print(f"{item[sort_key]:<20} {item[second_column_key]}")
    print("\n")

def prompt_int(message, default):
    while True:
        user_input = input(f"{message} (Default: {default}): ")
        if not user_input.strip():
            return default
        try:
            return int(user_input)
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

def prompt_choice(message, default, choices):
    print(message)
    for index, choice in enumerate(choices, start=1):
        print(f"{index}: {choice}")
    
    default_index = choices.index(default) + 1
    while True:
        user_input = input(f"Select an option by number (Default: {default_index}): ")
        if not user_input.strip():
            return default
        if user_input.isdigit() and 1 <= int(user_input) <= len(choices):
            return choices[int(user_input) - 1]
        else:
            print("Invalid choice. Please select a valid number.")

region = input("Enter region: ")
client_id = input("Enter client_id: ")
client_secret = getpass.getpass("Enter your client_secret(no visible input): ")
response_type = "code"
redirect_uri = input("Enter redirect_uri: ")
scope = input("Enter *SPACE* separated scope, e.g., control management monitoring: ")

auth_url = (
    f"https://{region}.ninjarmm.com/ws/oauth/authorize?"
    f"response_type={response_type}&"
    f"client_id={client_id}&"
    f"client_secret={client_secret}&"
    f"redirect_uri={redirect_uri}&"
    f"scope={scope}"
)

print("Opening browser for authentication...")
webbrowser.open(auth_url, new=1, autoraise=True)

print(f"\nIf the browser does not open, please navigate to the following URL to authenticate:\n{auth_url}")

code = input("Please enter the NinjaOne authorization code from the redirect URL: ")

url = f"https://{region}.ninjarmm.com/ws/oauth/token"

payload = {
    "grant_type": "authorization_code",
    "client_id": f"{client_id}",
    "client_secret": f"{client_secret}",
    "code": f"{code}",
    "redirect_uri": f"{redirect_uri}"
}

headers = {"Content-Type": "application/x-www-form-urlencoded"}
response = requests.post(url, data=payload, headers=headers)

response_data = response.json()

access_token = response_data["access_token"]

headers = {
    "Accept": "application/json",
    "Authorization": "Bearer {access_token}"
}

# Fetch Ticket Forms
response = requests.get(f"https://{region}.ninjarmm.com/v2/ticketing/ticket-form", headers=headers)
if response.status_code == 200:
    ticket_forms = response.json()
    display_table(ticket_forms, 'id', 'name', "Ticket Forms")
    form_id = prompt_int("Enter the Ticket Form ID to use", 1)
else:
    throw_error_response_with_result_code(response, "Ticket Form Collection Failed")

# Fetch Statuses
response = requests.get(f"https://{region}.ninjarmm.com/v2/ticketing/statuses", headers=headers)
if response.status_code == 200:
    statuses = response.json()
    display_table(statuses, 'statusId', 'displayName', "Ticket Statuses")
    status_id = prompt_int("Enter the Status ID to assign to the ticket", 1000)
else:
    throw_error_response_with_result_code(response, "Ticket Status Collection Failed")

# Fetch Organizations
response = requests.get(f"https://{region}.ninjarmm.com/v2/organizations", headers=headers)
if response.status_code == 200:
    organizations = response.json()
    display_table(organizations, 'id', 'name', "Organizations")
    client_id = prompt_int("Enter the Organization ID to associate with the ticket", 1)
else:
    throw_error_response_with_result_code(response, "Organization Collection Failed")

# Fetch Ticket Attributes
response = requests.get(f"https://{region}.ninjarmm.com/v2/ticketing/attributes", headers=headers)
if response.status_code == 200:
    ticket_attributes = response.json()
    display_table(ticket_attributes, 'id', 'description', "Ticket Attributes")
    attribute_id = prompt_int("Enter the Ticket Attribute ID to associate with the ticket", None)
    selected_attribute = next((attr for attr in ticket_attributes if attr['id'] == attribute_id), None)
    if selected_attribute:
        attribute_values = selected_attribute['content']['values']
        print(f"\nAvailable Values for Attribute '{selected_attribute['name']}':\n")
        for value in attribute_values:
            print(f"Value ID: {value['id']} | Name: {value['name']} | Active: {value['active']} | System: {value['system']}")
        attribute_value = prompt_int("Enter the Ticket Attribute Value to associate with the ticket attribute", None)
else:
    throw_error_response_with_result_code(response, "Ticket Attribute Collection Failed")

# Collect Ticket Details from User
subject = input("Enter the Subject of the ticket: ")
description = input("Enter the Description of the ticket: ")
description_public = prompt_choice("Is the description public?", True, [True, False])
priority = prompt_choice("Choose the Priority", "NONE", ["NONE", "HIGH", "LOW", "MEDIUM"])
ticket_type = prompt_choice("Choose the Type", "PROBLEM", ["PROBLEM", "QUESTION", "INCIDENT", "TASK"])

# Create the Payload
payload = {
    "clientId": client_id,
    "ticketFormId": form_id,
    "subject": subject,
    "description": {
        "public": description_public,
        "body": description,
        "htmlBody": f"<p>{description}</p>"
    },
    "status": str(status_id),
    "type": ticket_type,
    "priority": priority,
    "attributes": [
        {
            "attributeId": attribute_id,
            "value": attribute_value
        }
    ]
}

# POST Request to Create the Ticket
response = requests.post(f"https://{region}.ninjarmm.com/v2/ticketing/ticket", headers=headers, json=payload)
if response.status_code in [200, 201] and response.content:
    print("Ticket created successfully!")
    print("Ticket contents:")
    print(json.dumps(response.json(), indent=4))
else:
    throw_error_response_with_result_code(response, "Ticket Creation Failed")


<!-- print(json.dumps(response.json(), indent=4)) -->

```


# API tour for triggering a script
## Generate an API key
LINK TO NINJAONE DOCUMENTATION

The first step is from your NinjaOne portal to navigate to Administration > Applications > API and to add a new Client App ID. For more information, see the NinjaOne Dojo.

In this example we'll be using a:
* Web application
* Management and Monitoring only permissions
* Authorization Code
## Powershell 5.1
### Oauth2 example
THIS IS MISSING PARAMETERS
```
function Throw-ErrorResponseWithResultCode {
    param (
        [Parameter(Mandatory=$true)]
        [pscustomobject]$Response,
        
        [Parameter(Mandatory=$true)]
        [string]$Message
    )

    # Construct the resultCode message only if resultCode is present
    $resultCodeMessage = if ($Response.PSObject.Properties["resultCode"]) { 
        "`nStated reason: $($Response.resultCode)" 
    } else { 
        "" 
    }
    
    # Throw the formatted error message with customizable message
    throw "`n$Message`nUnexpected Status Code: $($Response.StatusCode)$resultCodeMessage"
}

# Function to Display Tables
function Display-Table {
    param (
        [array]$Data,
        [string]$SortKey,
        [string]$SecondColumnKey,
        [string]$Title
    )
    Write-Host "`n$Title`n" -ForegroundColor Cyan
    $sortedData = $Data | Sort-Object $SortKey
    $displayData = $sortedData | Select-Object @{Name=$SortKey; Expression={$_.($SortKey)}}, @{Name=$SecondColumnKey; Expression={$_.($SecondColumnKey)}}
    $displayData | Format-Table -AutoSize
}

# Function to Prompt for Integer Input with Default
function Prompt-Int {
    param (
        [string]$Message,
        [int]$Default
    )
    $input = Read-Host "$Message (Default: $Default)"
    if ([string]::IsNullOrWhiteSpace($input)) {
        return $Default
    } elseif ($input -match '^\d+$') {
        return [int]$input
    } else {
        Write-Host "Invalid input. Please enter a valid integer." -ForegroundColor Yellow
        return Prompt-Int -Message $Message -Default $Default
    }
}

# Function to Prompt for Choice Input with Default
function Prompt-Choice {
    param (
        [string]$Message,
        [Parameter(Mandatory=$true)] $Default,
        [Parameter(Mandatory=$true)] [array]$Choices
    )

    # Display choices with numbers
    Write-Host $Message
    for ($i = 0; $i -lt $Choices.Length; $i++) {
        Write-Host "$($i + 1): $($Choices[$i])"
    }

    # Find the index of the default choice (if it exists in $Choices)
    $defaultIndex = $Choices.IndexOf($Default) + 1
    $input = Read-Host "Select an option by number (Default: $defaultIndex)"

    # If no input, return the default choice
    if ([string]::IsNullOrWhiteSpace($input)) {
        return $Default
    }

    # Validate input as an integer within range
    if ([int]::TryParse($input, [ref]$null) -and $input -ge 1 -and $input -le $Choices.Length) {
        return $Choices[$input - 1]
    } else {
        Write-Host "Invalid choice. Please select a valid number." -ForegroundColor Yellow
        return Prompt-Choice -Message $Message -Default $Default -Choices $Choices
    }
}

$region = Read-Host "Enter a region, e.g., CA"
$client_id = Read-Host "Enter the client_id"
$client_secret = Read-Host "Enter the client_secret" -AsSecureString
$response_type = "code"
$scope = Read-Host "Enter *SPACE* separated scope, e.g., control management monitoring"
$scope = [uri]::EscapeDataString($scope) #this encoded right
$plain_client_secret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($client_secret))
$redirect_uri = Read-Host "Enter the route from app registration, e.g., https://localhost *OR* https://webhook.site/00000000-0000-0000-0000-000000000000"

$uri = "https://$($region).ninjarmm.com/oauth/authorize?" +
    "response_type=$($response_type)&" +
    "client_id=$($client_id)&" +
    "client_secret=$($plain_client_secret)&" +
    "redirect_uri=$($redirect_uri)&" +
    "scope=$scope"

Start-Process $uri

$auth_code = Read-Host "Enter the authorization code from receipt" -AsSecureString
$plain_auth_code = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($auth_code))

$headers = @{
    "Content-Type" = "application/x-www-form-urlencoded"
}
$grant_type	= "authorization_code"

$body = "grant_type=$($grant_type)&" +
    "client_id=$($client_id)&" +
    "client_secret=$($plain_client_secret)&" +
    "code=$($plain_auth_code)&" +
    "redirect_uri=$($redirect_uri)"

$response = Invoke-WebRequest -Uri "https://$($region).ninjarmm.com/ws/oauth/token" -Method POST -Headers $headers -Body $body
if ($response.StatusCode -eq 200) {
    $response_data = $response.Content | ConvertFrom-Json
    $access_token = $response_data.access_token
} else {
    Throw-ErrorResponseWithResultCode -Response $response -Message "Authorization Failed"
}

$headers = @{
    "Accept" = "application/json"
    "Authorization" = "Bearer $access_token"
}

# Fetch organizations
$response = Invoke-WebRequest -Uri "https://$region.ninjarmm.com/v2/organizations" -Method GET -Headers $headers -ErrorAction Stop
if ($response.StatusCode -eq 200) {
    $organizations = $response.Content | ConvertFrom-Json
    Display-Table -Data $organizations -SortKey 'id' -SecondColumnKey 'name' -Title "Organizations"
    $organization_id = Prompt-Int -Message "Enter the applicable organization ID" -Default 1
} else {
    Throw-ErrorResponseWithResultCode -Response $response -Message "Organization Collection Failed"
}

# Fetch Devices
$response = Invoke-WebRequest -Uri "https://$region.ninjarmm.com/v2/devices?df=org=$($organization_id)" -Method GET -Headers $headers -ErrorAction Stop
if ($response.StatusCode -eq 200) {
    $devices = $response.Content | ConvertFrom-Json
    Display-Table -Data $devices -SortKey 'id' -SecondColumnKey 'systemName' -Title "Devices"
    $device_id = Prompt-Int -Message "Enter the Device ID to lookup" -Default 1
} else {
    Throw-ErrorResponseWithResultCode -Response $response -Message "Devices Collection Failed"
}

# Fetch Device Scripts
$response = Invoke-WebRequest -Uri "https://$region.ninjarmm.com/v2/device/$($device_id)/scripting/options" -Method GET -Headers $headers -ErrorAction Stop
if ($response.StatusCode -eq 200) {
    $device_scripts = $response.Content.scripts | ConvertFrom-Json
    Display-Table -Data $device_scripts -SortKey 'id' -SecondColumnKey 'name' -Title "Device Scripts"
    $device_script_id = Prompt-Int -Message "Enter the Script ID to select" -Default 1000
    $selected_device_script = $device_scripts | Where-Object { $_.id -eq $device_script_id}
    $attribute_values = $selected_attribute.content.values
    $device_script = a
} else {
    Throw-ErrorResponseWithResultCode -Response $response -Message "Device Script Collection Failed"
}

$run_as = Prompt-Choice -Message "Choose the identity to run the script as" -Default "loggedonuser" -Choices @("system","SR_MAC_SCRIPT","SR_LINUX_SCRIPT","loggedonuser","SR_LOCAL_ADMINISTRATOR","SR_DOMAIN_ADMINISTRATOR")

<!-- Need to figure out how to pass parameters -->

# Create the Payload
$payload = @{
    "type": $selected_device_script.type,
    <!-- "parameters": "string", -->
    "runAs": $run_as
}

# Add uid only if type equals "action"
if ($selected_device_script.type -eq "action") {
    $payload["uid"] = $selected_device_script.uid
} else {
    $payload["id"] = $selected_device_script.id
}

$payload = $payload | ConvertTo-Json -Depth 10

headers = {
    "Content-Type": "application/json",
    "Accept": "*/*",
    "Authorization": "Bearer undefined"
}

# POST Request to Execute the script
$response = Invoke-WebRequest -Uri "https://$region.ninjarmm.com/v2/device/$($device_id)/script/run" -Method POST -Headers $headers -Body $payload -ContentType "application/json" -ErrorAction Stop
if (($response.StatusCode -eq 200 -or $response.StatusCode -eq 201) -and $response.Content.Count -gt 0) {
    Write-Host "Script executed!" -ForegroundColor Green
    $response.Content | ConvertFrom-Json | Format-List
} else {
    Throw-ErrorResponseWithResultCode -Response $response -Message "Script Execution Failed"
}

```

## Python3
### Oauth2 example
```
import requests
import getpass
import json
import webbrowser

def throw_error_response_with_result_code(response, message):
    result_code_message = f"\nStated reason: {response.json().get('resultCode')}" if 'resultCode' in response.json() else ""
    raise Exception(f"\n{message}\nUnexpected Status Code: {response.status_code}{result_code_message}")

def display_table(data, sort_key, second_column_key, title):
    print(f"\n{title}\n")
    sorted_data = sorted(data, key=lambda x: x[sort_key])
    for item in sorted_data:
        print(f"{item[sort_key]:<20} {item[second_column_key]}")
    print("\n")

def prompt_int(message, default):
    while True:
        user_input = input(f"{message} (Default: {default}): ")
        if not user_input.strip():
            return default
        try:
            return int(user_input)
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

def prompt_choice(message, default, choices):
    print(message)
    for index, choice in enumerate(choices, start=1):
        print(f"{index}: {choice}")
    
    default_index = choices.index(default) + 1
    while True:
        user_input = input(f"Select an option by number (Default: {default_index}): ")
        if not user_input.strip():
            return default
        if user_input.isdigit() and 1 <= int(user_input) <= len(choices):
            return choices[int(user_input) - 1]
        else:
            print("Invalid choice. Please select a valid number.")

region = input("Enter region: ")
client_id = input("Enter client_id: ")
client_secret = getpass.getpass("Enter your client_secret(no visible input): ")
response_type = "code"
redirect_uri = input("Enter redirect_uri: ")
scope = input("Enter *SPACE* separated scope, e.g., control management monitoring: ")

auth_url = (
    f"https://{region}.ninjarmm.com/ws/oauth/authorize?"
    f"response_type={response_type}&"
    f"client_id={client_id}&"
    f"client_secret={client_secret}&"
    f"redirect_uri={redirect_uri}&"
    f"scope={scope}"
)

print("Opening browser for authentication...")
webbrowser.open(auth_url, new=1, autoraise=True)

print(f"\nIf the browser does not open, please navigate to the following URL to authenticate:\n{auth_url}")

code = input("Please enter the NinjaOne authorization code from the redirect URL: ")

url = f"https://{region}.ninjarmm.com/ws/oauth/token"

payload = {
    "grant_type": "authorization_code",
    "client_id": f"{client_id}",
    "client_secret": f"{client_secret}",
    "code": f"{code}",
    "redirect_uri": f"{redirect_uri}"
}

headers = {"Content-Type": "application/x-www-form-urlencoded"}
response = requests.post(url, data=payload, headers=headers)

response_data = response.json()

access_token = response_data["access_token"]

headers = {
    "Accept": "application/json",
    "Authorization": "Bearer {access_token}"
}

# Fetch organizations
response = requests.get(f"https://{region}.ninjarmm.com/v2/organizations", headers=headers)
if response.status_code == 200:
    organizations = response.json()
    display_table(organizations, 'id', 'name', "Organizations")
    organization_id = prompt_int("Enter the applicable organization ID", 1)
else:
    throw_error_response_with_result_code(response, "Organization Collection Failed")

# Fetch devices
response = requests.get(f"https://{region}.ninjarmm.com/v2/devices?df=org={organization_id}", headers=headers)
if response.status_code == 200:
    devices = response.json()
    display_table(devices, 'id', 'systemName', "Devices")
    device_id = prompt_int("Enter the Device ID to lookup", 1)
else:
    throw_error_response_with_result_code(response, "Devices Collection Failed")

# Fetch device scripts
response = requests.get(f"https://{region}.ninjarmm.com/v2/device/{device_id}/scripting/options", headers=headers)
if response.status_code == 200:
    device_scripts = response.json().get("scripts", [])
    display_table(device_scripts, 'id', 'name', "Device Scripts")
    device_script_id = prompt_int("Enter the Script ID to select", 1000)
    selected_device_script = next((script for script in device_scripts if script['id'] == device_script_id), None)

    if selected_device_script:
        # Define the parameters for running the script
        run_as = prompt_choice("Choose the identity to run the script as", "loggedonuser", ["system", "SR_MAC_SCRIPT", "SR_LINUX_SCRIPT", "loggedonuser", "SR_LOCAL_ADMINISTRATOR", "SR_DOMAIN_ADMINISTRATOR"])

        # Construct the payload
        payload = {
            "type": selected_device_script["type"],
            "runAs": run_as
        }

        # Add uid only if type equals "action"
        if selected_device_script["type"] == "action":
            payload["uid"] = selected_device_script["uid"]
        else:
            payload["id"] = selected_device_script["id"]

        # Execute the script
        response = requests.post(f"https://{region}.ninjarmm.com/v2/device/{device_id}/script/run", headers={**headers, "Content-Type": "application/json"}, json=payload)
        if response.status_code in [200, 201] and response.content:
            print("Script executed successfully!")
            print(json.dumps(response.json(), indent=4))
        else:
            throw_error_response_with_result_code(response, "Script Execution Failed")
    else:
        print("No script selected. Please verify the script ID.")
else:
    throw_error_response_with_result_code(response, "Device Script Collection Failed")
```

# API tour for update device custom field // adding documentation/custom field
## Generate an API key
LINK TO NINJAONE DOCUMENTATION

The first step is from your NinjaOne portal to navigate to Administration > Applications > API and to add a new Client App ID. For more information, see the NinjaOne Dojo.

In this example we'll be using a:
* Web application
* Management and Management only permissions
* Authorization Code
## Powershell 5.1
### Oauth2 example
```
function Throw-ErrorResponseWithResultCode {
    param (
        [Parameter(Mandatory=$true)]
        [pscustomobject]$Response,
        
        [Parameter(Mandatory=$true)]
        [string]$Message
    )

    # Construct the resultCode message only if resultCode is present
    $resultCodeMessage = if ($Response.PSObject.Properties["resultCode"]) { 
        "`nStated reason: $($Response.resultCode)" 
    } else { 
        "" 
    }
    
    # Throw the formatted error message with customizable message
    throw "`n$Message`nUnexpected Status Code: $($Response.StatusCode)$resultCodeMessage"
}

# Function to Display Tables
function Display-Table {
    param (
        [array]$Data,
        [string]$SortKey,
        [string]$SecondColumnKey,
        [string]$Title
    )
    Write-Host "`n$Title`n" -ForegroundColor Cyan
    $sortedData = $Data | Sort-Object $SortKey
    $displayData = $sortedData | Select-Object @{Name=$SortKey; Expression={$_.($SortKey)}}, @{Name=$SecondColumnKey; Expression={$_.($SecondColumnKey)}}
    $displayData | Format-Table -AutoSize
}

# Function to Prompt for Integer Input with Default
function Prompt-Int {
    param (
        [string]$Message,
        [int]$Default
    )
    $input = Read-Host "$Message (Default: $Default)"
    if ([string]::IsNullOrWhiteSpace($input)) {
        return $Default
    } elseif ($input -match '^\d+$') {
        return [int]$input
    } else {
        Write-Host "Invalid input. Please enter a valid integer." -ForegroundColor Yellow
        return Prompt-Int -Message $Message -Default $Default
    }
}

# Function to Prompt for Choice Input with Default
function Prompt-Choice {
    param (
        [string]$Message,
        [Parameter(Mandatory=$true)] $Default,
        [Parameter(Mandatory=$true)] [array]$Choices
    )

    # Display choices with numbers
    Write-Host $Message
    for ($i = 0; $i -lt $Choices.Length; $i++) {
        Write-Host "$($i + 1): $($Choices[$i])"
    }

    # Find the index of the default choice (if it exists in $Choices)
    $defaultIndex = $Choices.IndexOf($Default) + 1
    $input = Read-Host "Select an option by number (Default: $defaultIndex)"

    # If no input, return the default choice
    if ([string]::IsNullOrWhiteSpace($input)) {
        return $Default
    }

    # Validate input as an integer within range
    if ([int]::TryParse($input, [ref]$null) -and $input -ge 1 -and $input -le $Choices.Length) {
        return $Choices[$input - 1]
    } else {
        Write-Host "Invalid choice. Please select a valid number." -ForegroundColor Yellow
        return Prompt-Choice -Message $Message -Default $Default -Choices $Choices
    }
}

$region = Read-Host "Enter a region, e.g., CA"
$client_id = Read-Host "Enter the client_id"
$client_secret = Read-Host "Enter the client_secret" -AsSecureString
$response_type = "code"
$scope = Read-Host "Enter *SPACE* separated scope, e.g., control management monitoring"
$scope = [uri]::EscapeDataString($scope) #this encoded right
$plain_client_secret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($client_secret))
$redirect_uri = Read-Host "Enter the route from app registration, e.g., https://localhost *OR* https://webhook.site/00000000-0000-0000-0000-000000000000"

$uri = "https://$($region).ninjarmm.com/oauth/authorize?" +
    "response_type=$($response_type)&" +
    "client_id=$($client_id)&" +
    "client_secret=$($plain_client_secret)&" +
    "redirect_uri=$($redirect_uri)&" +
    "scope=$scope"

Start-Process $uri

$auth_code = Read-Host "Enter the authorization code from receipt" -AsSecureString
$plain_auth_code = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($auth_code))

$headers = @{
    "Content-Type" = "application/x-www-form-urlencoded"
}
$grant_type	= "authorization_code"

$body = "grant_type=$($grant_type)&" +
    "client_id=$($client_id)&" +
    "client_secret=$($plain_client_secret)&" +
    "code=$($plain_auth_code)&" +
    "redirect_uri=$($redirect_uri)"

$response = Invoke-WebRequest -Uri "https://$($region).ninjarmm.com/ws/oauth/token" -Method POST -Headers $headers -Body $body
if ($response.StatusCode -eq 200) {
    $response_data = $response.Content | ConvertFrom-Json
    $access_token = $response_data.access_token
} else {
    Throw-ErrorResponseWithResultCode -Response $response -Message "Authorization Failed"
}

$headers = @{
    "Accept" = "application/json"
    "Authorization" = "Bearer $access_token"
}

# Fetch organizations
$response = Invoke-WebRequest -Uri "https://$region.ninjarmm.com/v2/organizations" -Method GET -Headers $headers -ErrorAction Stop
if ($response.StatusCode -eq 200) {
    $organizations = $response.Content | ConvertFrom-Json
    Display-Table -Data $organizations -SortKey 'id' -SecondColumnKey 'name' -Title "Organizations"
    $organization_id = Prompt-Int -Message "Enter the applicable organization ID" -Default 1
} else {
    Throw-ErrorResponseWithResultCode -Response $response -Message "Organization Collection Failed"
}

# Fetch Devices
$response = Invoke-WebRequest -Uri "https://$region.ninjarmm.com/v2/devices?df=org=$($organization_id)" -Method GET -Headers $headers -ErrorAction Stop
if ($response.StatusCode -eq 200) {
    $devices = $response.Content | ConvertFrom-Json
    Display-Table -Data $devices -SortKey 'id' -SecondColumnKey 'systemName' -Title "Devices"
    $device_id = Prompt-Int -Message "Enter the Device ID to lookup" -Default 1
} else {
    Throw-ErrorResponseWithResultCode -Response $response -Message "Devices Collection Failed"
}

# Fetch Device Custom Fields
$response = Invoke-WebRequest -Uri "https://$region.ninjarmm.com/v2/device/$($device_id)/custom-fields" -Method GET -Headers $headers -ErrorAction Stop
if ($response.StatusCode -eq 200) {
    $device_fields = $response.Content | ConvertFrom-Json
    $choices = $device_fields.PSObject.Properties.Name
    $device_field = Prompt-Choice -Message "Choose the custom field to update" -Default $null -Choices $choices
    $device_field_newValue = Read-Host "Enter the new value for $selectedProperty"
    $device_fields[$devicefield] = $device_field_newValue
    $payload = $device_fields | ConvertTo-Json -Depth 10
} else {
    Throw-ErrorResponseWithResultCode -Response $response -Message "Device Custom Field Collection Failed"
}

headers = {
    "Content-Type": "application/json",
    "Accept": "*/*",
    "Authorization": "Bearer undefined"
}

# PATCH Request to update device custom field
$response = Invoke-WebRequest -Uri "https://$region.ninjarmm.com/v2/device/$($device_id)/custom-fields" -Method PATCH -Headers $headers -Body $payload -ContentType "application/json" -ErrorAction Stop
if ($response.StatusCode -eq 200 -or $response.StatusCode -eq 201) {
    Write-Host "Custom field updated executed!" -ForegroundColor Green
    $response.Content | ConvertFrom-Json | Format-List
} else {
    Throw-ErrorResponseWithResultCode -Response $response -Message "Custom field update Failed"
}

```


## Python3
### Oauth2 example
```
import requests
import getpass
import json
import webbrowser

def throw_error_response_with_result_code(response, message):
    result_code_message = f"\nStated reason: {response.json().get('resultCode')}" if 'resultCode' in response.json() else ""
    raise Exception(f"\n{message}\nUnexpected Status Code: {response.status_code}{result_code_message}")

def display_table(data, sort_key, second_column_key, title):
    print(f"\n{title}\n")
    sorted_data = sorted(data, key=lambda x: x[sort_key])
    for item in sorted_data:
        print(f"{item[sort_key]:<20} {item[second_column_key]}")
    print("\n")

def prompt_int(message, default):
    while True:
        user_input = input(f"{message} (Default: {default}): ")
        if not user_input.strip():
            return default
        try:
            return int(user_input)
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

def prompt_choice(message, default, choices):
    print(message)
    for index, choice in enumerate(choices, start=1):
        print(f"{index}: {choice}")
    
    default_index = choices.index(default) + 1
    while True:
        user_input = input(f"Select an option by number (Default: {default_index}): ")
        if not user_input.strip():
            return default
        if user_input.isdigit() and 1 <= int(user_input) <= len(choices):
            return choices[int(user_input) - 1]
        else:
            print("Invalid choice. Please select a valid number.")

region = input("Enter region: ")
client_id = input("Enter client_id: ")
client_secret = getpass.getpass("Enter your client_secret(no visible input): ")
response_type = "code"
redirect_uri = input("Enter redirect_uri: ")
scope = input("Enter *SPACE* separated scope, e.g., control management monitoring: ")

auth_url = (
    f"https://{region}.ninjarmm.com/ws/oauth/authorize?"
    f"response_type={response_type}&"
    f"client_id={client_id}&"
    f"client_secret={client_secret}&"
    f"redirect_uri={redirect_uri}&"
    f"scope={scope}"
)

print("Opening browser for authentication...")
webbrowser.open(auth_url, new=1, autoraise=True)

print(f"\nIf the browser does not open, please navigate to the following URL to authenticate:\n{auth_url}")

code = input("Please enter the NinjaOne authorization code from the redirect URL: ")

url = f"https://{region}.ninjarmm.com/ws/oauth/token"

payload = {
    "grant_type": "authorization_code",
    "client_id": f"{client_id}",
    "client_secret": f"{client_secret}",
    "code": f"{code}",
    "redirect_uri": f"{redirect_uri}"
}

headers = {"Content-Type": "application/x-www-form-urlencoded"}
response = requests.post(url, data=payload, headers=headers)

response_data = response.json()

access_token = response_data["access_token"]

headers = {
    "Accept": "application/json",
    "Authorization": "Bearer {access_token}"
}

# Fetch organizations
response = requests.get(f"https://{region}.ninjarmm.com/v2/organizations", headers=headers)
if response.status_code == 200:
    organizations = response.json()
    display_table(organizations, 'id', 'name', "Organizations")
    organization_id = prompt_int("Enter the applicable organization ID", 1)
else:
    throw_error_response_with_result_code(response, "Organization Collection Failed")

# Fetch devices
response = requests.get(f"https://{region}.ninjarmm.com/v2/devices?df=org={organization_id}", headers=headers)
if response.status_code == 200:
    devices = response.json()
    display_table(devices, 'id', 'systemName', "Devices")
    device_id = prompt_int("Enter the Device ID to lookup", 1)
else:
    throw_error_response_with_result_code(response, "Devices Collection Failed")

# Fetch Device Custom Fields
response = requests.get(f"https://{region}.ninjarmm.com/v2/device/{device_id}/custom-fields", headers=headers)
if response.status_code == 200:
    device_fields = response.json()

    # Get a list of custom field names
    choices = list(device_fields.keys())
    
    # Prompt user to choose a custom field to update
    device_field = prompt_choice("Choose the custom field to update", None, choices)
    
    # Prompt user for the new value
    device_field_new_value = input(f"Enter the new value for {device_field}: ")

    # Update the selected custom field with the new value
    device_fields[device_field] = device_field_new_value
    
    # Prepare the payload
    payload = json.dumps(device_fields)
    
else:
    throw_error_response_with_result_code(response, "Device Custom Field Collection Failed")

headers = {
    "Content-Type": "application/json",
    "Accept": "*/*",
    "Authorization": f"Bearer {access_token}"
}

# PATCH request to update the device custom field
response = requests.patch(
    f"https://{region}.ninjarmm.com/v2/device/{device_id}/custom-fields",
    headers=headers,
    json=payload
)

# Check the response status
if response.status_code in [200, 201]:
    print("Custom field updated successfully!")
    print(json.dumps(response.json(), indent=4))
else:
    throw_error_response_with_result_code(response, "Custom field update failed")
```




