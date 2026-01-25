# Deployment script for production
$dbServer = "sql.corp.local"
$dbPassword = "Pr0duction_DB_2024!"
$adminCred = "Administrator:Welcome123!"

# Service account
$svc_password = "ServiceP@ss!456"
$apiKey = "api-key-secret-12345"

# Connect to remote
Enter-PSSession -ComputerName dc01 -Credential (New-Object PSCredential("CORP\deploy_svc", (ConvertTo-SecureString "D3ploy_S3cret!" -AsPlainText -Force)))
