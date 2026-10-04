Microsoft Sentinel: Phishing Triage & Threat Hunting Lab
Overview
I investigated an authorized phishing simulation that bypassed standard security filters. To analyze the attack, I built a custom data pipeline to push the email data into Microsoft Sentinel and used KQL to hunt for the targeted users and potential account compromises.

 Tools & Skills
SIEM: Microsoft Sentinel, Azure Log Analytics

Scripting: PowerShell, Azure REST API

Threat Hunting: KQL (Kusto Query Language), Log Parsing

Email Security: Analyzing SMTP Headers, SPF, DKIM, and DMARC

Step 1: Analyzing the Phishing Email
I analyzed a suspicious email that successfully reached a user's inbox. By reviewing the raw email headers, I identified how the email bypassed security:

(Raw header analysis showing the routing path)

The Tactic (Typosquatting): The sender used a lookalike domain (liinkediin.com).

The Bypass (Authentication): The sender correctly set up SPF and DKIM for their fake domain and used a p=none DMARC policy. This made the email look legitimate to standard security gateways.

(Authentication results showing SPF and DKIM passing)

Indicators of Compromise (IOCs) Found:

Source IP: 54.252.116.154

Sender Address: linkedin@e.premium.liinkediin.com

Step 2: Sending Data to Microsoft Sentinel
To analyze this threat in a SIEM, I needed to ingest the log data. I wrote a PowerShell script that formats the IOCs into JSON and uses the Azure REST API to push the data directly into a custom table (PhishingTriage_CL) in Microsoft Sentinel.

My script is available in the scripts/ folder.

Step 3: Finding the Blast Radius (Tier 1 Hunt)
Once the data was in Sentinel, I wrote a KQL query to find out exactly who received this phishing email.

KQL -
PhishingTriage_CL
| where SenderFromAddress_s has "liinkediin.com" or SenderIPv4_s == "54.252.116.154"
| project TimeGenerated, RecipientEmailAddress_s, Subject_s, SenderFromAddress_s, SenderIPv4_s, DeliveryAction_s
Result: The query successfully isolated the single targeted user (analyst@uts.local).

(KQL Search Results in Microsoft Sentinel)

Step 4: Checking for Account Takeover (Tier 2 Hunt)
Knowing the user received the email isn't enough. I needed to know if they clicked the link and entered their password.

I wrote a second KQL query to check Azure SigninLogs for any successful logins coming from outside the user's normal location (Australia).

KQL-
SigninLogs
| where UserPrincipalName == "analyst@uts.local" 
  and ResultType == "0" 
  and Location != "AU"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName
Result: This query will immediately alert the SOC if the attacker tries to log in with stolen credentials.

Step 5: How to Respond
If this were a real attack, my immediate next steps would be:

Delete the Email: Use a Sentinel Logic App to automatically remove the email from the user's inbox.

Secure the Account: Revoke the user's active login sessions and force a password reset.

Block the Attacker: Update email security policies to block newly registered domains and flag suspicious display names.
