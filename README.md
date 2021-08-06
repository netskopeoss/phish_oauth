<img src="https://www.netskope.com/wp-content/uploads/2020/03/netskope-threat-labs.png" alt="Netskope Threat Labs logo" width="200"/>

# Description

    This project provides POC code to explore [OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749)
    authorization flows and how they can be abused in phishing attacks.
    
    Specifically, we demonstrate a phishing attack using the device authorization grant
    on Microsoft and intend to add additional flows as we go. An implementation of this 
    is written in generic Powershell and can be run on any supported platform. Most cmdlet
    calls are simple REST API calls and should be translateable to any language.

# Directories / Files
    device_code/pwsh/
        demo_msft.ps1       - main Powershell file. Usage: powershell|pwsh -h
        demo_cfg.json       - required config file
        demo_email.txt      - email template if sending phish email

# OAuth Flows

## Device Authorization Grant (device code flow)
![Device Authorization Grant](device_code_flow.png)

# References

1.0 Evolving Phishing Attacks
1.1 A Big Catch: Cloud Phishing from Google App Engine and Azure App Service: https://www.netskope.com/blog/a-big-catch-cloud-phishing-from-google-app-engine-and-azure-app-service
1.2 Microsoft Seizes Malicious Domains Used in Mass Office 365 Attacks: https://threatpost.com/microsoft-seizes-domains-office-365-phishing-scam/157261/
1.3 Phishing Attack Hijacks Office 365 Accounts Using OAuth Apps: https://www.bleepingcomputer.com/news/security/phishing-attack-hijacks-office-365-accounts-using-oauth-apps/
1.4 Office 365 Phishing Attack Leverages Real-Time Active Directory Validation: https://threatpost.com/office-365-phishing-attack-leverages-real-time-active-directory-validation/159188/
1.5 Demonstration - Illicit Consent Grant Attack in Azure AD: https://www.nixu.com/blog/demonstration-illicit-consent-grant-attack-azure-ad-office-365
https://securecloud.blog/2018/10/02/demonstration-illicit-consent-grant-attack-in-azure-ad-office-365/
1.6 Detection and Mitigation of Illicit Consent Grant Attacks in Azure AD: https://www.cloud-architekt.net/detection-and-mitigation-consent-grant-attacks-azuread/
1.7 HelSec Azure AD write-up: Phishing on Steroids with Azure AD Consent Extractor: https://securecloud.blog/2019/12/17/helsec-azure-ad-write-up-phishing-on-steroids-with-azure-ad-consent-extractor/
1.8 Pawn Storm Abuses OAuth In Social Engineering Attack: https://www.trendmicro.com/en_us/research/17/d/pawn-storm-abuses-open-authentication-advanced-social-engineering-attacks.html

2.0 OAuth Device Code Flow
2.1 OAuth 2.0 RFC: https://tools.ietf.org/html/rfc6749
2.2 OAuth 2.0 Device Authorization Grant RFC: https://datatracker.ietf.org/doc/html/rfc8628
2.3 OAuth 2.0 for TV and Limited-Input Device Applications: https://developers.google.com/identity/protocols/oauth2/limited-input-device
2.4 OAuth 2.0 Scopes for Google APIs: https://developers.google.com/identity/protocols/oauth2/scopes
2.5 Introducing a new phishing technique for compromising Office 365 accounts: https://o365blog.com/post/phishing/#oauth-consent
2.6. Office Device Code Phishing: https://gist.github.com/Mr-Un1k0d3r/afef5a80cb72dfeaa78d14465fb0d333

3.0 Additional OAuth Research Areas
3.1 Poor OAuth implementation leaves millions at risk of stolen data: https://searchsecurity.techtarget.com/news/450402565/Poor-OAuth-implementation-leaves-millions-at-risk-of-stolen-data
3.2 How did a full access OAuth token get issued to the Pokémon GO app?: https://searchsecurity.techtarget.com/answer/How-did-a-full-access-OAuth-token-get-issued-to-the-Pokemon-GO-app


