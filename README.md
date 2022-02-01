# letItGo

## About
letItGo is a tool that was developed to aid security professionals in the identification of expired tenant domains in Office 365. Prior to Microsoft releasing a fix, it was possible to purchase these domains to obtain direct access to an organizations Office 365 tenant through PowerBI and PowerAutomate. For more information on this attack, check out the blog post here: [letItGo](https://sra.io/blog/letitgo-a-case-study-in-expired-domains-and-azure-ad/).

## Usage:
letItGo is a simple tool to run. Grab the latest release or compile your own. It just takes a domain as input and then begins the searching process.

`letitgo [domain].[tld]`

The output will be presented in 3 different colors/buckets:

- **Red:** These domains require further investigation. If a domain is marked "not found", it is likely expired and vulnerable to take-over.  
- **Yellow:** These domains could not be resolved via whois. These domains may require manual investigation.  
- **Green:** These domains are registered and cannot be purchesed until they expire. You should validate that you still own them.  

## Credits
- [Mark Arnold](https://www.linkedin.com/in/markarnold3) for validating the tenant takeover process.  
- [Lars Karlslund](https://twitter.com/lkarlslund) for the domain retrieval idea.  
- [Nestori Syynimaa](https://github.com/Gerenios/AADInternals) for creating and maintaining AADInternals (request to Autodiscover service).  
- Peter Crampton and Pb— for helping with creating letItGo  
