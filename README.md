# Haka-idp-powershell
ADFS 3 metadata and configuration management powershell scripts for the finnish Haka-federation

The scripts perform a few functions related to acting as an IPD in the HAKA-federation.
* Federation metadata management.
* Metadata signature validation, required some inline C# to add support for SHA256 signatures. 
* Creation of relying party trusts.
* Attribute management: generating values based on Active Directory, direct SQL server lookups and SQL server stored procedures.
  * Metadata based encoding, attribute-format handling. 
* Attribute handling is functionally (roughly)equivalent to Shibboleth 3 AttributeInMetadata style filtering, with no external attribute filter
definition.
  
The scripts contain commented out configuration for using the IDP in the HAKA-test federation, the main differences being
the source of the metadata and the signing certificate.
  
The scripts are provided as-is, with no guarantees.   
  
