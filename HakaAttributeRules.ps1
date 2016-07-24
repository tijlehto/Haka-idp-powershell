<#
Tässä tiedostossa määritellään attribuuttien muodostamissäännöt
oid <-> arvo pareina. Avaimena toimii attribuutin virallinen oid.

Muodostamissäännöt on testattu ADFS 3.1:llä, lisäksi muutama attribuutti hyödyntää SQL attribuuttisäilöä minne osa käsittelystä on ulkoistettu.
#>
$haka_autorisaatio_säännöt = '@RuleName = "Permit all"=> issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");'

$AttribuuttiSäännöt = @{}

#auth pp transport
$AttribuuttiSäännöt += @{"http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod" = 'c:[]=> issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", Value = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");'}
# givenName
$AttribuuttiSäännöt += @{"urn:oid:2.5.4.42" = 'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] => add(store = "Active Directory", types = ("urn:oid:2.5.4.42"), query = ";givenName;{0}", param = c.Value);'}
# sn
$AttribuuttiSäännöt += @{"urn:oid:2.5.4.4" = 'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] => add(store = "Active Directory", types = ("urn:oid:2.5.4.4"), query = ";sn;{0}", param = c.Value);'}
#mail
$AttribuuttiSäännöt += @{"urn:oid:0.9.2342.19200300.100.1.3" = 'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] => add(store = "Active Directory", types = ("urn:oid:0.9.2342.19200300.100.1.3"), query = ";mail;{0}", param = c.Value);'}
#schacHomeOrganization
$AttribuuttiSäännöt += @{"urn:oid:1.3.6.1.4.1.25178.1.2.9" = 'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] => add(Type = "urn:oid:1.3.6.1.4.1.25178.1.2.9", Value = "laurea.fi");'}
#schacHomeOrganizationType
$AttribuuttiSäännöt += @{"urn:oid:1.3.6.1.4.1.25178.1.2.10" = 'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] => add(Type = "urn:oid:1.3.6.1.4.1.25178.1.2.10",Value = "urn:schac:homeOrganizationType:fi:polytechnic");'}
# EPPN
$AttribuuttiSäännöt += @{"urn:oid:1.3.6.1.4.1.5923.1.1.1.6" = 'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] => add(store = "IDPData", types = ("urn:oid:1.3.6.1.4.1.5923.1.1.1.6"), query = "EXEC dbo.edupersonPrincipalName @accountname={0},@eppn =''''", param = c.Value);'}
# DisplayName
$AttribuuttiSäännöt += @{"urn:oid:2.16.840.1.113730.3.1.241" = 'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] => add(store = "Active Directory", types = ("urn:oid:2.16.840.1.113730.3.1.241"), query = ";displayName;{0}", param = c.Value);'}
# CN
$AttribuuttiSäännöt += @{"urn:oid:2.5.4.3" = 'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] => add(store = "Active Directory", types = ("urn:oid:2.5.4.3"), query = ";displayName;{0}", param = c.Value);'}
# HomePostalAddress
$AttribuuttiSäännöt += @{"urn:oid:0.9.2342.19200300.100.1.39" = 'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] => add(store = "IDPData", types = ("urn:oid:0.9.2342.19200300.100.1.39"), query = "select postaladdress from dbo.idpdata where accountname={0}", param = RegExReplace(c.Value, "LAUREA\\", ""));'}
# eduPersonProgram
$AttribuuttiSäännöt += @{"urn:oid:1.3.6.1.4.1.16161.1.1.12" = 'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] => add(store = "IDPData", types = ("urn:oid:1.3.6.1.4.1.16161.1.1.12"), query = "EXEC dbo.eduPersonProgram @accountname={0},@eduPersonProgram =''''", param = c.Value);'}
# personaluniqueID, aka HETU
$AttribuuttiSäännöt += @{"urn:oid:1.3.6.1.4.1.25178.1.2.15" = 'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] => add(store = "IDPData", types = ("urn:oid:1.3.6.1.4.1.25178.1.2.15"), query = "EXEC dbo.personalUniqueID @accountname={0},@personalUniqueID =''''", param = c.Value);'}
# mobile
$AttribuuttiSäännöt += @{"urn:oid:0.9.2342.19200300.100.1.41" = 'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] => add(store = "IDPData", types = ("urn:oid:0.9.2342.19200300.100.1.41"), query = "select mobile from dbo.idpdata where accountname ={0}", param = RegExReplace(c.Value, "LAUREA\\", ""));'}
# primaryaffiliation
$AttribuuttiSäännöt += @{"urn:oid:1.3.6.1.4.1.5923.1.1.1.5" = 'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] => add(store = "IDPData", types = ("urn:oid:1.3.6.1.4.1.5923.1.1.1.5"), query = "EXEC dbo.edupersonprimaryaffiliation @accountname={0},@eppa =''''", param = c.Value);'}
#affiliation
$AttribuuttiSäännöt += @{"urn:oid:1.3.6.1.4.1.5923.1.1.1.1" = 'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] => add(store = "IDPData", types = ("urn:oid:1.3.6.1.4.1.5923.1.1.1.1"), query = "EXEC dbo.edupersonaffiliation @accountname={0},@epa =''''", param = c.Value);'}
#uid
$AttribuuttiSäännöt += @{"urn:oid:0.9.2342.19200300.100.1.1" = 'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] => add(store = "IDPData", types = ("urn:oid:0.9.2342.19200300.100.1.1"), query = "select accountname from dbo.idpdata where accountname ={0}", param = RegExReplace(c.Value, "LAUREA\\", ""));'}
#postalAddress
$AttribuuttiSäännöt += @{"urn:oid:2.5.4.16" = 'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] => add(store = "IDPData", types = ("urn:oid:2.5.4.16"), query = "select postaladdress from dbo.idpdata where accountname={0}", param = RegExReplace(c.Value, "LAUREA\\", ""));'}
#postalAddress
$AttribuuttiSäännöt += @{"urn:oid:2.5.4.17" = 'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] => add(store = "IDPData", types = ("urn:oid:2.5.4.17"), query = "select homepostalcode from dbo.idpdata where accountname={0}", param = RegExReplace(c.Value, "LAUREA\\", ""));'}
# schacdateofbirth
$AttribuuttiSäännöt += @{"urn:oid:1.3.6.1.4.1.25178.1.2.3" = 'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] => add(store = "IDPData", types = ("urn:oid:1.3.6.1.4.1.25178.1.2.3"), query = "EXEC dbo.schacDateofBirth @accountname={0},@dob =''''", param = c.Value);'}
