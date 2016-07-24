<#
Lue Haka luottamusverkoston metadata ja käsittele se ADFS:lle käyttökelpoiseen muotoon.

Alkuperäinen idea ja osa funktioista on lainattu CSC:n Toni Sormuselta.

- Teemu Lehtonen, teemu.lehtonen@otaverkko.fi , Otaverkko Oy. 
    19.05.2016

* Metadatan käsittely ja kryptolaajennukset tuodaan sisään dot-sourcing metodilla tiedoston alussa. 
* New-Eventlog alustaa lähteen application eventlogiin, tämä suoritetaan vain kerran. 
* Windows logitus on vielä raakaversio.

* Seulotaan metadatasta kaikki SPSSODescriptorit ja kerätään varmennetiedot, varmenteista valitaan uusin.
* Generoidaan endpointit metadatan pohjalta. 
* Luetaan sisään federaation filtteritiedosto, generoidaan attribuuttien muodostaminen näiden pohjalta. 
* Attribuuttien SAML2 OID ja muodostamissääntö kytketään yhteen HakaAttributeRules.ps1 tiedostossa
* Attribuuttifilttereiden tulkintaa varten luetaan sisään tiedosto millä mapataan attribuuttien SAML2 ja SAML1 OIDit
    * Täällä SAML1 ID:t ovat siinä muodossa kuin ne esiintyvät HAKAn filtterikonfiguraatiossa. 

* Metadatan käsittelyn yhteydessä lisätään tulkinnat SHA256 signeeraukselle millä tarkistetaan metadatan signeeraus.
* Samassa yhteydessä tarkistetaan metadatan voimassaoloaika. 
#>

# Luetaan sisään kirjastofunktiot ja konfiguraatiot.
. C:\Skriptit\HakaMetadata.ps1
. C:\Skriptit\HakaAttributeRules.ps1

# Vakiot
$protokolla = "SAML"
$verkosto = "Haka"	## Viedään Notes kenttään, tunnistetaan federaation palvelut tällä.
$tokenLifetime = 5 # Lyhytikäiset tokenit.

# Alustetaan logitus
# New-EventLog -LogName Application -Source "Haka Metadata Loader"
Write-EventLog -LogName Application -Source "Haka Metadata Loader" -EntryType Information -EventId 1 -Message "HAKA metadatan käsittely alkoi"


# Metadatan käsittely tiedostossa HakaMetadata.ps1
$HakaPalvelut = @()
$HakaPalvelut = $metadata.EntitiesDescriptor.EntityDescriptor | ? { $_.SPSSODescriptor.Name -eq "SPSSODescriptor" }

# Skripti leimaa "Federation: Haka" tekstin luomaansa trustiin. Kerätään palvelut siihen. 
$poistettavatPalvelut = Get-ADFSRelyingPartyTrust | Where-Object { $_.Notes -eq "Haka" }

foreach ($palvelu in $HakaPalvelut) {
    if ( $palvelu.SPSSODescriptor.KeyDescriptor -eq $null ) { continue } # Ei avainta, ei jatkoon.

    
    # Varmennekäsittely.
    # Keydescriptorissa voi siis olla useampi varmenne. 
    $varmenteetxml = @() 
    $varmenteetxml = $palvelu.SPSSODescriptor.KeyDescriptor 
    $varmenteet = @()

    # Iteroidaan KeyDescriptor elementin läpi. Luodaan varmenneobjekti jokaisesta varmennekentästä, 
    # järjestetään päivämäärän mukaan ja valitaan tuorein.
    $varmenteetxml | % {
        $varmenne = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2    
        $varmenne.Import($enkoodaus.GetBytes($_.KeyInfo.X509Data.X509Certificate))
        $varmenteet += $varmenne 
    }
    $allekirjoitusvarmenne = $varmenteet | Sort-Object NotAfter | Select-Object -Last 1  

    $SAMLEndpointit = @()
    # Endpointtien generoiminen.Iteroidaan kaikki endpointit AssertionConsumerService nodesta minkä bindingina on HTTP-POST.
    $palvelu.SPSSODescriptor.AssertionConsumerService | ? { $_.Binding -eq "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"} | % {
        $SAMLEndpointit += New-ADFSSamlEndpoint -Binding "POST" -Protocol "SAMLAssertionConsumer" -Uri $_.Location -Index $_.index -isDefault ([System.Boolean]::Parse($_.isDefault))
    }

    # Logout endpointit. Näitä ei välttämättä ole, testataan ettei tule virheitä.
    $palvelu.SPSSODescriptor.SingleLogoutService | % {
        if ( $_.Location -ne $null) {
            $SAMLEndpointit += New-ADFSSamlEndpoint -Binding "REDIRECT" -Protocol "SAMLLogout" -Uri $_.Location
        }
    }

    # Poistetaan vanha. 
    if ((Get-ADFSRelyingPartyTrust -Identifier $palvelu.entityID) -ne $null) 
	{
        Remove-ADFSRelyingPartyTrust -TargetIdentifier $palvelu.entityID
    }

    # Alustettu niin että sisältö on kaikki SP:t. Metadataa iteroidessa joka kierroksella sisältö on kaikki mitä ennestään oli
    # minus nyt käsittelyssä oleva. --> Jäljelle jää entityID:t mitä ei ollut metadatassa.
    $poistettavatPalvelut = @($poistettavatPalvelut | Where-Object { $_.identifier -ne $palvelu.entityID })

<#
    NameIdentifier käsittely
#>

    switch ($palvelu.SPSSODescriptor.NameIDFormat) {
        "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" {
        $claimrules = '@RuleName="Transient NameID"c1:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"] && c2:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant"] => add(store = "_OpaqueIdStore", types = ("http://laurea/internal/transientId"), query = "{0};{1};{2};{3};{4}", param = "useEntropy", param = c1.Value, param = c1.OriginalIssuer, param = "", param = c2.Value);'+"`n"
        $claimrules += 'c:[Type == "http://laurea/internal/transientId"] => issue(Type = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", Issuer = c.Issuer, OriginalIssuer = c.OriginalIssuer, Value = c.Value, ValueType = c.ValueType, Properties["http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/format"] = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient");'+"`n"    
        break;
        }
        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" {
        $claimrules = '@RuleName="Persistent NameID"c:[type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname" ] => add(  store  = "_OpaqueIdStore", types = ("http://laurea/internal/persistentId"), query = "{0};{1};{2}",  param = "ppid",  param = c.Value,  param = c.OriginalIssuer);'+"`n"
        $claimrules += 'c:[Type == "http://laurea/internal/persistentId"] => issue(Type = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", Issuer = c.Issuer, OriginalIssuer = c.OriginalIssuer, Value = c.Value, ValueType = c.ValueType, Properties["http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/format"] = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");'+"`n"
        #$claimrules = '@RuleName="eduPersonTargetedID"c:[type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname" ] => add(  store  = "_OpaqueIdStore", types = ("http://laurea/internal/persistentId"), query = "{0};{1};{2}",  param = "ppid",  param = c.Value,  param = c.OriginalIssuer);'+"`n"
        #$claimrules += 'c:[Type == "http://laurea/internal/persistentId"] => issue(Type = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", Issuer = c.Issuer, OriginalIssuer = c.OriginalIssuer, Value = c.Value, ValueType = c.ValueType, Properties["http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/format"] = "urn:oid:1.3.6.1.4.1.5923.1.1.1.10", Properties["http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/attributename"] = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");'
        break;
        }
        default { 
        break; }
    } 
                
<#
    Attribuuttien käsittely. Rakennetaan SPSSODescriptor/AttributeConsumingService/RequestedAttribute arvoista.
#>
    # Array per palvelu. attributeID ja PermitValueRule kenttinä.
    $Attribuutit = HaeAttribuutitMetadatasta -metadata $metadata -entityID $palvelu.entityID 

    foreach ($attribute in $Attribuutit) {
        if ($attribuuttisäännöt.Item($attribute.Name) -ne $null) {
            $claimrules += "@RuleName = `"$($attribute.FriendlyName)`"`n"
            $claimrules += $attribuuttisäännöt.Item($attribute.Name)
            $claimrules += "@RuleName = `"$($attribute.FriendlyName)`"`n"
            $claimrules += "c:[Type == `"$($attribute.Name)`"] => issue(Type = `"$($attribute.Name)`", Value = c.Value, Properties[`"http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/attributename`"] = `"urn:oasis:names:tc:SAML:2.0:attrname-format:uri`");`n"
        }
    }

    Add-ADFSRelyingPartyTrust -Identifier $palvelu.entityID -Name $palvelu.entityID -SamlEndpoint $SAMLEndpointit   -Enabled $true -Notes $verkosto -SigningCertificateRevocationCheck none -SamlResponseSignature MessageAndAssertion -SignedSamlRequestsRequired $false -ProtocolProfile $protokolla -TokenLifetime $tokenLifetime -IssuanceAuthorizationRules $haka_autorisaatio_säännöt -IssuanceTransformRules $claimrules -SignatureAlgorithm $allekirjoitus_sha1 -RequestSigningCertificate $allekirjoitusvarmenne
} # SP silmukka kiinni.

$poistettavatPalvelut | Remove-AdfsRelyingPartyTrust
Write-EventLog -LogName Application -Source "Haka Metadata Loader" -EntryType Information -EventId 2 -Message "HAKA metadatan käsittely päättyi"