Add-Type -AssemblyName System.Security
Add-Type @'
        public class RSAPKCS1SHA256SignatureDescription : System.Security.Cryptography.SignatureDescription
            {
                public RSAPKCS1SHA256SignatureDescription()
                {
                    base.KeyAlgorithm = "System.Security.Cryptography.RSACryptoServiceProvider";
                    base.DigestAlgorithm = "System.Security.Cryptography.SHA256Managed";
                    base.FormatterAlgorithm = "System.Security.Cryptography.RSAPKCS1SignatureFormatter";
                    base.DeformatterAlgorithm = "System.Security.Cryptography.RSAPKCS1SignatureDeformatter";
                }

                public override System.Security.Cryptography.AsymmetricSignatureDeformatter CreateDeformatter(System.Security.Cryptography.AsymmetricAlgorithm key)
                {
                    System.Security.Cryptography.AsymmetricSignatureDeformatter asymmetricSignatureDeformatter = (System.Security.Cryptography.AsymmetricSignatureDeformatter)
                        System.Security.Cryptography.CryptoConfig.CreateFromName(base.DeformatterAlgorithm);
                    asymmetricSignatureDeformatter.SetKey(key);
                    asymmetricSignatureDeformatter.SetHashAlgorithm("SHA256");
                    return asymmetricSignatureDeformatter;
                }
            }
'@
$RSAPKCS1SHA256SignatureDescription = New-Object RSAPKCS1SHA256SignatureDescription
[System.Security.Cryptography.CryptoConfig]::AddAlgorithm($RSAPKCS1SHA256SignatureDescription.GetType(), "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")

<# Haka Tuotanto, metadata ja varmenteen polku. #>
$metadataURL = "https://haka.funet.fi/metadata/haka-metadata.xml"
$metadatavarmennepolku = "C:\skriptit\haka-sign-v3.pem"

<# Haka testi, metadata ja varmenteen polku #>
#$metadataURL = "https://haka.funet.fi/metadata/haka_test_metadata_signed.xml"
#$metadataURL = "C:\Skriptit\haka_test_metadata_signed.xml" # Paikallinen tiedosto, runneltu niin että signeeraus ei täsmää.
#$metadatavarmennepolku = "C:\skriptit\haka_testi_2015_sha2.crt"

# Pääasiassa rsa-sha1, laajennetaan tästä tarvittaessa. 
$allekirjoitus_sha2 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" 
$allekirjoitus_sha1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
$enkoodaus = New-Object System.Text.ASCIIEncoding

# Onko varmenne millä metadata signeerattiin OK?
$metadatavarmenne = New-Object System.Security.Cryptography.X509Certificates.X509Certificate
$metadatavarmenne.Import($metadatavarmennepolku)
$varmenneketju = New-Object System.Security.Cryptography.X509Certificates.X509Chain

if ( $varmenneketju.Build($metadatavarmenne) -ne $true )
{
	Write-Host -ForegroundColor RED "Metadatan allekirjoitusvarmenteen varmistaminen ei onnistunut.";
    Write-EventLog -LogName Application -Source "Haka Metadata Loader" -EntryType Error -EventId 1 -Message "HAKA metadatan allekirjoitusvarmenteen validointi epäonnistui" 
	#return
}
else { 
    Write-Host "Metadatan allekirjoitusvarmenne on ok." 
 }

$varmenneketju.Reset()

$Xmldata = New-Object Xml.XmlDocument
$Xmldata.PreserveWhitespace = $true
$Xmldata.Load($metadataURL)

<#
SignedXml luokan kuvaus.
https://msdn.microsoft.com/en-us/library/system.security.cryptography.xml.signedxml(v=vs.110).aspx
#>

# Välitetään konstruktorille metadata XML dokumentti.
$SignedXml = New-Object System.Security.Cryptography.Xml.SignedXml -ArgumentList $Xmldata
$XmlSignature = $Xmldata.EntitiesDescriptor.Signature

# SignedXml.LoadXml haluaa XMLElement tyyppisen parametrin.
$SignedXml.LoadXml($XmlSignature)

# CheckSignature(varmenne, validoidaanko varmenne?)
if ($SignedXml.CheckSignature($metadatavarmennepolku, $true)) {
    Write-Host "Metadatan signeeraus on validi"
} else {
    Write-EventLog -LogName Application -Source "Haka Metadata Loader" -EntryType Error -EventId 2 -Message "HAKA metadatan allekirjoitusvarmenteen validointi epäonnistui"
    Write-Host "Metadatan signeeraus ei täsmää dokumenttiin."
}

if ($Xmldata.EntitiesDescriptor.validUntil -ge (Get-Date)) {
    Write-Host "Metadatan voimassaoloaika on OK"
    $metadata = $Xmldata
}

Function HaeAttribuutitMetadatasta {
    Param(
        [Xml.XmlDocument]$metadata,
        [String]$entityID  
    )
    $Attribuutit = @()
    $entity = $metadata.EntitiesDescriptor.EntityDescriptor| ? { $_.entityID -eq $entityID}
    $entity = $entity.SPSSODescriptor.AttributeConsumingService | ? { $_.isDefault -eq "true" }
    $Attribuutit = $entity.RequestedAttribute
    $Attribuutit
}