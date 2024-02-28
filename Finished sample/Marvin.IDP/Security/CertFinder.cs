using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

public class CertFinder
{
    public static X509Certificate2 FindOrGenerateCertificate(string thumbprint, StoreName storeName, StoreLocation storeLocation)
    {
        // Try to find the certificate in the store
        var store = new X509Store(storeName, storeLocation);
        store.Open(OpenFlags.ReadOnly);

        var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
        if (certificates.Count > 0)
        {
            // Certificate found
            return certificates[0];
        }

        // Certificate not found, generate a new one
        var newCert = GenerateSelfSignedCertificate();

        // Optionally, add the new certificate to the store for future use
        // Note: This requires administrative privileges
        //store.Add(newCert);

        store.Close();

        return newCert;
    }

    private static X509Certificate2 GenerateSelfSignedCertificate()
    {
        // Define certificate subject
        var subjectName = new X500DistinguishedName($"CN=SelfSignedCertificate");

        using (var rsa = RSA.Create(2048))
        {
            var request = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            // Set certificate validity period
            var notBefore = DateTimeOffset.Now;
            var notAfter = notBefore.AddYears(1);

            // Generate the certificate
            var certificate = request.CreateSelfSigned(notBefore, notAfter);

            // Export and re-import the certificate to make it exportable (optional)
            var exportableCert = new X509Certificate2(certificate.Export(X509ContentType.Pfx, "password"), "password", X509KeyStorageFlags.Exportable);

            return exportableCert;
        }
    }
}
