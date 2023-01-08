package com.hatip.test;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.ThreadLocalRandom;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectParser;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Slf4j
public class KeyPairValidationTest {

    /**
     * The purpose of this code will be to verify that a public/private keypair is a match.
     * <p>
     * Illustrates understanding of basic concepts of keys and certificate encodings, and signing an object
     * with a private key then verifying the signature with the certificate.
     * <p>
     * Where the default javax.crypto API support is insufficient, Bouncycastle libraries should be used as they
     * provide comprehensive cryptographic operations support.  Please provide the code with a gradle
     * build file including the necessary dependencies so it can be built and executed
     * <p>
     * This should be done for both ECC and RSA.  A set of matching key/certificates for each are included below.
     * <p>
     * Bonus: sign and verify some data on the command line with openssl
     */

    public String PRIVATE_KEY_FILE = "variable/rsa/private_key.der";
    public String PUBLIC_KEY_FILE = "variable/rsa/public_key.der";
    public String PRIVATE_KEY_FILE_EC = "variable/ec/private_key.der";
    public String PUBLIC_KEY_FILE_EC = "variable/ec/public_key.der";

    String eccCertNonValid = "-----BEGIN CERTIFICATE-----\n" +
            "MIIB+zCCAVygAwIBAgIJALtuvIUD5bGXMAoGCCqGSM49BAMCMBcxFTATBgNVBAMM\n" +
            "DFBDLUVDQ0EtVEVTVDAeFw0yMjA4MTIxNzI5MDNaFw0yMzA4MTIxNzI5MDNaMBYx\n" +
            "FDASBgNVBAMMC2JvYjI1Ni1zY2VwMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n" +
            "o3Vi+2gwxCT2tAwj2Bt+mbUCsPhHbCJ3Vr5hoaLnbxhlhSXH0Td5y9Oo0TTR7WhD\n" +
            "oNK+J7GNIBKrulqs91fxraOBkTCBjjAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQM\n" +
            "MAoGCCsGAQUFBwMCMEcGA1UdIwRAMD6AFKZY0YHqqCRrgCinhhOFUCajKY3moRuk\n" +
            "GTAXMRUwEwYDVQQDDAxQQy1FQ0NBLVRFU1SCCQC1EJLK4Qp9TTAdBgNVHQ4EFgQU\n" +
            "WrJTjTiq+AKpuEdR4mmcbS17/GIwCgYIKoZIzj0EAwIDgYwAMIGIAkIAmormONWJ\n" +
            "R/ii9SXvEEXGPKVIcz7yaWRItQAWTH9AuSQbOVKhZ+hLli8JyxmaJl8CaMnEPu8+\n" +
            "2y/IVG3eBKDF0bQCQgGZXF2E5aLn6KheJGoEYLhnlXS9e58K4xmDcn4Lwj5Ti8sX\n" +
            "uI9PjBsaNoBSq8LmdAQrMOO2wZRPdqyJJ2efBsIsGQ==\n" +
            "-----END CERTIFICATE-----";
    String eccCert = "-----BEGIN PUBLIC KEY-----\n" +
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEo3Vi+2gwxCT2tAwj2Bt+mbUCsPhH\n" +
            "bCJ3Vr5hoaLnbxhlhSXH0Td5y9Oo0TTR7WhDoNK+J7GNIBKrulqs91fxrQ==\n" +
            "-----END PUBLIC KEY-----\n";
    String eccKey = "-----BEGIN EC PRIVATE KEY-----\n" +
            "MHcCAQEEIJIPHQlxeLbIYWopuWtVDdQhCP3rcYr1LWm4xv7wBPy1oAoGCCqGSM49\n" +
            "AwEHoUQDQgAEo3Vi+2gwxCT2tAwj2Bt+mbUCsPhHbCJ3Vr5hoaLnbxhlhSXH0Td5\n" +
            "y9Oo0TTR7WhDoNK+J7GNIBKrulqs91fxrQ==\n" +
            "-----END EC PRIVATE KEY-----";


    String rsaCert = "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4ehYZGgQnLyiP5Jf7681\n" +
            "TuMLcQFoNIfuxMoBgOj9Pv7W/ShBkDSvhXpdcOJRX8aZhLAJkCKONH7wM8WkNjYc\n" +
            "VxrDI0e0dhZhzfmei42WmecUYQjqISKUfGHTE9SdqIN8wq/UMcHpCRXpjay5DVdP\n" +
            "InZvg8DR/jHh2PWyLgCdwXjyzCgAxCDniIwP6ibOMLyv2kWzgGOB4b0b+stjnUUn\n" +
            "t25uGTpIAomygQbAVsmDU+r+TwRIac5p1q/JImWOi57hv4IgatJaKzl/m6kKZmT0\n" +
            "1m7SdbdB1w9m16wZhhHqVFq0NZvvrZAlgqKS/DjmjJCRgYcwhA47tRGBlQvyo87U\n" +
            "vwIDAQAB\n" +
            "-----END PUBLIC KEY-----";
    String rsaCertNonValid = "-----BEGIN CERTIFICATE-----\n" +
            "MIICmjCCAYICCQCe7/hdRJT7hDANBgkqhkiG9w0BAQsFADANMQswCQYDVQQDDAJj\n" +
            "YTAeFw0yMjA4MjQxNzA4MDJaFw0yMzA4MTkxNzA4MDJaMBExDzANBgNVBAMMBmNs\n" +
            "aWVudDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOHoWGRoEJy8oj+S\n" +
            "X++vNU7jC3EBaDSH7sTKAYDo/T7+1v0oQZA0r4V6XXDiUV/GmYSwCZAijjR+8DPF\n" +
            "pDY2HFcawyNHtHYWYc35nouNlpnnFGEI6iEilHxh0xPUnaiDfMKv1DHB6QkV6Y2s\n" +
            "uQ1XTyJ2b4PA0f4x4dj1si4AncF48swoAMQg54iMD+omzjC8r9pFs4BjgeG9G/rL\n" +
            "Y51FJ7dubhk6SAKJsoEGwFbJg1Pq/k8ESGnOadavySJljoue4b+CIGrSWis5f5up\n" +
            "CmZk9NZu0nW3QdcPZtesGYYR6lRatDWb762QJYKikvw45oyQkYGHMIQOO7URgZUL\n" +
            "8qPO1L8CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAjtTgCBGUIwLIX/H8kOxweH5P\n" +
            "ItRU4y7q3oU1bD11NimuzM2THJDR/qni3/T2vkjnVJMRbTdYwBnoT8edujxl3321\n" +
            "yxCsRgFeEHgHwq74m7KsBDAf7B7fxypHUzshp2H+W3BQLdaFKVSvX6VomMwE8fF7\n" +
            "BXR+nCQQM/ZWl/OsNFswsDI49htCoQzKM5h9MjIIm/IJr3oyRYubf+aFlq3o/hsh\n" +
            "GwZqLkJMHOVPvFTupxhoOElACn6MkwXKmtuA18SDStRrJWSJo1GXMIHUmpbCggjw\n" +
            "Sc0wDOX91NDxYafuAUgaEzrS6saSjl/b/Qn+SZrJBSqmEHx4PWszYmW1H3rCzQ==\n" +
            "-----END CERTIFICATE-----\n";
    String rsaKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIIEpQIBAAKCAQEA4ehYZGgQnLyiP5Jf7681TuMLcQFoNIfuxMoBgOj9Pv7W/ShB\n" +
            "kDSvhXpdcOJRX8aZhLAJkCKONH7wM8WkNjYcVxrDI0e0dhZhzfmei42WmecUYQjq\n" +
            "ISKUfGHTE9SdqIN8wq/UMcHpCRXpjay5DVdPInZvg8DR/jHh2PWyLgCdwXjyzCgA\n" +
            "xCDniIwP6ibOMLyv2kWzgGOB4b0b+stjnUUnt25uGTpIAomygQbAVsmDU+r+TwRI\n" +
            "ac5p1q/JImWOi57hv4IgatJaKzl/m6kKZmT01m7SdbdB1w9m16wZhhHqVFq0NZvv\n" +
            "rZAlgqKS/DjmjJCRgYcwhA47tRGBlQvyo87UvwIDAQABAoIBAQC9a7zyM+/5/JFv\n" +
            "DKU0rIzeYLIvRybBJVmn2Fn6ZWIzeCt8ikyvRf4Gxduj06C31ibTg2gBW3gxvF5c\n" +
            "itRuQGDzCJWm93Dxs0K/Gxc9nLMyyPflhTwMHJq00LHUZurraZUrCZO7RQTJgX4c\n" +
            "NT/VV+ga1YQbzYpGwjzFVv7YY9vjZJtHop3MrWNmufjnAxmY4e/mHNbBWdhr4iUG\n" +
            "89owqWWsbCI8JLDeCTz1Dpd/IOSdeDVJpHGTsu3Ut2JCIJ06D5mevG3edE0kzybU\n" +
            "sC5d5rywbYCy2nqAxiGyEGejd/a696qVqqQqxCtH6uG4AMNsCRItlGPMqQ/8swaZ\n" +
            "j9akK6YBAoGBAPsIU22P423kzlxYr2246lW8+QrjkhIJwm+sdMkETqFKE5wiesN/\n" +
            "8hY6pYYGETZ6xR2QmPNYzr6gMYqItFXarP9Ew+Cp4YYrVajw2g+C8Ixk8EfkBQw6\n" +
            "9XsAz5DakfO4lq3MPcjpUi75TyqmDMCIRrOs3nzTdhWgnRofoksJnjXfAoGBAOZg\n" +
            "vgCEWnhQ545eidJ0fQCrPA0inFIKBPR9oOAex2NBaAUFXM5m0S1LzfULBnkOiCSj\n" +
            "nWgcMhYjktJdTaRZOoq4D0AJ1B1D2TMwH7o8ZEu2gY4Ika+c6xAQUf9acR67v/lh\n" +
            "QY7CQ+Xbsth3G0l5cOU3WorpqukeUSHkvf5FZH0hAoGBAKIFlqtBUn3sTtDFoLyF\n" +
            "vCGIbYj8ppuj1u3y9hGECSgKwqtkia3C18JHKexd4CA0jyLs3/s4V4Arrq4GW7aK\n" +
            "BFxhyrcnjlrlf00h3uxiC9XhlEAiSKvDJgu000Nf/xG6Eu6rwzj4dsXAvbr+H37o\n" +
            "thFjwtn4Nd/xoVRqFHqwA4ArAoGBAL7AK5JSBHbKxm/jZ0qSmU4MelSF69kh4qht\n" +
            "vN7VnVJZvb8qiYV9LIXM1mOnFVz241MzBgpGDlK2ccMs7jS+jPJ/JGFpwe/ZVeZE\n" +
            "WoDhsEnge7UW80ntK9TJLpu4TyGbY4EhPh7uSznvh04kkLttikTAaH/Mqm8LYzIl\n" +
            "LAt1eZcBAoGAFK+RC5AkQvbr5edQY7EpbazF722k+w+qcSkr0+qV/hWc2xgKNrb4\n" +
            "25dTrxuAObXycRum47JzVp0DC/SU4qCp4VZiB+QcJ82hcxk5GTef+wVNlcgHRUZw\n" +
            "vtXy0n15fuXske/MaFrh4z4n/Ie62+wbPRBk8mkVIOxsFhYfdpcldrA=\n" +
            "-----END RSA PRIVATE KEY-----\n";

    @Test
    public void certificateTest() throws Exception {
        assertTrue(verifyKeyAndCert(rsaCert, rsaKey));
        assertFalse(verifyKeyAndCert(rsaCertNonValid, rsaKey));
        assertFalse(verifyKeyAndCert(eccCertNonValid, eccKey));
        assertTrue(verifyKeyAndCert(eccCert, eccKey));
    }

    public boolean verifyKeyAndCert(String pemEncodedCert, String pemEncodedKey) throws Exception {
        //create PrivateKey and X509Certificate objects
        java.security.Security.addProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider()
        );
        if (pemEncodedKey.contains("RSA")) {
            try {
                KeyFactory factory = KeyFactory.getInstance("RSA");
                RSAPrivateKey privateKey = (RSAPrivateKey) getPrivateKey(pemEncodedKey, factory);
                RSAPublicKey publicKey = (RSAPublicKey) getPublicKey(pemEncodedCert, factory);
                return isRSAKeyPair(publicKey, privateKey);
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        } else {
            try {
                KeyFactory factory = KeyFactory.getInstance("EC");
                PemReader pemPrivateReader = new PemReader(new StringReader(pemEncodedKey));
                PemObject privateKeyPemObject = pemPrivateReader.readPemObject();
                byte[] contentPrivate = privateKeyPemObject.getContent();
                PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(contentPrivate);
                log.info("Private key format = {}",privateKeyPemObject.getType() );
                ECPrivateKey privKey = (ECPrivateKey) factory.generatePrivate(privKeySpec);
                isKeyPair(getPublicKey(pemEncodedCert, factory), privKey);
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }

        //create a Signature object
        return false;
    }

    private static PublicKey getPublicKey(String pemEncodedCert, KeyFactory factory) throws IOException, InvalidKeySpecException {
        PemReader pemReader = new PemReader(new StringReader(pemEncodedCert));
        PemObject rsaPubObject = pemReader.readPemObject();
        byte[] contentPublic = rsaPubObject.getContent();
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(contentPublic);
        return factory.generatePublic(pubKeySpec);
    }

    private static PrivateKey getPrivateKey(String pemEncodedKey, KeyFactory factory) throws IOException, InvalidKeySpecException {
        PemReader pemPrivateReader = new PemReader(new StringReader(pemEncodedKey));
        PemObject privateKeyPemObject = pemPrivateReader.readPemObject();
        byte[] contentPrivate = privateKeyPemObject.getContent();
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(contentPrivate);
        return factory.generatePrivate(privKeySpec);
    }

    public static boolean isRSAKeyPair(final RSAPublicKey pubKey, final RSAPrivateKey privKey) {
        byte[] SIGN_BYTES = "text".getBytes();
        final RSADigestSigner signer = new RSADigestSigner(new SHA256Digest());
        try {
            signer.init(true, new RSAKeyParameters(true, privKey.getModulus(), privKey.getPrivateExponent()));
            signer.update(SIGN_BYTES, 0, SIGN_BYTES.length);
            final byte[] sig = signer.generateSignature();
            signer.init(false, new RSAKeyParameters(false, pubKey.getModulus(), pubKey.getPublicExponent()));
            signer.update(SIGN_BYTES, 0, SIGN_BYTES.length);
            return signer.verifySignature(sig);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static boolean isKeyPair(final PublicKey pubKey, final PrivateKey privKey) {
        try {
            // create a challenge
            byte[] challenge = new byte[10000];
            ThreadLocalRandom.current().nextBytes(challenge);

            // sign using the private key
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(privKey);
            sig.update(challenge);
            byte[] signature = sig.sign();

            // verify signature using the public key
            sig.initVerify(pubKey);
            sig.update(challenge);

            return sig.verify(signature);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }


    @Test
    void rsaTest() throws Exception {
        PublicKey publicKey = getPublicFromFile(PUBLIC_KEY_FILE, "RSA");
        PrivateKey privateKey = getPrivateFromFile(PRIVATE_KEY_FILE, "RSA");

        // create a challenge
        byte[] challenge = new byte[10000];
        ThreadLocalRandom.current().nextBytes(challenge);

        // sign using the private key
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(challenge);
        byte[] signature = sig.sign();

        // verify signature using the public key
        sig.initVerify(publicKey);
        sig.update(challenge);

        boolean keyPairMatches = sig.verify(signature);
        assertTrue(keyPairMatches);
    }

    @Test
    void ecTest() throws Exception {
        PublicKey publicKey = getPublicFromFile(PUBLIC_KEY_FILE_EC, "EC");
        PrivateKey privateKey = getPrivateFromFile(PRIVATE_KEY_FILE_EC, "EC");

        // create a challenge
        byte[] challenge = new byte[10000];
        ThreadLocalRandom.current().nextBytes(challenge);

        // sign using the private key
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(privateKey);
        sig.update(challenge);
        byte[] signature = sig.sign();

        // verify signature using the public key
        sig.initVerify(publicKey);
        sig.update(challenge);

        boolean keyPairMatches = sig.verify(signature);
        assertTrue(keyPairMatches);
    }

    public PrivateKey getPrivateFromFile(String filename, String algorithm)
            throws Exception {
        ClassLoader classLoader = this.getClass().getClassLoader();
        File file = new File(classLoader.getResource(filename).getFile());
        byte[] keyBytes = Files.readAllBytes(file.toPath());

        PKCS8EncodedKeySpec spec =
                new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        return kf.generatePrivate(spec);
    }

    public PublicKey getPublicFromFile(String filename, String algorithm)
            throws Exception {
        ClassLoader classLoader = this.getClass().getClassLoader();
        File file = new File(classLoader.getResource(filename).getFile());
        byte[] keyBytes = Files.readAllBytes(file.toPath());

        X509EncodedKeySpec spec =
                new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        return kf.generatePublic(spec);
    }
}
