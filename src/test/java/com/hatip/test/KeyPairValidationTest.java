package com.hatip.test;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.util.concurrent.ThreadLocalRandom;
import lombok.extern.slf4j.Slf4j;
import org.apache.tomcat.util.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.junit.jupiter.api.Test;

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

    @Test
    public void certificateTest() throws Exception {

        String eccCert = "-----BEGIN CERTIFICATE-----\n" +
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

        String eccKey = "-----BEGIN EC PRIVATE KEY-----\n" +
                "MHcCAQEEIJIPHQlxeLbIYWopuWtVDdQhCP3rcYr1LWm4xv7wBPy1oAoGCCqGSM49\n" +
                "AwEHoUQDQgAEo3Vi+2gwxCT2tAwj2Bt+mbUCsPhHbCJ3Vr5hoaLnbxhlhSXH0Td5\n" +
                "y9Oo0TTR7WhDoNK+J7GNIBKrulqs91fxrQ==\n" +
                "-----END EC PRIVATE KEY-----";


        String rsaCert = "-----BEGIN CERTIFICATE-----\n" +
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



        assertTrue(verifyKeyAndCert(rsaCert, rsaKey));
       // assertTrue(verifyKeyAndCert(eccCert, eccKey));


    }

    public boolean verifyKeyAndCert(String pemEncodedCert, String pemEncodedKey) throws Exception {
        //create PrivateKey and X509Certificate objects
        java.security.Security.addProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider()
        );
        if (pemEncodedKey.contains("RSA")) {
            RSAPrivateKey privateK = RSAPrivateKey.getInstance(ASN1Sequence.fromByteArray(getBase64decoded(pemEncodedKey)));
            RSAPublicKey publicK = RSAPublicKey.getInstance(ASN1Sequence.fromByteArray(getBase64decoded(pemEncodedCert)));

            return isKeyPair(publicK,privateK);
        }

        //create a Signature object
        return false;
    }
    public static boolean isKeyPair(final RSAPublicKey pubKey, final RSAPrivateKey privKey) {
        byte[] SIGN_BYTES ="text".getBytes();
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

    public RSAPrivateKeySpec readPrivateKey(byte[] privateKeyDerBytes) throws IOException {
        RSAPrivateKey asn1PrivKey = RSAPrivateKey.getInstance(ASN1Sequence.fromByteArray(privateKeyDerBytes));
        return new RSAPrivateKeySpec(asn1PrivKey.getModulus(), asn1PrivKey.getPrivateExponent());
    }
    public byte[] getBase64decoded(String key) {
        String replace = key.replace("-----BEGIN CERTIFICATE-----\n", "")
                .replace("\n", "")
                .replace("-----END CERTIFICATE-----", "")
                .replace("-----BEGIN EC PRIVATE KEY-----", "")
                .replace("-----END EC PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "");
        return Base64.decodeBase64(replace);
    }



    @Test
    void rsaTest() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);

        KeyPair keyPair = keyGen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

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
    void ecTest() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidAlgorithmParameterException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp384r1"));

        KeyPair keyPair = keyGen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

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


}
