package ru.forichok;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import sun.misc.BASE64Encoder;

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

class Organization {

    private static final String ALIAS = "A-1";

    private static final String SHA_256_WITH_RSA = "GOST3411withECGOST3410";

    private static char[] PRIVATE_KEY_PASSWORD = "dgsfgjfdhsgfghyjtydrsdrstgbryftdrstdghndyfhtdgrsferghjukyujtydhsgrfaedfrgthyjutgrfedfrgthyjuhgfdsafghyjtyhtgrfedfrgthyjtfdhrsegawragthjyfydhtsgreathyjfhdgsfasesgrhjkfhgrtewatyudrseatyjufyhtrtr".toCharArray();

    private static char[] KEYSTORE_PASSWORD = "1234567890".toCharArray();

    private KeyStore keyStore;

    Organization() throws Exception {
        this(KeyStoreFactory.getInstance().newKeyStoreSHA256WithRSA2048(ALIAS, KEYSTORE_PASSWORD, PRIVATE_KEY_PASSWORD));
    }

    private Organization(KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    X509Certificate cert() throws Exception {
        return (X509Certificate) keyStore.getCertificate(ALIAS);
    }

    private PrivateKey key() throws Exception {
//    GOST3410KeyPairGenerator gen = new GOST3410KeyPairGenerator();
//    gen.init(new GOST3410KeyGenerationParameters(new SecureRandom(), new GOST3410Parameters(BigInteger.TEN, BigInteger.ONE, BigInteger.ZERO)));
//    AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();
//    return (PrivateKey) keyPair.getPrivate();
//        return (PrivateKey) keyStore.getKey(ALIAS, PRIVATE_KEY_PASSWORD);

        KeyPairGenerator g = KeyPairGenerator.getInstance("ECGOST3410", "BC");
        g.initialize(new ECNamedCurveGenParameterSpec("GostR3410-2001-CryptoPro-A"), new SecureRandom());

        KeyPair p = g.generateKeyPair();

//    sKey = p.getPrivate();
//    vKey = p.getPublic();
//    KeyPairGenerator g = KeyPairGenerator.getInstance("GOST3410", "BC");
//
//    GOST3410ParameterSpec gost3410P = new GOST3410ParameterSpec(CryptoProObjectIdentifiers.gostR3410_94_CryptoPro_A.getId());
//
//    g.initialize(gost3410P, new SecureRandom());
//
//    KeyPair p = g.generateKeyPair();
//
        PrivateKey sKey = p.getPrivate();
        PublicKey vKey = p.getPublic();
        return sKey;
    }

    private DigestCalculatorProvider digestCalculatorProvider() throws OperatorCreationException {
        return new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
    }

    SignerInfoGenerator createSignerInfoGenerator() throws Exception {
        Supplier<CMSAttributeTableGenerator> $null = () -> null;
        return createSignerInfoGenerator($null, $null);
    }

    SignerInfoGenerator createSignerInfoGenerator(
        Supplier<CMSAttributeTableGenerator> signedAttributesGenerator,
        Supplier<CMSAttributeTableGenerator> unsignedAttributesGenerator) throws Exception {

        DigestCalculatorProvider digestProvider = digestCalculatorProvider();

        PrivateKey signingKey = key();

        X509Certificate signingCert = cert();

        ContentSigner contentSigner = new JcaContentSignerBuilder(SHA_256_WITH_RSA).build(signingKey);

        JcaSignerInfoGeneratorBuilder jcaSignerInfoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(digestProvider);

        Optional.ofNullable(signedAttributesGenerator.get()).ifPresent(jcaSignerInfoGeneratorBuilder::setSignedAttributeGenerator);
        Optional.ofNullable(unsignedAttributesGenerator.get()).ifPresent(jcaSignerInfoGeneratorBuilder::setUnsignedAttributeGenerator);

        return jcaSignerInfoGeneratorBuilder
            .build(contentSigner, signingCert);

    }

    public static KeyStore getJks() throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECGOST3410", "BC");
        keyPairGenerator.initialize(new ECGenParameterSpec("GostR3410-2001-CryptoPro-A"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        org.bouncycastle.asn1.x500.X500Name subject = new org.bouncycastle.asn1.x500.X500Name("CN=Me");
        org.bouncycastle.asn1.x500.X500Name issuer = subject; // self-signed
        BigInteger serial = BigInteger.ONE; // serial number for self-signed does not matter a lot
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + TimeUnit.DAYS.toMillis(365));

        org.bouncycastle.cert.X509v3CertificateBuilder certificateBuilder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
            issuer, serial,
            notBefore, notAfter,
            subject, keyPair.getPublic()
        );


        org.bouncycastle.cert.X509CertificateHolder certificateHolder = certificateBuilder.build(
            new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("GOST3411withECGOST3410")
                .build(keyPair.getPrivate())
        );
        org.bouncycastle.cert.jcajce.JcaX509CertificateConverter certificateConverter = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter();
        X509Certificate certificate = certificateConverter.getCertificate(certificateHolder);




        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null); // initialize new keystore
//    keyPair = keyPairGenerator.generateKeyPair();
        keyStore.setEntry(
            "alias",
            new KeyStore.PrivateKeyEntry(
                keyPair.getPrivate(),
                new X509Certificate[]{certificate}
            ),
            new KeyStore.PasswordProtection("entryPassword".toCharArray())
        );
        keyStore.store(new FileOutputStream("test.jks"), "keystorePassword".toCharArray());
        loadKeystoreData(keyStore);
        return keyStore;
    }

    public static void loadKeystoreData(KeyStore keystore) throws Exception {
        Enumeration<String> aliases = keystore.aliases();

        HashMap<String, Key> keys = new HashMap<>();
        HashMap<String, X509Certificate> certificates = new HashMap<>();

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();

            if (keystore.isKeyEntry(alias)) {
                Key key = keystore.getKey(alias, "entryPassword".toCharArray());
                keys.put(alias.toLowerCase(), key); //any key,value collection

                Certificate certificate = keystore.getCertificate(alias);
                if (certificate instanceof X509Certificate)
                    certificates.put(alias.toLowerCase(), (X509Certificate) certificate); //any key,value collection
                sign((PrivateKey) key, (X509Certificate) certificate);
            }
        }
        System.out.println(keys.size());
    }

    public static byte[] sign(PrivateKey privateKey, X509Certificate certificate) throws Exception {
        String[] arr = new String[20000];
        Arrays.fill(arr, " ");
        String text = "TEST CONTENT TO SIGN ";
        String tmp = String.join(text, arr);
        byte[] signData = tmp.getBytes();

        CMSProcessableByteArray msg = new CMSProcessableByteArray(signData);

        List certList = new ArrayList();
        certList.add(certificate);

        Store certs = new JcaCertStore(certList);
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("GOST3411WITHECGOST3410-2012-256").setProvider("BC").build(privateKey);



        TsaClient tsaClient = new TsaClient("http://ca.signfiles.com/TSAServer.aspx");

        if (tsaClient != null) {
            byte[] tsImprint = tsaClient.getMessageDigest().digest(signData);
            byte[] tsToken = tsaClient.getTimeStampToken(tsImprint);
            if (tsToken != null) {
                ASN1EncodableVector unauthAttributes = buildUnauthenticatedAttributes(tsToken);
                if (unauthAttributes != null) {
//                    signerinfo.add(new DERTaggedObject(false, 1, new DERSet(unauthAttributes)));
                    DERTaggedObject a = new DERTaggedObject(false, 1, new DERSet(unauthAttributes));
                    System.out.println(234);
                }
            }
        }



        ASN1EncodableVector signedAttributes = new ASN1EncodableVector();
        Attribute signingAttribute = new Attribute(CMSAttributes.signingTime, new DERSet(new DERUTCTime(new Date())));
        signedAttributes.add(signingAttribute);
// Create the signing table
        AttributeTable signedAttributesTable = new AttributeTable(signedAttributes);

// Create the table table generator that will added to the Signer builder
        DefaultSignedAttributeTableGenerator signedAttributeGenerator = new DefaultSignedAttributeTableGenerator(signedAttributesTable);


        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).setSignedAttributeGenerator(signedAttributeGenerator).build(signer, certificate));
        gen.addCertificates(certs);


        CMSSignedData sigData = gen.generate(msg, false);
        byte[] sign = sigData.getEncoded(); //result here
        verify(signData, sign);
        BASE64Encoder encoder = new BASE64Encoder();

        String signedContent = encoder.encode(sign);
        System.out.println(signedContent);
        FileOutputStream sigfos = new FileOutputStream("advancedsign.sig");
        sigfos.write(sign);
        sigfos.close();


        return sign;
    }

    public static void verify(byte[] data, byte[] signature) {
//    byte[] data = ...; //signed file data
//    byte[] signature = ...;//signature
        boolean checkResult = false;
//    data[23] = 23;

        CMSProcessable signedContent = new CMSProcessableByteArray(data);
        CMSSignedData signedData = null;
        try {
            signedData = new CMSSignedData(signedContent, signature);
        } catch (CMSException e) {
            System.out.println("@#@%#@%*!&!^*&#$");
        }

        SignerInformation signer;
        try {
            Store<X509CertificateHolder> certStoreInSing = signedData.getCertificates();
            signer = signedData.getSignerInfos().getSigners().iterator().next();

            Collection certCollection = certStoreInSing.getMatches(signer.getSID());
            Iterator certIt = certCollection.iterator();

            AttributeTable attrs = signer.getSignedAttributes();

            ASN1Encodable date = attrs.get(CMSAttributes.signingTime).getAttrValues().getObjectAt(0).toASN1Primitive();
            Date date1 = DERUTCTime.getInstance(date).getDate();
            X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();
            X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certHolder);
            checkResult = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certificate));

            System.out.println(checkResult);
        } catch (Exception ex) {
            System.out.println("fdghxgn");
        }
    }

    private static ASN1EncodableVector buildUnauthenticatedAttributes(byte[] timeStampToken)  throws IOException {
        if (timeStampToken == null)
            return null;

        // @todo: move this together with the rest of the defintions
        String ID_TIME_STAMP_TOKEN = "1.2.840.113549.1.9.16.2.14"; // RFC 3161 id-aa-timeStampToken

        ASN1InputStream tempstream = new ASN1InputStream(new ByteArrayInputStream(timeStampToken));
        ASN1EncodableVector unauthAttributes = new ASN1EncodableVector();

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1ObjectIdentifier(ID_TIME_STAMP_TOKEN)); // id-aa-timeStampToken
        ASN1Sequence seq = (ASN1Sequence) tempstream.readObject();
        v.add(new DERSet(seq));

        unauthAttributes.add(new DERSequence(v));
        return unauthAttributes;
    }

//    public static TimeStampReq createTimeStampRequest(byte[] hashedData, String nonce, boolean requireCert, String digestAlgorithm, String timestampPolicy) throws TimeStampGenerationException {
//
//        MessageImprint imprint = new MessageImprint(new AlgorithmIdentifier(digestAlgorithm), hashedData);
//
//        TimeStampReq request = new TimeStampReq(
//            imprint,
//            timestampPolicy!=null?new DERObjectIdentifier(timestampPolicy):null,
//            nonce!=null?new DERInteger(nonce.getBytes()):null,
//            new DERBoolean(requireCert),
//            null
//        );
//
//        return request;
//    }
}
