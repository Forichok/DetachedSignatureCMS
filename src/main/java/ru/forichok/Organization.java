package ru.forichok;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;

class Organization {

  private static final String ALIAS = "A-1";

  private KeyStore keyStore;

  private PrivateKey privateKey;

  private X509Certificate certificate;

  public Organization(KeyStore keyStore) {
    this.keyStore = keyStore;
    try {
      loadKeystoreData(keyStore, "keystorePassword");
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  X509Certificate getCertificate() {
    return certificate;
  }

  public PrivateKey getPrivateKey() {
    return privateKey;
  }

  private void loadKeystoreData(KeyStore keystore, String keystorePassword) throws Exception {
    Enumeration<String> aliases = keystore.aliases();
    while (aliases.hasMoreElements()) {
      String alias = aliases.nextElement();
      if (keystore.isKeyEntry(alias)) {
        privateKey = (PrivateKey) keystore.getKey(alias, keystorePassword.toCharArray());
        Certificate cert = keystore.getCertificate(alias);
        if (cert instanceof X509Certificate) {
          this.certificate = (X509Certificate) cert;
        }
      }
    }
  }

  public CMSSignedData sign(byte[] data, PrivateKey privateKey, X509Certificate certificate) throws Exception {
    CMSProcessableByteArray msg = new CMSProcessableByteArray(data);

    List certList = new ArrayList();
    certList.add(certificate);

    Store certs = new JcaCertStore(certList);
    CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
    ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("GOST3411WITHECGOST3410-2012-256").setProvider("BC").build(privateKey);

    gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(signer, certificate));
    gen.addCertificates(certs);

    CMSSignedData sigData = gen.generate(msg, false);
    return sigData;
  }
}
