package ru.forichok;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.jcajce.provider.digest.GOST3411;
import org.bouncycastle.tsp.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

class TsaClient {

  /** The Logger instance. */


  /** URL of the Time Stamp Authority */
  protected String tsaURL;

  /** TSA Username */
  protected String tsaUsername;

  /** TSA password */
  protected String tsaPassword;

  /** An interface that allows you to inspect the timestamp info. */
  protected TSAInfoBouncyCastle tsaInfo;

  /** The default value for the hash algorithm */
  public static final int DEFAULTTOKENSIZE = 4096;

  /** Estimate of the received time stamp token */
  protected int tokenSizeEstimate;

  /** The default value for the hash algorithm */
  public static final String DEFAULTHASHALGORITHM = "SHA-256";

  /** Hash algorithm */
  protected String digestAlgorithm;

  /**
   * Creates an instance of a TSAClient that will use BouncyCastle.
   * @param url String - Time Stamp Authority URL (i.e. "http://tsatest1.digistamp.com/TSA")
   */
  public TsaClient(String url) {
    this(url, null, null, DEFAULTTOKENSIZE, DEFAULTHASHALGORITHM);
  }

  /**
   * Creates an instance of a TSAClient that will use BouncyCastle.
   * @param url String - Time Stamp Authority URL (i.e. "http://tsatest1.digistamp.com/TSA")
   * @param username String - user(account) name
   * @param password String - password
   */
  public TsaClient(String url, String username, String password) {
    this(url, username, password, 4096, DEFAULTHASHALGORITHM);
  }

  /**
   * Constructor.
   * Note the token size estimate is updated by each call, as the token
   * size is not likely to change (as long as we call the same TSA using
   * the same imprint length).
   * @param url String - Time Stamp Authority URL (i.e. "http://tsatest1.digistamp.com/TSA")
   * @param username String - user(account) name
   * @param password String - password
   * @param tokSzEstimate int - estimated size of received time stamp token (DER encoded)
   */
  public TsaClient(String url, String username, String password, int tokSzEstimate, String digestAlgorithm) {
    this.tsaURL       = url;
    this.tsaUsername  = username;
    this.tsaPassword  = password;
    this.tokenSizeEstimate = tokSzEstimate;
    this.digestAlgorithm = digestAlgorithm;
  }

  /**
   * @param tsaInfo the tsaInfo to set
   */
  public void setTSAInfo(TSAInfoBouncyCastle tsaInfo) {
    this.tsaInfo = tsaInfo;
  }

  /**
   * Get the token size estimate.
   * Returned value reflects the result of the last succesfull call, padded
   * @return an estimate of the token size
   */
  public int getTokenSizeEstimate() {
    return tokenSizeEstimate;
  }

  /**
   * Gets the MessageDigest to digest the data imprint
   * @return the digest algorithm name
   */
  public MessageDigest getMessageDigest() throws GeneralSecurityException {
    return new GOST3411.Digest();
  }

  /**
   * Get RFC 3161 timeStampToken.
   * Method may return null indicating that timestamp should be skipped.
   * @param imprint data imprint to be time-stamped
   * @return encoded, TSA signed data of the timeStampToken
   * @throws IOException
   * @throws TSPException
   */
  public byte[] getTimeStampTokenBytes(byte[] imprint) throws IOException, TSPException {
    byte[] respBytes = null;
    // Setup the time stamp request
    TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
    tsqGenerator.setCertReq(true);
    // tsqGenerator.setReqPolicy("1.3.6.1.4.1.601.10.3.1");
    BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
    TimeStampRequest request = tsqGenerator.generate(new ASN1ObjectIdentifier("1.2.643.2.2.9"), imprint, nonce); // GOST3411
    byte[] requestBytes = request.getEncoded();

    // Call the communications layer
    respBytes = getTSAResponse(requestBytes);

    // Handle the TSA response
    TimeStampResponse response = new TimeStampResponse(respBytes);

    // validate communication level attributes (RFC 3161 PKIStatus)
    response.validate(request);
    PKIFailureInfo failure = response.getFailInfo();
    int value = (failure == null) ? 0 : failure.intValue();
    if (value != 0) {
      // @todo: Translate value of 15 error codes defined by PKIFailureInfo to string
      throw new IOException("null value");
    }
    // @todo: validate the time stap certificate chain (if we want
    //        assure we do not sign using an invalid timestamp).

    // extract just the time stamp token (removes communication status info)
    TimeStampToken tsToken = response.getTimeStampToken();
    if (tsToken == null) {
      throw new IOException("NULL TOKEN");
    }
    TimeStampTokenInfo tsTokenInfo = tsToken.getTimeStampInfo(); // to view details
    byte[] encoded = tsToken.getEncoded();


    if (tsaInfo != null) {
      tsaInfo.inspectTimeStampTokenInfo(tsTokenInfo);
    }
    // Update our token size estimate for the next call (padded to be safe)
    this.tokenSizeEstimate = encoded.length + 32;
    return encoded;
  }

  public TimeStampToken getTimeStampToken(byte[] imprint) throws IOException, TSPException {
    byte[] respBytes = null;
    // Setup the time stamp request
    TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
    tsqGenerator.setCertReq(true);
    // tsqGenerator.setReqPolicy("1.3.6.1.4.1.601.10.3.1");
    BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
    TimeStampRequest request = tsqGenerator.generate(new ASN1ObjectIdentifier("1.2.643.2.2.9"), imprint, nonce); // GOST3411
    byte[] requestBytes = request.getEncoded();

    // Call the communications layer
    respBytes = getTSAResponse(requestBytes);

    // Handle the TSA response
    TimeStampResponse response = new TimeStampResponse(respBytes);

    // validate communication level attributes (RFC 3161 PKIStatus)
    response.validate(request);
    PKIFailureInfo failure = response.getFailInfo();
    int value = (failure == null) ? 0 : failure.intValue();
    if (value != 0) {
      // @todo: Translate value of 15 error codes defined by PKIFailureInfo to string
      throw new IOException("null value");
    }
    // @todo: validate the time stap certificate chain (if we want
    //        assure we do not sign using an invalid timestamp).

    // extract just the time stamp token (removes communication status info)
    TimeStampToken tsToken = response.getTimeStampToken();
    if (tsToken == null) {
      throw new IOException("NULL TOKEN");
    }
    return tsToken;
  }



  /**
   * Get timestamp token - communications layer
   * @return - byte[] - TSA response, raw bytes (RFC 3161 encoded)
   * @throws IOException
   */
  protected byte[] getTSAResponse(byte[] requestBytes) throws IOException {
    // Setup the TSA connection
    URL url = new URL(tsaURL);
    URLConnection tsaConnection;
    try {
      tsaConnection = (URLConnection) url.openConnection();
    }
    catch (IOException ioe) {
      throw new IOException(ioe);
    }
    tsaConnection.setDoInput(true);
    tsaConnection.setDoOutput(true);
    tsaConnection.setUseCaches(false);
    tsaConnection.setRequestProperty("Content-Type", "application/timestamp-query");
    //tsaConnection.setRequestProperty("Content-Transfer-Encoding", "base64");
    tsaConnection.setRequestProperty("Content-Transfer-Encoding", "binary");

    if ((tsaUsername != null) && !tsaUsername.equals("") ) {
      String userPassword = tsaUsername + ":" + tsaPassword;
      tsaConnection.setRequestProperty("Authorization", "Basic " +
          Base64.encode(userPassword.getBytes()));
    }
    OutputStream out = tsaConnection.getOutputStream();
    out.write(requestBytes);
    out.close();

    // Get TSA response as a byte array
    InputStream inp = tsaConnection.getInputStream();
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    byte[] buffer = new byte[1024];
    int bytesRead = 0;
    while ((bytesRead = inp.read(buffer, 0, buffer.length)) >= 0) {
      baos.write(buffer, 0, bytesRead);
    }
    byte[] respBytes = baos.toByteArray();

    String encoding = tsaConnection.getContentEncoding();
    if (encoding != null && encoding.equalsIgnoreCase("base64")) {
      respBytes = Base64.decode(new String(respBytes));
    }
    return respBytes;
  }
}