package com.coveo.saml;

import com.coveo.saml.SamlClient.SamlBinding;
import com.google.common.collect.Lists;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Saml2Settings
 *
 * <p>A class that implements the settings handler
 *
 * @author vishal
 * @since 7.3
 */
public class MetadataSettings {
  /** Private property to construct a logger for this class. */
  private static final Logger LOGGER = LoggerFactory.getLogger(MetadataSettings.class);

  /** CONSTANTS */
  // Bindings
  public static String BINDING_HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

  public static String BINDING_HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
  public static String BINDING_HTTP_ARTIFACT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";
  public static String BINDING_SOAP = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";
  public static String BINDING_DEFLATE =
      "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE";
  public static String NAMEID_UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";

  // Sign & Crypt
  // https://www.w3.org/TR/xmlenc-core/#sec-Alg-MessageDigest
  // https://www.w3.org/TR/xmlsec-algorithms/#signature-method-uris
  // https://tools.ietf.org/html/rfc6931
  public static String SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";
  public static String SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
  public static String SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";
  public static String SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512";

  public static String DSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";
  public static String RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
  public static String RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  public static String RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
  public static String RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

  public static String TRIPLEDES_CBC = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc";
  public static String AES128_CBC = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
  public static String AES192_CBC = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
  public static String AES256_CBC = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
  public static String RSA_1_5 = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
  public static String RSA_OAEP_MGF1P = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";

  // SP
  private String spEntityId = "";
  private String spAssertionConsumerServiceUrl = null;
  private SamlBinding spAssertionConsumerServiceBinding = SamlBinding.POST;
  private String spSingleLogoutServiceUrl = null;
  private SamlBinding spSingleLogoutServiceBinding = SamlBinding.Redirect;
  private String spNameIDFormat = NAMEID_UNSPECIFIED;

  private X509Certificate spX509cert = null;
  private List<X509Certificate> additionalSpX509certs = Lists.newArrayList();

  // Security
  private boolean nameIdEncrypted = false;
  private boolean authnRequestsSigned = false;
  private boolean logoutRequestSigned = false;
  private boolean logoutResponseSigned = false;
  private boolean wantMessagesSigned = false;
  private boolean wantAssertionsSigned = false;
  private boolean wantAssertionsEncrypted = false;
  private boolean wantNameId = true;
  private boolean wantNameIdEncrypted = false;
  private boolean signMetadata = false;
  private List<String> requestedAuthnContext = new ArrayList<>();
  private String requestedAuthnContextComparison = "exact";
  private boolean wantXMLValidation = true;
  private String signatureAlgorithm = RSA_SHA1;
  private String digestAlgorithm = SHA1;
  private boolean rejectUnsolicitedResponsesWithInResponseTo = false;
  private String uniqueIDPrefix = null;

  // Compress
  private boolean compressRequest = true;
  private boolean compressResponse = true;

  private boolean spValidationOnly = false;

  private MetadataSettings(Builder builder) {
    if (builder.spEntityId == null || builder.spEntityId.trim().isEmpty()) {
      throw new IllegalArgumentException("spEntityId cannot be empty");
    }
    this.spEntityId = builder.spEntityId;

    this.spAssertionConsumerServiceUrl = builder.spAssertionConsumerServiceUrl;
    this.spAssertionConsumerServiceBinding = builder.spAssertionConsumerServiceBinding;
    this.spSingleLogoutServiceUrl = builder.spSingleLogoutServiceUrl;
    this.spSingleLogoutServiceBinding = builder.spSingleLogoutServiceBinding;
    this.spNameIDFormat = builder.spNameIDFormat;
    this.spX509cert = builder.spX509cert;
    this.additionalSpX509certs = builder.additionalSpX509certs;
    this.nameIdEncrypted = builder.nameIdEncrypted;
    this.authnRequestsSigned = builder.authnRequestsSigned;
    this.logoutRequestSigned = builder.logoutRequestSigned;
    this.logoutResponseSigned = builder.logoutResponseSigned;
    this.wantMessagesSigned = builder.wantMessagesSigned;
    this.wantAssertionsSigned = builder.wantAssertionsSigned;
    this.wantAssertionsEncrypted = builder.wantAssertionsEncrypted;
    this.wantNameId = builder.wantNameId;
    this.wantNameIdEncrypted = builder.wantNameIdEncrypted;
    this.signMetadata = builder.signMetadata;
    this.requestedAuthnContext = builder.requestedAuthnContext;
    this.requestedAuthnContextComparison = builder.requestedAuthnContextComparison;
    this.wantXMLValidation = builder.wantXMLValidation;
    this.signatureAlgorithm = builder.signatureAlgorithm;
    this.digestAlgorithm = builder.digestAlgorithm;
    this.rejectUnsolicitedResponsesWithInResponseTo =
        builder.rejectUnsolicitedResponsesWithInResponseTo;
    this.uniqueIDPrefix = builder.uniqueIDPrefix;
    this.compressRequest = builder.compressRequest;
    this.compressResponse = builder.compressResponse;
    this.spValidationOnly = builder.spValidationOnly;
  }

  /**
   * Creates builder to build {@link MetadataSettings}.
   *
   * @return created builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /** Builder to build {@link MetadataSettings}. */
  public static final class Builder {
    // SP
    private String spEntityId = "";
    private String spAssertionConsumerServiceUrl = null;
    private SamlBinding spAssertionConsumerServiceBinding = SamlBinding.POST;
    private String spSingleLogoutServiceUrl = null;
    private SamlBinding spSingleLogoutServiceBinding = SamlBinding.Redirect;
    private String spNameIDFormat = NAMEID_UNSPECIFIED;
    private X509Certificate spX509cert = null;
    private List<X509Certificate> additionalSpX509certs = Lists.newArrayList();

    // Security
    private boolean nameIdEncrypted = false;
    private boolean authnRequestsSigned = false;
    private boolean logoutRequestSigned = false;
    private boolean logoutResponseSigned = false;
    private boolean wantMessagesSigned = false;
    private boolean wantAssertionsSigned = false;
    private boolean wantAssertionsEncrypted = false;
    private boolean wantNameId = true;
    private boolean wantNameIdEncrypted = false;
    private boolean signMetadata = false;
    private List<String> requestedAuthnContext = new ArrayList<>();
    private String requestedAuthnContextComparison = "exact";
    private boolean wantXMLValidation = true;
    private String signatureAlgorithm = RSA_SHA1;
    private String digestAlgorithm = SHA1;
    private boolean rejectUnsolicitedResponsesWithInResponseTo = false;
    private String uniqueIDPrefix = null;

    // Compress
    private boolean compressRequest = true;
    private boolean compressResponse = true;

    private boolean spValidationOnly = false;

    private Builder() {}

    /**
     * Builder method for spEntityId parameter.
     *
     * @param spEntityId field to set
     * @return builder
     */
    public Builder spEntityId(@Nonnull String spEntityId) {
      this.spEntityId = spEntityId;
      return this;
    }

    /**
     * Builder method for spAssertionConsumerServiceUrl parameter.
     *
     * @param spAssertionConsumerServiceUrl field to set
     * @return builder
     */
    public Builder spAssertionConsumerServiceUrl(@Nonnull String spAssertionConsumerServiceUrl) {
      this.spAssertionConsumerServiceUrl = spAssertionConsumerServiceUrl;
      return this;
    }

    /**
     * Builder method for spAssertionConsumerServiceBinding parameter.
     *
     * @param spAssertionConsumerServiceBinding field to set
     * @return builder
     */
    public Builder spAssertionConsumerServiceBinding(
        @Nonnull SamlBinding spAssertionConsumerServiceBinding) {
      this.spAssertionConsumerServiceBinding = spAssertionConsumerServiceBinding;
      return this;
    }

    /**
     * Builder method for spSingleLogoutServiceUrl parameter.
     *
     * @param spSingleLogoutServiceUrl field to set
     * @return builder
     */
    public Builder spSingleLogoutServiceUrl(@Nonnull String spSingleLogoutServiceUrl) {
      this.spSingleLogoutServiceUrl = spSingleLogoutServiceUrl;
      return this;
    }

    /**
     * Builder method for spSingleLogoutServiceBinding parameter.
     *
     * @param spSingleLogoutServiceBinding field to set
     * @return builder
     */
    public Builder spSingleLogoutServiceBinding(@Nonnull SamlBinding spSingleLogoutServiceBinding) {
      this.spSingleLogoutServiceBinding = spSingleLogoutServiceBinding;
      return this;
    }

    /**
     * Builder method for spNameIDFormat parameter.
     *
     * @param spNameIDFormat field to set
     * @return builder
     */
    public Builder spNameIDFormat(@Nonnull String spNameIDFormat) {
      this.spNameIDFormat = spNameIDFormat;
      return this;
    }

    /**
     * Builder method for nameIdEncrypted parameter.
     *
     * @param nameIdEncrypted field to set
     * @return builder
     */
    public Builder nameIdEncrypted(@Nonnull boolean nameIdEncrypted) {
      this.nameIdEncrypted = nameIdEncrypted;
      return this;
    }

    /**
     * Builder method for authnRequestsSigned parameter.
     *
     * @param authnRequestsSigned field to set
     * @return builder
     */
    public Builder authnRequestsSigned(@Nonnull boolean authnRequestsSigned) {
      this.authnRequestsSigned = authnRequestsSigned;
      return this;
    }

    /**
     * Builder method for logoutRequestSigned parameter.
     *
     * @param logoutRequestSigned field to set
     * @return builder
     */
    public Builder logoutRequestSigned(@Nonnull boolean logoutRequestSigned) {
      this.logoutRequestSigned = logoutRequestSigned;
      return this;
    }

    /**
     * Builder method for logoutResponseSigned parameter.
     *
     * @param logoutResponseSigned field to set
     * @return builder
     */
    public Builder logoutResponseSigned(@Nonnull boolean logoutResponseSigned) {
      this.logoutResponseSigned = logoutResponseSigned;
      return this;
    }

    /**
     * Builder method for wantMessagesSigned parameter.
     *
     * @param wantMessagesSigned field to set
     * @return builder
     */
    public Builder wantMessagesSigned(@Nonnull boolean wantMessagesSigned) {
      this.wantMessagesSigned = wantMessagesSigned;
      return this;
    }

    /**
     * Builder method for wantAssertionsSigned parameter.
     *
     * @param wantAssertionsSigned field to set
     * @return builder
     */
    public Builder wantAssertionsSigned(@Nonnull boolean wantAssertionsSigned) {
      this.wantAssertionsSigned = wantAssertionsSigned;
      return this;
    }

    /**
     * Builder method for wantAssertionsEncrypted parameter.
     *
     * @param wantAssertionsEncrypted field to set
     * @return builder
     */
    public Builder wantAssertionsEncrypted(@Nonnull boolean wantAssertionsEncrypted) {
      this.wantAssertionsEncrypted = wantAssertionsEncrypted;
      return this;
    }

    /**
     * Builder method for wantNameId parameter.
     *
     * @param wantNameId field to set
     * @return builder
     */
    public Builder wantNameId(@Nonnull boolean wantNameId) {
      this.wantNameId = wantNameId;
      return this;
    }

    /**
     * Builder method for wantNameIdEncrypted parameter.
     *
     * @param wantNameIdEncrypted field to set
     * @return builder
     */
    public Builder wantNameIdEncrypted(@Nonnull boolean wantNameIdEncrypted) {
      this.wantNameIdEncrypted = wantNameIdEncrypted;
      return this;
    }

    /**
     * Builder method for signMetadata parameter.
     *
     * @param signMetadata field to set
     * @return builder
     */
    public Builder signMetadata(@Nonnull boolean signMetadata) {
      this.signMetadata = signMetadata;
      return this;
    }

    /**
     * Builder method for requestedAuthnContext parameter.
     *
     * @param requestedAuthnContext field to set
     * @return builder
     */
    public Builder requestedAuthnContext(@Nonnull List<String> requestedAuthnContext) {
      this.requestedAuthnContext = requestedAuthnContext;
      return this;
    }

    /**
     * Builder method for requestedAuthnContextComparison parameter.
     *
     * @param requestedAuthnContextComparison field to set
     * @return builder
     */
    public Builder requestedAuthnContextComparison(
        @Nonnull String requestedAuthnContextComparison) {
      this.requestedAuthnContextComparison = requestedAuthnContextComparison;
      return this;
    }

    /**
     * Builder method for wantXMLValidation parameter.
     *
     * @param wantXMLValidation field to set
     * @return builder
     */
    public Builder wantXMLValidation(@Nonnull boolean wantXMLValidation) {
      this.wantXMLValidation = wantXMLValidation;
      return this;
    }

    /**
     * Builder method for signatureAlgorithm parameter.
     *
     * @param signatureAlgorithm field to set
     * @return builder
     */
    public Builder signatureAlgorithm(@Nonnull String signatureAlgorithm) {
      this.signatureAlgorithm = signatureAlgorithm;
      return this;
    }

    /**
     * Builder method for digestAlgorithm parameter.
     *
     * @param digestAlgorithm field to set
     * @return builder
     */
    public Builder digestAlgorithm(@Nonnull String digestAlgorithm) {
      this.digestAlgorithm = digestAlgorithm;
      return this;
    }

    /**
     * Builder method for rejectUnsolicitedResponsesWithInResponseTo parameter.
     *
     * @param rejectUnsolicitedResponsesWithInResponseTo field to set
     * @return builder
     */
    public Builder rejectUnsolicitedResponsesWithInResponseTo(
        @Nonnull boolean rejectUnsolicitedResponsesWithInResponseTo) {
      this.rejectUnsolicitedResponsesWithInResponseTo = rejectUnsolicitedResponsesWithInResponseTo;
      return this;
    }

    /**
     * Builder method for uniqueIDPrefix parameter.
     *
     * @param uniqueIDPrefix field to set
     * @return builder
     */
    public Builder uniqueIDPrefix(@Nonnull String uniqueIDPrefix) {
      this.uniqueIDPrefix = uniqueIDPrefix;
      return this;
    }

    /**
     * Builder method for compressRequest parameter.
     *
     * @param compressRequest field to set
     * @return builder
     */
    public Builder compressRequest(@Nonnull boolean compressRequest) {
      this.compressRequest = compressRequest;
      return this;
    }

    /**
     * Builder method for compressResponse parameter.
     *
     * @param compressResponse field to set
     * @return builder
     */
    public Builder compressResponse(@Nonnull boolean compressResponse) {
      this.compressResponse = compressResponse;
      return this;
    }

    /**
     * Builder method for spValidationOnly parameter.
     *
     * @param spValidationOnly field to set
     * @return builder
     */
    public Builder spValidationOnly(@Nonnull boolean spValidationOnly) {
      this.spValidationOnly = spValidationOnly;
      return this;
    }

    /**
     * Set service provider keys.
     *
     * @param publicKey the public key
     * @throws SamlException if publicKey and privateKey don't form a valid credential
     * @return builder
     */
    public Builder spX509cert(String publicKey) throws SamlException {
      this.spX509cert = loadCertificate(publicKey);
      return this;
    }

    /**
     * Set service provider keys.
     *
     * @param publicKeyInputStream the public key
     * @throws SamlException if publicKey and privateKey don't form a valid credential
     * @return builder
     */
    public Builder spX509cert(InputStream publicKeyInputStream) throws SamlException {
      this.spX509cert = loadCertificate(publicKeyInputStream);
      return this;
    }

    /**
     * Add an additional service provider certificate/key pair for decryption.
     *
     * @param publicKey the public key
     * @throws SamlException if publicKey and privateKey don't form a valid credential
     * @return builder
     */
    public Builder additionalSpX509certs(String publicKey) throws SamlException {
      additionalSpX509certs.add(loadCertificate(publicKey));
      return this;
    }

    /**
     * Add an additional service provider certificate/key pair for decryption.
     *
     * @param publicKeyInputStream of the publicKey file
     * @throws SamlException if publicKey and privateKey don't form a valid credential
     * @return builder
     */
    public Builder additionalSpX509certs(InputStream publicKeyInputStream) throws SamlException {
      additionalSpX509certs.add(loadCertificate(publicKeyInputStream));
      return this;
    }

    /**
     * Remove all additional service provider decryption certificate/key pairs.
     *
     * @return builder
     */
    public Builder clearAdditionalSPKeys() {
      additionalSpX509certs = new ArrayList<>();
      return this;
    }

    /**
     * Builder method of the builder.
     *
     * @return built class
     */
    public MetadataSettings build() {
      return new MetadataSettings(this);
    }
  }

  /** @return the spEntityId setting value */
  public final String getSpEntityId() {
    return spEntityId;
  }

  /** @return the spAssertionConsumerServiceUrl */
  public final String getSpAssertionConsumerServiceUrl() {
    return spAssertionConsumerServiceUrl;
  }

  /** @return the spAssertionConsumerServiceBinding setting value */
  public final SamlBinding getSpAssertionConsumerServiceBinding() {
    return spAssertionConsumerServiceBinding;
  }

  /** @return the spSingleLogoutServiceUrl setting value */
  public final String getSpSingleLogoutServiceUrl() {
    return spSingleLogoutServiceUrl;
  }

  /** @return the spSingleLogoutServiceBinding setting value */
  public final SamlBinding getSpSingleLogoutServiceBinding() {
    return spSingleLogoutServiceBinding;
  }

  /** @return the spNameIDFormat setting value */
  public final String getSpNameIDFormat() {
    return spNameIDFormat;
  }

  /** @return the nameIdEncrypted setting value */
  public boolean getNameIdEncrypted() {
    return nameIdEncrypted;
  }

  /** @return the authnRequestsSigned setting value */
  public boolean getAuthnRequestsSigned() {
    return authnRequestsSigned;
  }

  /** @return the logoutRequestSigned setting value */
  public boolean getLogoutRequestSigned() {
    return logoutRequestSigned;
  }

  /** @return the logoutResponseSigned setting value */
  public boolean getLogoutResponseSigned() {
    return logoutResponseSigned;
  }

  /** @return the wantMessagesSigned setting value */
  public boolean getWantMessagesSigned() {
    return wantMessagesSigned;
  }

  /** @return the wantAssertionsSigned setting value */
  public boolean getWantAssertionsSigned() {
    return wantAssertionsSigned;
  }

  /** @return the wantAssertionsEncrypted setting value */
  public boolean getWantAssertionsEncrypted() {
    return wantAssertionsEncrypted;
  }

  /** @return the wantNameId setting value */
  public boolean getWantNameId() {
    return wantNameId;
  }

  /** @return the wantNameIdEncrypted setting value */
  public boolean getWantNameIdEncrypted() {
    return wantNameIdEncrypted;
  }

  /** @return the signMetadata setting value */
  public boolean getSignMetadata() {
    return signMetadata;
  }

  /** @return the requestedAuthnContext setting value */
  public List<String> getRequestedAuthnContext() {
    return requestedAuthnContext;
  }

  /** @return the requestedAuthnContextComparison setting value */
  public String getRequestedAuthnContextComparison() {
    return requestedAuthnContextComparison;
  }

  /** @return the wantXMLValidation setting value */
  public boolean getWantXMLValidation() {
    return wantXMLValidation;
  }

  /** @return the signatureAlgorithm setting value */
  public String getSignatureAlgorithm() {
    return signatureAlgorithm;
  }

  /** @return the digestAlgorithm setting value */
  public String getDigestAlgorithm() {
    return digestAlgorithm;
  }

  /** @return Unique ID prefix */
  public String getUniqueIDPrefix() {
    return this.uniqueIDPrefix;
  }

  /** @return the rejectUnsolicitedResponsesWithInResponseTo value */
  public boolean isRejectUnsolicitedResponsesWithInResponseTo() {
    return rejectUnsolicitedResponsesWithInResponseTo;
  }

  /** @return the spValidationOnly value */
  public boolean getSPValidationOnly() {
    return this.spValidationOnly;
  }

  /** @return the compressRequest setting value */
  public boolean isCompressRequestEnabled() {
    return compressRequest;
  }

  /** @return the compressResponse setting value */
  public boolean isCompressResponseEnabled() {
    return compressResponse;
  }

  /** @return the spX509cert */
  public X509Certificate getSpX509cert() {
    return spX509cert;
  }

  /** @return the additionalSpX509certs */
  public List<X509Certificate> getAdditionalSpX509certs() {
    return additionalSpX509certs;
  }

  /**
   * Load an X.509 certificate
   *
   * @param filename The path of the certificate
   */
  private static X509Certificate loadCertificate(String filename) throws SamlException {
    try (FileInputStream fis = new FileInputStream(filename);
        BufferedInputStream bis = new BufferedInputStream(fis)) {

      CertificateFactory cf = CertificateFactory.getInstance("X.509");

      return (X509Certificate) cf.generateCertificate(bis);

    } catch (FileNotFoundException e) {
      throw new SamlException("Public key file doesn't exist", e);
    } catch (Exception e) {
      throw new SamlException("Couldn't load public key", e);
    }
  }

  /**
   * Load an X.509 certificate
   *
   * @param is - InputStream of the file
   * @return {@link X509Certificate} X509 certificate
   */
  public static X509Certificate loadCertificate(InputStream is) throws SamlException {
    try {

      CertificateFactory cf = CertificateFactory.getInstance("X.509");

      return (X509Certificate) cf.generateCertificate(is);

    } catch (Exception e) {
      throw new SamlException("Couldn't load public key", e);
    }
  }

  /**
   * Load a PKCS8 key
   *
   * @param filename The path of the key
   * @return {@link PrivateKey}
   * @throws SamlException the saml exception
   */
  public static PrivateKey loadPrivateKey(String filename) throws SamlException {
    try (RandomAccessFile raf = new RandomAccessFile(filename, "r")) {
      byte[] buf = new byte[(int) raf.length()];
      raf.readFully(buf);
      PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(buf);
      KeyFactory kf = KeyFactory.getInstance("RSA");

      return kf.generatePrivate(kspec);

    } catch (FileNotFoundException e) {
      throw new SamlException("Private key file doesn't exist", e);
    } catch (Exception e) {
      throw new SamlException("Couldn't load private key", e);
    }
  }

  /**
   * Load a PKCS8 key
   *
   * @param is - the inputStream of the privateKey certificate
   * @return {@link PrivateKey}
   * @throws SamlException the saml exception
   */
  public static PrivateKey loadPrivateKey(InputStream is) throws SamlException {
    try {

      byte[] buf = new byte[is.available()];
      is.read(buf);

      PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(buf);
      KeyFactory kf = KeyFactory.getInstance("RSA");

      return kf.generatePrivate(kspec);

    } catch (FileNotFoundException e) {
      throw new SamlException("Private key file doesn't exist", e);
    } catch (Exception e) {
      throw new SamlException("Couldn't load private key", e);
    }
  }
}
