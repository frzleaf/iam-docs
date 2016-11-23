# 1. Cài Shibboleth
- T?i Shibboleth IdP 3
- Cài Shibboleth vào thu m?c /opt/shibboleth-idp

## **Chuy?n sang thu m?c cài shibboleth tru?c khi th?c hi?n các bu?c ti?p theo**

# 2. Config v?i ADFS
#### a. S?a `conf/metadata-providers.xml` v?i link mà bên ADFS cung c?p
```
...
<MetadataProvider id="HTTPMetadata" xsi:type="FileBackedHTTPMetadataProvider"
backingFile="%{idp.home}/metadata/FederationMetadata.xml"
metadataURL="https://leth.teca.vn/FederationMetadata/2007-06/FederationMetadata.xml" >
<MetadataFilter xsi:type="EntityRoleWhiteList">
            <RetainedRole>md:SPSSODescriptor</RetainedRole>
        </MetadataFilter>
    </MetadataProvider>

</MetadataProvider>
...
```
#### b. S?a conf/ldap.properties các giá tr? c?n d? s? d?ng ldap
M?u:
```
...
# LDAP authentication configuration, see authn/ldap-authn-config.xml
# Note, this doesn't apply to the use of JAAS

## Authenticator strategy, either anonSearchAuthenticator, bindSearchAuthenticator, directAuthenticator, adAuthenticator

idp.authn.LDAP.authenticator                   = bindSearchAuthenticator 


## Connection properties ##
idp.authn.LDAP.ldapURL                         = ldap://10.0.0.11:3389
idp.authn.LDAP.useStartTLS                     = false 
idp.authn.LDAP.useSSL                          = false
#idp.authn.LDAP.connectTimeout                  = 3000

## SSL configuration, either jvmTrust, certificateTrust, or keyStoreTrust
#idp.authn.LDAP.sslConfig                       = certificateTrust
## If using certificateTrust above, set to the trusted certificate's path

idp.authn.LDAP.trustCertificates                = %{idp.home}/credentials/ldap-server.crt

## If using keyStoreTrust above, set to the truststore path

idp.authn.LDAP.trustStore                       = %{idp.home}/credentials/ldap-server.truststore

## Return attributes during authentication
## NOTE: there is a separate property used for attribute resolution
idp.authn.LDAP.returnAttributes                 = passwordExpirationTime,loginGraceRemaining

## DN resolution properties ##

# Search DN resolution, used by anonSearchAuthenticator, bindSearchAuthenticator
# for AD: CN=Users,DC=example,DC=org

idp.authn.LDAP.baseDN                           = dc=bhxh,dc=vn

#idp.authn.LDAP.subtreeSearch                   = false


#idp.authn.LDAP.userFilter                       = (|(teca-users-Email={user})(|(cas-users-EMAIL={user})(email={user})))
idp.authn.LDAP.userFilter                       = (teca-users-email={user})

# bind search configuration
# for AD: idp.authn.LDAP.bindDN=adminuser@domain.com

idp.authn.LDAP.bindDN                           = cn=Directory Manager Server3 

idp.authn.LDAP.bindDNCredential                 = Oracle_123456a# 

# Format DN resolution, used by directAuthenticator, adAuthenticator
# for AD use idp.authn.LDAP.dnFormat=%s@domain.com

idp.authn.LDAP.dnFormat                         = email=%s,%{idp.authn.LDAP.baseDN}

# LDAP attribute configuration, see attribute-resolver.xml
# Note, this likely won't apply to the use of legacy V2 resolver configurations
idp.attribute.resolver.LDAP.ldapURL             = %{idp.authn.LDAP.ldapURL}
idp.attribute.resolver.LDAP.baseDN              = %{idp.authn.LDAP.baseDN:undefined}
idp.attribute.resolver.LDAP.bindDN              = %{idp.authn.LDAP.bindDN:undefined}
idp.attribute.resolver.LDAP.bindDNCredential    = %{idp.authn.LDAP.bindDNCredential:undefined}
# idp.attribute.resolver.LDAP.useStartTLS         = %{idp.authn.LDAP.useStartTLS:true}
idp.attribute.resolver.LDAP.trustCertificates   = %{idp.authn.LDAP.trustCertificates:undefined}
#idp.attribute.resolver.LDAP.searchFilter        = (email=$resolutionContext.principal)
idp.attribute.resolver.LDAP.searchFilter        = (|(teca-users-Email=$resolutionContext.principal)(|(cas-users-EMAIL=$resolutionContext.principal)(email=$resolutionContext.principal)))
idp.attribute.resolver.LDAP.returnAttributes    =  cn,email,macoquan,madonvi,uid,cas-users-macoquan,cas-users-email,cas-users-madvi,cas-users-macoquan,teca-users-email,teca-users-macoquan

# LDAP pool configuration, used for both authn and DN resolution
#idp.pool.LDAP.minSize                          = 3
#idp.pool.LDAP.maxSize                          = 10
#idp.pool.LDAP.validateOnCheckout               = false
#idp.pool.LDAP.validatePeriodically             = true
#idp.pool.LDAP.validatePeriod                   = 300
#idp.pool.LDAP.prunePeriod                      = 300
#idp.pool.LDAP.idleTime                         = 600
#idp.pool.LDAP.blockWaitTime                    = 3000
#idp.pool.LDAP.failFastInitialize               = false
...
```
#### c. S?a `conf/attribute-resolver.xml`
M?u:
```
...
 <resolver:AttributeDefinition id="cas-users-email" xsi:type="ad:Simple" sourceAttributeID="cas-users-email">
        <resolver:Dependency ref="myLDAP" />
        <resolver:AttributeEncoder xsi:type="enc:SAML1String" name="urn:mace:dir:attribute-def:cas-users-email" encodeType="false" />
        <resolver:AttributeEncoder xsi:type="enc:SAML2String" name="urn:oid:3.0.0.1.99.2" friendlyName="cas-users-EMAIL"/>
    </resolver:AttributeDefinition>

    <resolver:AttributeDefinition id="cn" xsi:type="ad:Simple" sourceAttributeID="cn">
        <resolver:Dependency ref="myLDAP" />
        <resolver:AttributeEncoder xsi:type="enc:SAML1String" name="urn:mace:dir:attribute-def:cn" encodeType="false" />
        <resolver:AttributeEncoder xsi:type="enc:SAML2String" name="urn:oid:2.5.4.3" friendlyName="cn"/>
    </resolver:AttributeDefinition>
    <resolver:AttributeDefinition id="teca-users-macoquan" xsi:type="ad:Simple" sourceAttributeID="teca-users-macoquan">
        <resolver:Dependency ref="myLDAP" />
        <resolver:AttributeEncoder xsi:type="enc:SAML1String" name="urn:mace:dir:attribute-def:teca-users-MaCoQuan" encodeType="false" />
        <resolver:AttributeEncoder xsi:type="enc:SAML2String" name="urn:oid:3.0.0.1.98.3" friendlyName="teca-users-MaCoQuan"/>
    </resolver:AttributeDefinition>
    <resolver:AttributeDefinition id="cas-users-madvi" xsi:type="ad:Simple" sourceAttributeID="cas-users-madvi">
        <resolver:Dependency ref="myLDAP" />
        <resolver:AttributeEncoder xsi:type="enc:SAML1String" name="urn:mace:dir:attribute-def:cas-users-madvi" encodeType="false" />
        <resolver:AttributeEncoder xsi:type="enc:SAML2String" name="urn:oid:3.0.0.1.99.5" friendlyName="cas-users-madvi"/> 
    </resolver:AttributeDefinition>
    <resolver:AttributeDefinition id="cas-users-mst" xsi:type="ad:Simple" sourceAttributeID="cas-users-mst">
        <resolver:Dependency ref="myLDAP" />
        <resolver:AttributeEncoder xsi:type="enc:SAML1String" name="urn:mace:dir:attribute-def:cas-users-mst" encodeType="false" />
        <resolver:AttributeEncoder xsi:type="enc:SAML2String" name="urn:oid:3.0.0.1.99.1" friendlyName="cas-users-mst"/>   
    </resolver:AttributeDefinition>

    <!-- teca-users -->
    <resolver:AttributeDefinition id="teca-users-email" xsi:type="ad:Simple" sourceAttributeID="teca-users-email">
        <resolver:Dependency ref="myLDAP" />
        <resolver:AttributeEncoder xsi:type="enc:SAML1String" name="urn:mace:dir:attribute-def:teca-users-email" encodeType="false" />
        <resolver:AttributeEncoder xsi:type="enc:SAML2String" name="urn:oid:3.0.0.1.98.8" friendlyName="teca-users-email"/>
    </resolver:AttributeDefinition>
    <resolver:AttributeDefinition id="teca-users-macoquan" xsi:type="ad:Simple" sourceAttributeID="teca-users-macoquan">
        <resolver:Dependency ref="myLDAP" />
        <resolver:AttributeEncoder xsi:type="enc:SAML1String" name="urn:mace:dir:attribute-def:teca-users-macoquan" encodeType="false" />
        <resolver:AttributeEncoder xsi:type="enc:SAML2String" name="urn:oid:3.0.0.1.98.9" friendlyName="teca-users-macoquan"/>
    </resolver:AttributeDefinition>
	
    <!-- dreamUser -->
    <resolver:AttributeDefinition id="email" xsi:type="ad:Simple" sourceAttributeID="email">
        <resolver:Dependency ref="myLDAP" />
        <resolver:AttributeEncoder xsi:type="enc:SAML1String" name="urn:mace:dir:attribute-def:email" encodeType="false" />
        <resolver:AttributeEncoder xsi:type="enc:SAML2String" name="urn:oid:1.1.1.1.7" friendlyName="email"/>
    </resolver:AttributeDefinition>

    <resolver:AttributeDefinition id="cn" xsi:type="ad:Simple" sourceAttributeID="cn">
        <resolver:Dependency ref="myLDAP" />
        <resolver:AttributeEncoder xsi:type="enc:SAML1String" name="urn:mace:dir:attribute-def:cn" encodeType="false" />
        <resolver:AttributeEncoder xsi:type="enc:SAML2String" name="urn:oid:2.5.4.3" friendlyName="cn"/>
    </resolver:AttributeDefinition>
    <resolver:AttributeDefinition id="macoquan" xsi:type="ad:Simple" sourceAttributeID="macoquan">
        <resolver:Dependency ref="myLDAP" />
        <resolver:AttributeEncoder xsi:type="enc:SAML1String" name="urn:mace:dir:attribute-def:maCoQuan" encodeType="false" />
        <resolver:AttributeEncoder xsi:type="enc:SAML2String" name="urn:oid:1.1.1.1.8" friendlyName="maCoQuan"/>
    </resolver:AttributeDefinition>
    <resolver:AttributeDefinition id="madonvi" xsi:type="ad:Simple" sourceAttributeID="madonvi">
        <resolver:Dependency ref="myLDAP" />
        <resolver:AttributeEncoder xsi:type="enc:SAML1String" name="urn:mace:dir:attribute-def:maDonVi" encodeType="false" />
        <resolver:AttributeEncoder xsi:type="enc:SAML2String" name="urn:oid:2.2.2.2.1" friendlyName="maDonVi"/>
    </resolver:AttributeDefinition>
    <resolver:AttributeDefinition id="uid" xsi:type="ad:Simple" sourceAttributeID="uid">
        <resolver:Dependency ref="myLDAP" />
        <resolver:AttributeEncoder xsi:type="enc:SAML1String" name="urn:mace:dir:attribute-def:uid" encodeType="false" />
        <resolver:AttributeEncoder xsi:type="enc:SAML2String" name="urn:oid:0.9.2342.19200300.100.1.1" friendlyName="uid"/>
    </resolver:AttributeDefinition>


    <!--
    In the rest of the world, the email address is the standard identifier,
    despite the problems with that practice. Consider making the EPPN value
    the same as your official email addresses whenever possible.
    
    <resolver:AttributeDefinition id="email" xsi:type="ad:Simple" sourceAttributeID="email">
        <resolver:Dependency ref="myLDAP" />
        <resolver:AttributeEncoder xsi:type="enc:SAML1String" name="urn:mace:dir:attribute-def:email" encodeType="false" />
        <resolver:AttributeEncoder xsi:type="enc:SAML2String" name="urn:oid:1.1.1.1.7" friendlyName="email" encodeType="false" />
    </resolver:AttributeDefinition>
    -->    

    <!-- ========================================== -->
    <!--      Data Connectors                       -->
    <!-- ========================================== -->
    
    <!--
    Example LDAP Connector
    
    The connectivity details can be specified in ldap.properties to
    share them with your authentication settings if desired.
    -->
    <resolver:DataConnector id="myLDAP" xsi:type="dc:LDAPDirectory"
        ldapURL="%{idp.attribute.resolver.LDAP.ldapURL}"
        baseDN="%{idp.attribute.resolver.LDAP.baseDN}" 
        principal="cn=Directory Manager Server3"
        principalCredential="Oracle_123456a#">

        <dc:FilterTemplate>
            <![CDATA[
		%{idp.attribute.resolver.LDAP.searchFilter}
	    ]]>
        </dc:FilterTemplate>
        <dc:ReturnAttributes>%{idp.attribute.resolver.LDAP.returnAttributes}</dc:ReturnAttributes>
    </resolver:DataConnector>
...
```
#### d. S?a `conf/idp.properties`
M?u:
```
...
# Load any additional property resources from a comma-delimited list
idp.additionalProperties= /conf/ldap.properties, /conf/saml-nameid.properties, /conf/services.properties

# Set the entityID of the IdP
idp.entityID= https://chai65.iam:8443/idp/shibboleth

# Set the scope used in the attribute resolver for scoped attributes
idp.scope= iam

# General cookie properties (maxAge only applies to persistent cookies)
#idp.cookie.secure = false
#idp.cookie.httpOnly = true
#idp.cookie.domain =
#idp.cookie.path =
#idp.cookie.maxAge = 31536000

# Set the location of user-supplied web flow definitions
#idp.webflows = %{idp.home}/flows

# Set the location of Velocity view templates
#idp.views = %{idp.home}/views

# Settings for internal AES encryption key
#idp.sealer.storeType = JCEKS
#idp.sealer.updateInterval = PT15M
#idp.sealer.aliasBase = secret
idp.sealer.storeResource= %{idp.home}/credentials/sealer.jks
idp.sealer.versionResource= %{idp.home}/credentials/sealer.kver
idp.sealer.storePassword= 1
idp.sealer.keyPassword= 1

# Settings for public/private signing and encryption key(s)
# During decryption key rollover, point the ".2" properties at a second
# keypair, uncomment in credentials.xml, then publish it in your metadata.
idp.signing.key= %{idp.home}/credentials/idp-signing.key
idp.signing.cert= %{idp.home}/credentials/idp-signing.crt
idp.encryption.key= %{idp.home}/credentials/idp-encryption.key
idp.encryption.cert= %{idp.home}/credentials/idp-encryption.crt
#idp.encryption.key.2 = %{idp.home}/credentials/idp-encryption-old.key
#idp.encryption.cert.2 = %{idp.home}/credentials/idp-encryption-old.crt

# Sets the bean ID to use as a default security configuration set
#idp.security.config = shibboleth.DefaultSecurityConfiguration

# To default to SHA-1, set to shibboleth.SigningConfiguration.SHA1
#idp.signing.config = shibboleth.SigningConfiguration.SHA256

# Configures trust evaluation of keys used by services at runtime
# Defaults to supporting both explicit key and PKIX using SAML metadata.
#idp.trust.signatures = shibboleth.ChainingSignatureTrustEngine
# To pick only one set to one of:
#   shibboleth.ExplicitKeySignatureTrustEngine, shibboleth.PKIXSignatureTrustEngine
#idp.trust.certificates = shibboleth.ChainingX509TrustEngine
# To pick only one set to one of:
#   shibboleth.ExplicitKeyX509TrustEngine, shibboleth.PKIXX509TrustEngine

# If true, encryption will happen whenever a key to use can be located, but
# failure to encrypt won't result in request failure.
#idp.encryption.optional = false

# Configuration of client- and server-side storage plugins
#idp.storage.cleanupInterval = PT10M
#idp.storage.htmlLocalStorage = false

# Set to true to expose more detailed errors in responses to SPs
#idp.errors.detailed = false
# Set to false to skip signing of SAML response messages that signal errors
#idp.errors.signed = true
# Name of bean containing a list of Java exception classes to ignore
#idp.errors.excludedExceptions = ExceptionClassListBean
# Name of bean containing a property set mapping exception names to views
#idp.errors.exceptionMappings = ExceptionToViewPropertyBean
# Set if a different default view name for events and exceptions is needed
#idp.errors.defaultView = error

# Set to false to disable the IdP session layer
idp.session.enabled = true

# Set to "shibboleth.StorageService" for server-side storage of user sessions
idp.session.StorageService = shibboleth.StorageService

# Size of session IDs
#idp.session.idSize = 32
# Bind sessions to IP addresses
#idp.session.consistentAddress = true
# Inactivity timeout
#idp.session.timeout = PT60M
# Extra time to store sessions for logout
idp.session.slop = PT60M
# Tolerate storage-related errors
#idp.session.maskStorageFailure = false
# Track information about SPs logged into
idp.session.trackSPSessions = true
# Support lookup by SP for SAML logout
idp.session.secondaryServiceIndex = true
# Length of time to track SP sessions
#idp.session.defaultSPlifetime = PT2H

# Regular expression matching login flows to enable, e.g. IPAddress|Password


# Regular expression of forced "initial" methods when no session exists,
# usually in conjunction with the idp.authn.resolveAttribute property below.
#idp.authn.flows.initial = Password

# Set to an attribute ID to resolve prior to selecting authentication flows;
# its values are used to filter the flows to allow.
#idp.authn.resolveAttribute = eduPersonAssurance

# Default lifetime and timeout of various authentication methods
#idp.authn.defaultLifetime = PT60M
#idp.authn.defaultTimeout = PT30M

# Whether to prioritize "active" results when an SP requests more than
# one possible matching login method (V2 behavior was to favor them)
#idp.authn.favorSSO = true

# Whether to fail requests when a user identity after authentication
# doesn't match the identity in a pre-existing session.
#idp.authn.identitySwitchIsError = false

# Set to "shibboleth.StorageService" or custom bean for alternate storage of consent
#idp.consent.StorageService = shibboleth.ClientPersistentStorageService

# Set to "shibboleth.consent.AttributeConsentStorageKey" to use an attribute
# to key user consent storage records (and set the attribute name)
#idp.consent.userStorageKey = shibboleth.consent.PrincipalConsentStorageKey
#idp.consent.userStorageKeyAttribute = uid

# Flags controlling how built-in attribute consent feature operates
#idp.consent.allowDoNotRemember = true
#idp.consent.allowGlobal = true
#idp.consent.allowPerAttribute = false

# Whether attribute values and terms of use text are compared
#idp.consent.compareValues = false
# Maximum number of consent records for space-limited storage (e.g. cookies)
#idp.consent.maxStoredRecords = 10
# Maximum number of consent records for larger/server-side storage (0 = no limit)
#idp.consent.expandedMaxStoredRecords = 0

# Time in milliseconds to expire consent storage records.
#idp.consent.storageRecordLifetime = P1Y

# Whether to lookup metadata, etc. for every SP involved in a logout
# for use by user interface logic; adds overhead so off by default.
idp.logout.elaboration = true

# Whether to require logout requests be signed/authenticated.
idp.logout.authenticated = false

# Message freshness and replay cache tuning
#idp.policy.messageLifetime = PT3M
#idp.policy.clockSkew = PT3M

# Set to custom bean for alternate storage of replay cache
#idp.replayCache.StorageService = shibboleth.StorageService

# Toggles whether to allow outbound messages via SAML artifact
#idp.artifact.enabled = true
# Suppresses typical signing/encryption when artifact binding used
#idp.artifact.secureChannel = true
# May differ to direct SAML 2 artifact lookups to specific server nodes
#idp.artifact.endpointIndex = 2
# Set to custom bean for alternate storage of artifact map state
#idp.artifact.StorageService = shibboleth.StorageService

# Name of access control policy for various admin flows
idp.status.accessPolicy= AccessByIPAddress
idp.resolvertest.accessPolicy= AccessByIPAddress
idp.reload.accessPolicy= AccessByIPAddress

# Comma-delimited languages to use if not match can be found with the
# browser-supported languages, defaults to an empty list.
idp.ui.fallbackLanguages= en,fr,de

# Storage service used by CAS protocol
# Defaults to shibboleth.StorageService (in-memory)
# MUST be server-side storage (e.g. in-memory, memcached, database)
# NOTE that idp.session.StorageService requires server-side storage
# when CAS protocol is enabled
idp.cas.StorageService=shibboleth.StorageService

# CAS service registry implementation class
#idp.cas.serviceRegistryClass=net.shibboleth.idp.cas.service.PatternServiceRegistry

# Profile flows in which the ProfileRequestContext should be exposed
# in servlet request under the key "opensamlProfileRequestContext"
#idp.profile.exposeProfileRequestContextInServletRequest = SAML2/POST/SSO,SAML2/Redirect/SSO

# F-TICKS auditing - set salt to include hashed username
#idp.fticks.federation=MyFederation
#idp.fticks.algorithm=SHA-256
#idp.fticks.salt=somethingsecret
# Regular expression matching login flows to enable, e.g. IPAddress|Password
#idp.authn.flows = Password


# By default you always get the AuthenticatedNameTranslator, add additional code to cover your custom needs.
# Takes a comma separated list of fully qualified class names
# shibcas.casToShibTranslators = com.your.institution.MyCustomNamedTranslatorClass

## leth
idp.authn.flows = Shibcas

# CAS Client properties (usage loosely matches that of the Java CAS Client)
# CAS Server Properties
shibcas.casServerUrlPrefix = https://cas.tecapro.com.vn:8443/cas
shibcas.casServerLoginUrl = ${shibcas.casServerUrlPrefix}/login

## Shibboleth Server Properties
shibcas.serverName = https://chai65.iam:8443

...
```
### e. S?a file `attribute-filter.xml`
M?u:
```
<?xml version="1.0" encoding="UTF-8"?>
<!--
    This file is an EXAMPLE policy file.  While the policy presented in this
    example file is illustrative of some simple cases, it relies on the names of
    non-existent example services and the example attributes demonstrated in the
    default attribute-resolver.xml file.

    Deployers should refer to the documentation for a complete list of components
    and their options.
-->
<AttributeFilterPolicyGroup id="ShibbolethFilterPolicy"
        xmlns="urn:mace:shibboleth:2.0:afp"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="urn:mace:shibboleth:2.0:afp http://shibboleth.net/schema/idp/shibboleth-afp.xsd">

    <!-- Release some attributes to an SP. -->
    <AttributeFilterPolicy id="test1">
        <PolicyRequirementRule xsi:type="ANY"/>
        <AttributeRule attributeID="cn">
            <PermitValueRule xsi:type="ANY" />
        </AttributeRule>

        <AttributeRule attributeID="teca-users-email">
            <PermitValueRule xsi:type="ANY" />
        </AttributeRule>
        <AttributeRule attributeID="teca-users-macoquan">
            <PermitValueRule xsi:type="ANY" />
        </AttributeRule>

        <AttributeRule attributeID="cas-users-email">
            <PermitValueRule xsi:type="ANY" />
        </AttributeRule>
        <AttributeRule attributeID="cas-users-macoquan">
            <PermitValueRule xsi:type="ANY" />
        </AttributeRule>

        <AttributeRule attributeID="cas-users-madvi">
            <PermitValueRule xsi:type="ANY" />
        </AttributeRule>
        <AttributeRule attributeID="cas-users-mst">
            <PermitValueRule xsi:type="ANY" />
        </AttributeRule>
        <AttributeRule attributeID="email">
            <PermitValueRule xsi:type="ANY" />
        </AttributeRule>
        <AttributeRule attributeID="macoquan">
            <PermitValueRule xsi:type="ANY" />
        </AttributeRule>
        <AttributeRule attributeID="madonvi">
            <PermitValueRule xsi:type="ANY" />
        </AttributeRule>

    </AttributeFilterPolicy>

    <!-- Release eduPersonAffiliation to two specific SPs. -->
    <AttributeFilterPolicy id="example2">
        <PolicyRequirementRule xsi:type="OR">
            <Rule xsi:type="Requester" value="https://sp.example.org" />
            <Rule xsi:type="Requester" value="https://another.example.org/shibboleth" />
        </PolicyRequirementRule>

        <AttributeRule attributeID="eduPersonScopedAffiliation">
            <PermitValueRule xsi:type="ANY" />
        </AttributeRule>
    </AttributeFilterPolicy>

</AttributeFilterPolicyGroup>
```

# 3. Config v?i CAS Authn
> Cài d?t theo hu?ng d?n t?i link: [shib-cas-authn3](https://github.com/frzleaf/shib-cas-authn3)

#### a. Thêm plugin Shib-cas-authn3
- T?i source [shib-cas-authn3](https://github.com/frzleaf/shib-cas-authn3) v?
- Copy 2 file xml t? thu m?c IDP_HOME sao cho kh?p v?i du?ng d?n trong thu m?c cài Shibboleth

#### b. Config file `idp.properties`
Config/Thêm vào do?n sau:

```
...
# Regular expression matching login flows to enable, e.g. IPAddress|Password
#idp.authn.flows = Password
idp.authn.flows = Shibcas

# CAS Client properties (usage loosely matches that of the Java CAS Client)
## CAS Server Properties
shibcas.casServerUrlPrefix = https://cassserver.example.edu/cas
shibcas.casServerLoginUrl = ${shibcas.casServerUrlPrefix}/login

## Shibboleth Server Properties
shibcas.serverName = https://shibserver.example.edu

# By default you always get the AuthenticatedNameTranslator, add additional code to cover your custom needs.
# Takes a comma separated list of fully qualified class names
# shibcas.casToShibTranslators = com.your.institution.MyCustomNamedTranslatorClass
...
```
#### c. Thay d?i file `general-authn.xml`
Thêm module dang nh?p b?ng CAS b?ng cách thêm bean `authn/Shibcas` vào `conf/authn/general-authn.xml`:
```xml
...
    <util:list id="shibboleth.AvailableAuthenticationFlows">

        <bean id="authn/Shibcas" parent="shibboleth.AuthenticationFlow"
                p:passiveAuthenticationSupported="true"
                p:forcedAuthenticationSupported="true"
                p:nonBrowserSupported="false" />
...
```
#### d. Copy thu vi?n
Plugin này dùng d?n thu vi?n cas client, nên copy c? thu vi?n shib-cas-authenticator và cas-client-core vào `edit-webapp/WEB-INF/lib/`
- <https://github.com/frzleaf/shib-cas-authn3/releases/download/v3.0.0/shib-cas-authenticator-3.0.0.jar>
- <https://github.com/frzleaf/shib-cas-authn3/releases/download/v3.0.0/cas-client-core-3.3.3.jar>

#### e. Build l?i file war
Ch?y file `bin/build.sh`(Unix-like) ho?c `bin\build.bat`(Windows) d? build l?i file `idp.war`

# 4. Build file war d? deploy trên Weblogic
- T?o file `edit-webapp/WEB-INF/weblogic.xml`:
```
<?xml version="1.0" encoding="UTF-8"?>
<weblogic-web-app
        xmlns="http://www.bea.com/ns/weblogic/90"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://www.bea.com/ns/weblogic/90
                    http://www.bea.com/ns/weblogic/90/weblogic-web-app.xsd">

    <container-descriptor>
        <prefer-web-inf-classes>true</prefer-web-inf-classes>
    </container-descriptor>
</weblogic-web-app>
```
- Ch?y file `bin/build.sh` d? build l?i file `war/idp.war`
- M? weblogic, deploy file `war/idp.war` v?a t?o

> N?u trong quá trình deploy, x?y ra l?i javax.xml... thì xóa file xml-apis* trong thu m?c `edit-webapp/WEB-INF/lib` d? build l?i