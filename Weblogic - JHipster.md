# 1. Project Jhipster
     Ð?m b?o project dã có file ApplicationWebXml
```
public class ApplicationWebXml extends SpringBootServletInitializer {

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        /**
         * set a default to use when no profile is configured.
         */
        DefaultProfileUtil.addDefaultProfile(application.application());
        return application.sources(LdapWebserviceApp.class);
    }
}
```
# 2. Thêm WEB-INF
     T?o m?i thu m?c WEB-INF n?u chua có trong folder webapp và thêm 2 file
`dispatcherServlet-servlet.xml`
```
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
    http://www.springframework.org/schema/beans/spring-beans.xsd">

    <!-- Do not remove this file! -->

</beans>
```

`weblogic.xml`
```
<?xml version="1.0" encoding="UTF-8"?>
<wls:weblogic-web-app
    xmlns:wls="http://xmlns.oracle.com/weblogic/weblogic-web-app"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://java.sun.com/xml/ns/javaee
http://java.sun.com/xml/ns/javaee/ejb-jar_3_0.xsd
http://xmlns.oracle.com/weblogic/weblogic-web-app
http://xmlns.oracle.com/weblogic/weblogic-web-app/1.4/weblogic-web-app.xsd">
    <wls:context-root>/ldapws</wls:context-root>
    <wls:container-descriptor>
        <wls:prefer-application-packages>
            <wls:package-name>com.fasterxml.jackson.*</wls:package-name>
            <wls:package-name>org.slf4j.*</wls:package-name>
            <wls:package-name>com.fasterxml.jackson.datatype.*</wls:package-name>
            <wls:package-name>javassist.*</wls:package-name>
            <wls:package-name>org.joda.time.*</wls:package-name>
            <wls:package-name>javax.persistence.*</wls:package-name>
            <wls:package-name>com.google.common.*</wls:package-name>
        </wls:prefer-application-packages>
        <!--<wls:prefer-web-inf-classes>true</wls:prefer-web-inf-classes>-->
    </wls:container-descriptor>

</wls:weblogic-web-app>
```
# 3. Build
     Build file war jhipster:
     $ mvn package
     ho?c 
     $ gradle bootRepackage