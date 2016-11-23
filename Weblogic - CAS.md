### 1. Thêm file weblogic.xml
T?o file WEB-INF/weblogic.xml n?i dung nhu sau:
```
<?xml version="1.0" encoding="UTF-8"?>
<wls:weblogic-web-app xmlns:wls="http://www.bea.com/ns/weblogic/weblogic-web-app"
                      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                      xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-app_2_5.xsd http://www.bea.com/ns/weblogic/weblogic-web-app http://www.bea.com/ns/weblogic/weblogic-web-app/1.0/weblogic-web-app.xsd">
    <wls:weblogic-version>10.3</wls:weblogic-version>
    <wls:context-root>cas-server</wls:context-root>
    <wls:container-descriptor>
        <wls:show-archived-real-path-enabled>true</wls:show-archived-real-path-enabled>
        <wls:prefer-web-inf-classes>true</wls:prefer-web-inf-classes>
    </wls:container-descriptor>
</wls:weblogic-web-app>
```
### 2. S?a thu vi?n
Xóa thu vi?n: /WEB-INF/lib/xml-apis*.jar
### 3. Config Log4j
Copy file `WEB-INF/classes/log4j.xml` vào `/etc/cas/`

Thêm dòng này vào file `cas.properties`:
```
...
log4j.config.location=/etc/cas/log4j.xml
...
```
### 4. Build
Build l?i file cas.war và deploy trên Weblogic