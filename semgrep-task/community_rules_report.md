# Semgrep Rules Report

**Total Languages:** 28
**Total Rules:** 2242

---

## Ai (25 rules)

**`detect-anthropic`** | INFO | `community-rules\ai\python\detect-anthropic.yaml`
> Possibly found usage of AI: Anthropic

---

**`detect-anthropic`** | INFO | `community-rules\ai\typescript\detect-anthropic.yaml`
> Possibly found usage of AI: Anthropic

---

**`detect-apple-core-ml`** | INFO | `community-rules\ai\swift\detect-apple-core-ml.yaml`
> Possibly found usage of AI: Apple CoreML

---

**`detect-gemini`** | INFO | `community-rules\ai\dart\detect-gemini.yaml`
> Possibly found usage of AI: Gemini

---

**`detect-gemini`** | INFO | `community-rules\ai\go\detect-gemini.yaml`
> Possibly found usage of AI: Gemini

---

**`detect-gemini`** | INFO | `community-rules\ai\kotlin\detect-gemini.yaml`
> Possibly found usage of AI: Gemini

---

**`detect-gemini`** | INFO | `community-rules\ai\python\detect-gemini.yaml`
> Possibly found usage of AI: Gemini

---

**`detect-gemini`** | INFO | `community-rules\ai\swift\detect-gemini.yaml`
> Possibly found usage of AI: Gemini

---

**`detect-gemini`** | INFO | `community-rules\ai\typescript\detect-gemini.yaml`
> Possibly found usage of AI: Gemini

---

**`detect-generic-ai-anthprop`** | INFO | `community-rules\ai\generic\detect-generic-ai-anthprop.yaml`
> Possibly found usage of AI: Anthropic

---

**`detect-generic-ai-api`** | INFO | `community-rules\ai\generic\detect-generic-ai-api.yaml`
> Possibly found usage of AI: HTTP Request

---

**`detect-generic-ai-gem`** | INFO | `community-rules\ai\generic\detect-generic-ai-gem.yaml`
> Possibly found usage of AI: Gemini

---

**`detect-generic-ai-oai`** | INFO | `community-rules\ai\generic\detect-generic-ai-oai.yaml`
> Possibly found usage of AI: OpenAI

---

**`detect-huggingface`** | INFO | `community-rules\ai\python\detect-huggingface.yaml`
> Possibly found usage of AI: HuggingFace

---

**`detect-langchain`** | INFO | `community-rules\ai\python\detect-langchain.yaml`
> Possibly found usage of AI tooling: LangChain

---

**`detect-mistral`** | INFO | `community-rules\ai\python\detect-mistral.yaml`
> Possibly found usage of AI: Mistral

---

**`detect-mistral`** | INFO | `community-rules\ai\typescript\detect-mistral.yaml`
> Possibly found usage of AI: Mistral

---

**`detect-openai`** | INFO | `community-rules\ai\csharp\detect-openai.yaml`
> Possibly found usage of AI: OpenAI

---

**`detect-openai`** | INFO | `community-rules\ai\go\detect-openai.yaml`
> Possibly found usage of AI: OpenAI

---

**`detect-openai`** | INFO | `community-rules\ai\python\detect-openai.yaml`
> Possibly found usage of AI: OpenAI

---

**`detect-openai`** | INFO | `community-rules\ai\typescript\detect-openai.yaml`
> Possibly found usage of AI: OpenAI

---

**`detect-promptfoo`** | INFO | `community-rules\ai\typescript\detect-promptfoo.yaml`
> Possibly found usage of AI tooling: promptfoo

---

**`detect-pytorch`** | INFO | `community-rules\ai\python\detect-pytorch.yaml`
> Possibly found usage of AI tooling: PyTorch

---

**`detect-tensorflow`** | INFO | `community-rules\ai\python\detect-tensorflow.yaml`
> Possibly found usage of AI tooling: Tensorflow

---

**`detect-vercel-ai`** | INFO | `community-rules\ai\typescript\detect-vercel-ai.yaml`
> Possibly found usage of AI: VercelAI

---

## Apex (18 rules)

**`absolute-urls`** | WARNING | `community-rules\apex\lang\best-practice\ncino\urls\AbsoluteUrls.yaml`
> Using absolute URLs to Salesforce Pages is bug prone. Different sandboxes and production environments will have different instance names (like "na10", "na15" etc.). Code using absolute URLs will only work when it runs in the corresponding salesforce instances. It will break as soon as it is deployed in another one. Thus only relative URLs, i.e. without the domain and subdomain names, should be used when pointing to a salesforce page.

---

**`apex-csrf-constructor`** | ERROR | `community-rules\apex\lang\security\ncino\dml\ApexCSRFConstructor.yaml`
> Having DML operations in Apex class constructor or initializers can have unexpected side effects: By just accessing a page, the DML statements would be executed and the database would be modified. Just querying the database is permitted.

---

**`apex-csrf-static-constructor`** | ERROR | `community-rules\apex\lang\security\ncino\dml\ApexCSRFStaticConstructor.yaml`
> Having DML operations in Apex class constructor or initializers can have unexpected side effects: By just accessing a page, the DML statements would be executed and the database would be modified. Just querying the database is permitted.

---

**`avoid-native-dml-in-loops`** | ERROR | `community-rules\apex\lang\performance\ncino\operationsInLoops\AvoidNativeDmlInLoops.yaml`
> Avoid DML statements inside loops to avoid hitting the DML governor limit. Instead, try to batch up the data into a list and invoke your DML once on that list of data outside the loop.

---

**`avoid-operations-with-limits-in-loops`** | ERROR | `community-rules\apex\lang\performance\ncino\operationsInLoops\AvoidOperationsWithLimitsInLoops.yaml`
> Database class methods, DML operations, SOQL queries, SOSL queries, Approval class methods, Email sending, async scheduling or queueing within loops can cause governor limit exceptions. Instead, try to batch up the data into a list and invoke the operation once on that list of data outside the loop.

---

**`avoid-soql-in-loops`** | ERROR | `community-rules\apex\lang\performance\ncino\operationsInLoops\AvoidSoqlInLoops.yaml`
> Database class methods, DML operations, SOQL queries, SOSL queries, Approval class methods, Email sending, async scheduling or queueing within loops can cause governor limit exceptions. Instead, try to batch up the data into a list and invoke the operation once on that list of data outside the loop.

---

**`avoid-sosl-in-loops`** | ERROR | `community-rules\apex\lang\performance\ncino\operationsInLoops\AvoidSoslInLoops.yaml`
> Database class methods, DML operations, SOQL queries, SOSL queries, Approval class methods, Email sending, async scheduling or queueing within loops can cause governor limit exceptions. Instead, try to batch up the data into a list and invoke the operation once on that list of data outside the loop.

---

**`bad-crypto`** | ERROR | `community-rules\apex\lang\security\ncino\encryption\BadCrypto.yaml`
> The rule makes sure you are using randomly generated IVs and keys for Crypto calls. Hard-coding these values greatly compromises the security of encrypted data.

---

**`dml-native-statements`** | WARNING | `community-rules\apex\lang\security\ncino\dml\DmlNativeStatements.yaml`
> Native Salesforce DML operations execute in system context, ignoring the current user's permissions, field-level security, organization-wide defaults, position in the role hierarchy, and sharing rules. Be mindful when using native Salesforce DML operations.

---

**`global-access-modifiers`** | WARNING | `community-rules\apex\lang\best-practice\ncino\accessModifiers\GlobalAccessModifiers.yaml`
> Global classes, methods, and variables should be avoided (especially in managed packages) as they can never be deleted or changed in signature. Always check twice if something needs to be global.

---

**`insecure-http-request`** | ERROR | `community-rules\apex\lang\security\ncino\endpoints\InsecureHttpRequest.yaml`
> The software transmits sensitive or security-critical data in cleartext in a communication channel that can be sniffed by unauthorized actors.

---

**`named-credentials-constant-match`** | ERROR | `community-rules\apex\lang\security\ncino\endpoints\NamedCredentialsConstantMatch.yaml`
> Named Credentials (and callout endpoints) should be used instead of hard-coding credentials. 1. Hard-coded credentials are hard to maintain when mixed in with application code. 2. It is particularly hard to update hard-coded credentials when they are used amongst different classes. 3. Granting a developer access to the codebase means granting knowledge of credentials, and thus keeping a two-level access is not possible. 4. Using different credentials for different environments is troublesome and error-prone.

---

**`named-credentials-string-match`** | ERROR | `community-rules\apex\lang\security\ncino\endpoints\NamedCredentialsStringMatch.yaml`
> Named Credentials (and callout endpoints) should be used instead of hard-coding credentials. 1. Hard-coded credentials are hard to maintain when mixed in with application code. 2. It is particularly hard to update hard-coded credentials when they are used amongst different classes. 3. Granting a developer access to the codebase means granting knowledge of credentials, and thus keeping a two-level access is not possible. 4. Using different credentials for different environments is troublesome and error-prone.

---

**`soql-injection-unescaped-param`** | ERROR | `community-rules\apex\lang\security\ncino\injection\ApexSOQLInjectionUnescapedParam.yaml`
> If a dynamic query must be used,leverage nFORCE Query Builder. In other programming languages, the related flaw is known as SQL injection. Apex doesn't use SQL, but uses its own database query language, SOQL. SOQL is much simpler and more limited in functionality than SQL. The risks are much lower for SOQL injection than for SQL injection, but the attacks are nearly identical to traditional SQL injection. SQL/SOQL injection takes user-supplied input and uses those values in a dynamic SOQL query. If the input isn't validated, it can include SOQL commands that effectively modify the SOQL statement and trick the application into performing unintended commands.

---

**`soql-injection-unescaped-url-param`** | ERROR | `community-rules\apex\lang\security\ncino\injection\ApexSOQLInjectionFromUnescapedURLParam.yaml`
> If a dynamic query must be used,leverage nFORCE Query Builder. In other programming languages, the related flaw is known as SQL injection. Apex doesn't use SQL, but uses its own database query language, SOQL. SOQL is much simpler and more limited in functionality than SQL. The risks are much lower for SOQL injection than for SQL injection, but the attacks are nearly identical to traditional SQL injection. SQL/SOQL injection takes user-supplied input and uses those values in a dynamic SOQL query. If the input isn't validated, it can include SOQL commands that effectively modify the SOQL statement and trick the application into performing unintended commands.

---

**`specify-sharing-level`** | WARNING | `community-rules\apex\lang\security\ncino\sharing\SpecifySharingLevel.yaml`
> Every Apex class should have an explicit sharing mode declared. Use the `with sharing` or `without sharing` keywords on a class to specify whether sharing rules must be enforced. Use the `inherited sharing` keyword on an Apex class to run the class in the sharing mode of the class that called it.

---

**`system-debug`** | WARNING | `community-rules\apex\lang\security\ncino\system\SystemDebug.yaml`
> In addition to debug statements potentially logging data excessively, debug statements also contribute to longer transactions and consume Apex CPU time even when debug logs are not being captured.

---

**`use-assert-class`** | WARNING | `community-rules\apex\lang\best-practice\ncino\tests\UseAssertClass.yaml`
> Assert methods in the System class have been replaced with the Assert class: https://developer.salesforce.com/docs/atlas.en-us.apexref.meta/apexref/apex_class_System_Assert.htm

---

## Bash (7 rules)

**`curl-eval`** | WARNING | `community-rules\bash\curl\security\curl-eval.yaml`
> Data is being eval'd from a `curl` command. An attacker with control of the server in the `curl` command could inject malicious code into the `eval`, resulting in a system comrpomise. Avoid eval'ing untrusted data if you can. If you must do this, consider checking the SHA sum of the content returned by the server to verify its integrity.

---

**`curl-pipe-bash`** | WARNING | `community-rules\bash\curl\security\curl-pipe-bash.yaml`
> Data is being piped into `bash` from a `curl` command. An attacker with control of the server in the `curl` command could inject malicious code into the pipe, resulting in a system compromise. Avoid piping untrusted data into `bash` or any other shell if you can. If you must do this, consider checking the SHA sum of the content returned by the server to verify its integrity.

---

**`ifs-tampering`** | WARNING | `community-rules\bash\lang\security\ifs-tampering.yaml`
> The special variable IFS affects how splitting takes place when expanding unquoted variables. Don't set it globally. Prefer a dedicated utility such as 'cut' or 'awk' if you need to split input data. If you must use 'read', set IFS locally using e.g. 'IFS="," read -a my_array'.

---

**`iteration-over-ls-output`** | WARNING | `community-rules\bash\lang\best-practice\iteration-over-ls-output.yaml`
> Iterating over ls output is fragile. Use globs, e.g. 'dir/*' instead of '$(ls dir)'.

---

**`unquoted-command-substitution-in-command`** | INFO | `community-rules\bash\lang\correctness\unquoted-expansion.yaml`
> The result of command substitution $(...) or `...`, if unquoted, is split on whitespace or other separators specified by the IFS variable. You should surround it with double quotes to avoid splitting the result.

---

**`unquoted-variable-expansion-in-command`** | INFO | `community-rules\bash\lang\correctness\unquoted-expansion.yaml`
> Variable expansions must be double-quoted so as to prevent being split into multiple pieces according to whitespace or whichever separator is specified by the IFS variable. If you really wish to split the variable's contents, you may use a variable that starts with an underscore e.g. $_X instead of $X, and semgrep will ignore it. If what you need is an array, consider using a proper bash array.

---

**`useless-cat`** | WARNING | `community-rules\bash\lang\best-practice\useless-cat.yaml`
> Useless call to 'cat' in a pipeline. Use '<' and '>' for any command to read from a file or write to a file.

---

## C (16 rules)

**`c-string-equality`** | ERROR | `community-rules\c\lang\correctness\c-string-equality.yaml`
> Using == on char* performs pointer comparison, use strcmp instead

---

**`double-free`** | ERROR | `community-rules\c\lang\security\double-free.yaml`
> Variable '$VAR' was freed twice. This can lead to undefined behavior.

---

**`double_goto`** | WARNING | `community-rules\c\lang\correctness\goto-fail.yaml`
> The second goto statement will always be executed.

---

**`function-use-after-free`** | WARNING | `community-rules\c\lang\security\function-use-after-free.yaml`
> Variable '$VAR' was passed to a function after being freed. This can lead to undefined behavior.

---

**`incorrect-use-ato-fn`** | WARNING | `community-rules\c\lang\correctness\incorrect-use-ato-fn.yaml`
> Avoid the 'ato*()' family of functions. Their use can lead to undefined behavior, integer overflows, and lack of appropriate error handling. Instead prefer the 'strtol*()' family of functions.

---

**`incorrect-use-sscanf-fn`** | WARNING | `community-rules\c\lang\correctness\incorrect-use-sscanf-fn.yaml`
> Avoid 'sscanf()' for number conversions. Its use can lead to undefined behavior, slow processing, and integer overflows. Instead prefer the 'strto*()' family of functions.

---

**`info-leak-on-non-formated-string`** | WARNING | `community-rules\c\lang\security\info-leak-on-non-formatted-string.yaml`
> Use %s, %d, %c... to format your variables, otherwise this could leak information.

---

**`insecure-use-gets-fn`** | ERROR | `community-rules\c\lang\security\insecure-use-gets-fn.yaml`
> Avoid 'gets()'. This function does not consider buffer boundaries and can lead to buffer overflows. Use 'fgets()' or 'gets_s()' instead.

---

**`insecure-use-memset`** | WARNING | `community-rules\c\lang\security\insecure-use-memset.yaml`
> When handling sensitive information in a buffer, it's important to ensure  that the data is securely erased before the buffer is deleted or reused.  While `memset()` is commonly used for this purpose, it can leave sensitive  information behind due to compiler optimizations or other factors.  To avoid this potential vulnerability, it's recommended to use the  `memset_s()` function instead. `memset_s()` is a standardized function  that securely overwrites the memory with a specified value, making it more  difficult for an attacker to recover any sensitive data that was stored in  the buffer. By using `memset_s()` instead of `memset()`, you can help to  ensure that your application is more secure and less vulnerable to exploits  that rely on residual data in memory.

---

**`insecure-use-printf-fn`** | WARNING | `community-rules\c\lang\security\insecure-use-printf-fn.yaml`
> Avoid using user-controlled format strings passed into 'sprintf', 'printf' and 'vsprintf'. These functions put you at risk of buffer overflow vulnerabilities through the use of format string exploits. Instead, use 'snprintf' and 'vsnprintf'.

---

**`insecure-use-scanf-fn`** | WARNING | `community-rules\c\lang\security\insecure-use-scanf-fn.yaml`
> Avoid using 'scanf()'. This function, when used improperly, does not consider buffer boundaries and can lead to buffer overflows. Use 'fgets()' instead for reading input.

---

**`insecure-use-strcat-fn`** | WARNING | `community-rules\c\lang\security\insecure-use-strcat-fn.yaml`
> Finding triggers whenever there is a strcat or strncat used. This is an issue because strcat or strncat can lead to buffer overflow vulns. Fix this by using strcat_s instead.

---

**`insecure-use-string-copy-fn`** | WARNING | `community-rules\c\lang\security\insecure-use-string-copy-fn.yaml`
> Finding triggers whenever there is a strcpy or strncpy used. This is an issue because strcpy does not affirm the size of the destination array and strncpy will not automatically NULL-terminate strings. This can lead to buffer overflows, which can cause program crashes and potentially let an attacker inject code in the program. Fix this by using strcpy_s instead (although note that strcpy_s is an optional part of the C11 standard, and so may not be available).

---

**`insecure-use-strtok-fn`** | WARNING | `community-rules\c\lang\security\insecure-use-strtok-fn.yaml`
> Avoid using 'strtok()'. This function directly modifies the first argument buffer, permanently erasing the delimiter character. Use 'strtok_r()' instead.

---

**`random-fd-exhaustion`** | WARNING | `community-rules\c\lang\security\random-fd-exhaustion.yaml`
> Call to 'read()' without error checking is susceptible to file descriptor exhaustion. Consider using the 'getrandom()' function.

---

**`use-after-free`** | WARNING | `community-rules\c\lang\security\use-after-free.yaml`
> Variable '$VAR' was used after being freed. This can lead to undefined behavior.

---

## Clojure (5 rules)

**`command-injection-shell-call`** | ERROR | `community-rules\clojure\lang\security\command-injection-shell-call.yaml`
> A call to clojure.java.shell has been found, this could lead to an RCE if the inputs are user-controllable. Please ensure their origin is validated and sanitized.

---

**`documentbuilderfactory-xxe`** | ERROR | `community-rules\clojure\lang\security\documentbuilderfactory-xxe.yaml`
> DOCTYPE declarations are enabled for javax.xml.parsers.SAXParserFactory. Without prohibiting external entity declarations, this is vulnerable to XML external entity attacks. Disable this by setting the feature "http://apache.org/xml/features/disallow-doctype-decl" to true. Alternatively, allow DOCTYPE declarations and only prohibit external entities declarations. This can be done by setting the features "http://xml.org/sax/features/external-general-entities" and "http://xml.org/sax/features/external-parameter-entities" to false.

---

**`read-string-unsafe`** | ERROR | `community-rules\clojure\security\clojure-read-string\read-string-unsafe.yaml`
> The default core Clojure read-string method is dangerous and can lead to deserialization vulnerabilities. Use the edn/read-string instead.

---

**`use-of-md5`** | WARNING | `community-rules\clojure\lang\security\use-of-md5.yaml`
> MD5 hash algorithm detected. This is not collision resistant and leads to easily-cracked password hashes. Replace with current recommended hashing algorithms.

---

**`use-of-sha1`** | WARNING | `community-rules\clojure\lang\security\use-of-sha1.yaml`
> Detected SHA1 hash algorithm which is considered insecure. SHA1 is not collision resistant and is therefore not suitable as a cryptographic signature. Instead, use PBKDF2 for password hashing or SHA256 or SHA512 for other hash function applications.

---

## Csharp (52 rules)

**`X509-subject-name-validation`** | WARNING | `community-rules\csharp\lang\security\cryptography\X509-subject-name-validation.yaml`
> Validating certificates based on subject name is bad practice. Use the X509Certificate2.Verify() method instead.

---

**`X509Certificate2-privkey`** | WARNING | `community-rules\csharp\lang\security\cryptography\X509Certificate2-privkey.yaml`
> X509Certificate2.PrivateKey is obsolete. Use a method such as GetRSAPrivateKey() or GetECDsaPrivateKey(). Alternatively, use the CopyWithPrivateKey() method to create a new instance with a private key. Further, if you set X509Certificate2.PrivateKey to `null` or set it to another key without deleting it first, the private key will be left on disk. 

---

**`correctness-double-epsilon-equality`** | WARNING | `community-rules\csharp\lang\correctness\double\double-epsilon-equality.yaml`
> Double.Epsilon is defined by .NET as the smallest value that can be added to or subtracted from a zero-value Double. It is unsuitable for equality comparisons of non-zero Double values. Furthermore, the value of Double.Epsilon is framework and processor architecture dependent. Wherever possible, developers should prefer the framework Equals() method over custom equality implementations.

---

**`correctness-regioninfo-interop`** | WARNING | `community-rules\csharp\lang\correctness\regioninfo\regioninfo-interop.yaml`
> Potential inter-process write of RegionInfo $RI via $PIPESTREAM $P that was instantiated with a two-character culture code $REGION.  Per .NET documentation, if you want to persist a RegionInfo object or communicate it between processes, you should instantiate it by using a full culture name rather than a two-letter ISO region code.

---

**`correctness-sslcertificatetrust-handshake-no-trust`** | WARNING | `community-rules\csharp\lang\correctness\sslcertificatetrust\sslcertificatetrust-handshake-no-trust.yaml`
> Sending the trusted CA list increases the size of the handshake request and can leak system configuration information.

---

**`csharp-sqli`** | ERROR | `community-rules\csharp\lang\security\sqli\csharp-sqli.yaml`
> Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements instead. You can obtain a PreparedStatement using 'SqlCommand' and 'SqlParameter'.

---

**`data-contract-resolver`** | WARNING | `community-rules\csharp\lang\security\insecure-deserialization\data-contract-resolver.yaml`
> Only use DataContractResolver if you are completely sure of what information is being serialized. Malicious types can cause unexpected behavior.

---

**`html-raw-json`** | ERROR | `community-rules\csharp\razor\security\html-raw-json.yaml`
> Unencoded JSON in HTML context is vulnerable to cross-site scripting, because `</script>` is not properly encoded.

---

**`http-listener-wildcard-bindings`** | WARNING | `community-rules\csharp\lang\security\http\http-listener-wildcard-bindings.yaml`
> The top level wildcard bindings $PREFIX leaves your application open to security vulnerabilities and give attackers more control over where traffic is routed. If you must use wildcards, consider using subdomain wildcard binding. For example, you can use "*.asdf.gov" if you own all of "asdf.gov".

---

**`insecure-binaryformatter-deserialization`** | WARNING | `community-rules\csharp\lang\security\insecure-deserialization\binary-formatter.yaml`
> The BinaryFormatter type is dangerous and is not recommended for data processing. Applications should stop using BinaryFormatter as soon as possible, even if they believe the data they're processing to be trustworthy. BinaryFormatter is insecure and can't be made secure

---

**`insecure-fastjson-deserialization`** | WARNING | `community-rules\csharp\lang\security\insecure-deserialization\fast-json.yaml`
> $type extension has the potential to be unsafe, so use it with common sense and known json sources and not public facing ones to be safe

---

**`insecure-fspickler-deserialization`** | WARNING | `community-rules\csharp\lang\security\insecure-deserialization\fs-pickler.yaml`
> The FsPickler is dangerous and is not recommended for data processing. Default configuration tend to insecure deserialization vulnerability.

---

**`insecure-javascriptserializer-deserialization`** | ERROR | `community-rules\csharp\lang\security\insecure-deserialization\javascript-serializer.yaml`
> The SimpleTypeResolver class is insecure and should not be used. Using SimpleTypeResolver to deserialize JSON could allow the remote client to execute malicious code within the app and take control of the web server.

---

**`insecure-losformatter-deserialization`** | WARNING | `community-rules\csharp\lang\security\insecure-deserialization\los-formatter.yaml`
> The LosFormatter type is dangerous and is not recommended for data processing. Applications should stop using LosFormatter as soon as possible, even if they believe the data they're processing to be trustworthy. LosFormatter is insecure and can't be made secure

---

**`insecure-netdatacontract-deserialization`** | WARNING | `community-rules\csharp\lang\security\insecure-deserialization\net-data-contract.yaml`
> The NetDataContractSerializer type is dangerous and is not recommended for data processing. Applications should stop using NetDataContractSerializer as soon as possible, even if they believe the data they're processing to be trustworthy. NetDataContractSerializer is insecure and can't be made secure

---

**`insecure-newtonsoft-deserialization`** | WARNING | `community-rules\csharp\lang\security\insecure-deserialization\newtonsoft.yaml`
> TypeNameHandling $TYPEHANDLER is unsafe and can lead to arbitrary code execution in the context of the process. Use a custom SerializationBinder whenever using a setting other than TypeNameHandling.None.

---

**`insecure-soapformatter-deserialization`** | WARNING | `community-rules\csharp\lang\security\insecure-deserialization\soap-formatter.yaml`
> The SoapFormatter type is dangerous and is not recommended for data processing. Applications should stop using SoapFormatter as soon as possible, even if they believe the data they're processing to be trustworthy. SoapFormatter is insecure and can't be made secure

---

**`insecure-typefilterlevel-full`** | WARNING | `community-rules\csharp\lang\security\insecure-deserialization\insecure-typefilterlevel-full.yaml`
> Using a .NET remoting service can lead to RCE, even if you try to configure TypeFilterLevel. Recommended to switch from .NET Remoting to WCF https://docs.microsoft.com/en-us/dotnet/framework/wcf/migrating-from-net-remoting-to-wcf

---

**`jwt-tokenvalidationparameters-no-expiry-validation`** | WARNING | `community-rules\csharp\lang\security\ad\jwt-tokenvalidationparameters-no-expiry-validation.yaml`
> The TokenValidationParameters.$LIFETIME is set to $FALSE, this means the JWT tokens lifetime is not validated. This can lead to an JWT token being used after it has expired, which has security implications. It is recommended to validate the JWT lifetime to ensure only valid tokens are used.

---

**`ldap-injection`** | ERROR | `community-rules\csharp\dotnet\security\audit\ldap-injection.yaml`
> LDAP queries are constructed dynamically on user-controlled input. This vulnerability in code could lead to an arbitrary LDAP query execution.

---

**`mass-assignment`** | WARNING | `community-rules\csharp\dotnet\security\audit\mass-assignment.yaml`
> Mass assignment or Autobinding vulnerability in code allows an attacker to execute over-posting attacks, which could create a new parameter in the binding request and manipulate the underlying object in the application.

---

**`memory-marshal-create-span`** | WARNING | `community-rules\csharp\lang\security\memory\memory-marshal-create-span.yaml`
> MemoryMarshal.CreateSpan and MemoryMarshal.CreateReadOnlySpan should be used with caution, as the length argument is not checked.

---

**`misconfigured-lockout-option`** | WARNING | `community-rules\csharp\dotnet\security\audit\misconfigured-lockout-option.yaml`
> A misconfigured lockout mechanism allows an attacker to execute brute-force attacks. Account lockout must be correctly configured and enabled to prevent these attacks.

---

**`missing-hsts-header`** | WARNING | `community-rules\csharp\lang\security\missing-hsts-header.yaml`
> The HSTS HTTP response security header is missing, allowing interaction and communication to be sent over the insecure HTTP protocol.

---

**`missing-or-broken-authorization`** | INFO | `community-rules\csharp\dotnet\security\audit\missing-or-broken-authorization.yaml`
> Anonymous access shouldn't be allowed unless explicit by design. Access control checks are missing and potentially can be bypassed. This finding violates the principle of least privilege or deny by default, where access should only be permitted for a specific set of roles or conforms to a custom policy or users.

---

**`mvc-missing-antiforgery`** | WARNING | `community-rules\csharp\dotnet\security\mvc-missing-antiforgery.yaml`
> $METHOD is a state-changing MVC method that does not validate the antiforgery token or do strict content-type checking. State-changing controller methods should either enforce antiforgery tokens or do strict content-type checking to prevent simple HTTP request types from bypassing CORS preflight controls.

---

**`net-webconfig-debug`** | WARNING | `community-rules\csharp\dotnet\security\net-webconfig-debug.yaml`
> ASP.NET applications built with `debug` set to true in production may leak debug information to attackers. Debug mode also affects performance and reliability. Set `debug` to `false` or remove it from `<compilation ... />`

---

**`net-webconfig-trace-enabled`** | WARNING | `community-rules\csharp\dotnet\security\net-webconfig-trace-enabled.yaml`
> OWASP guidance recommends disabling tracing for production applications to prevent accidental leakage of sensitive application information.

---

**`open-directory-listing`** | INFO | `community-rules\csharp\dotnet\security\audit\open-directory-listing.yaml`
> An open directory listing is potentially exposed, potentially revealing sensitive information to attackers.

---

**`open-redirect`** | ERROR | `community-rules\csharp\lang\security\open-redirect.yaml`
> A query string parameter may contain a URL value that could cause the web application to redirect the request to a malicious website controlled by an attacker. Make sure to sanitize this parameter sufficiently.

---

**`os-command-injection`** | ERROR | `community-rules\csharp\lang\security\injections\os-command.yaml`
> The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component.

---

**`razor-template-injection`** | WARNING | `community-rules\csharp\dotnet\security\razor-template-injection.yaml`
> User-controllable string passed to Razor.Parse. This leads directly to code execution in the context of the process.

---

**`razor-use-of-htmlstring`** | WARNING | `community-rules\csharp\dotnet\security\audit\razor-use-of-htmlstring.yaml`
> ASP.NET Core MVC provides an HtmlString class which isn't automatically encoded upon output. This should never be used in combination with untrusted input as this will expose an XSS vulnerability.

---

**`regular-expression-dos`** | WARNING | `community-rules\csharp\lang\security\regular-expression-dos\regular-expression-dos.yaml`
> When using `System.Text.RegularExpressions` to process untrusted input, pass a timeout.  A malicious user can provide input to `RegularExpressions` that abuses the backtracking behaviour of this regular expression engine. This will lead to excessive CPU usage, causing a Denial-of-Service attack

---

**`regular-expression-dos-infinite-timeout`** | WARNING | `community-rules\csharp\lang\security\regular-expression-dos\regular-expression-dos-infinite-timeout.yaml`
> Specifying the regex timeout leaves the system vulnerable to a regex-based Denial of Service (DoS) attack. Consider setting the timeout to a short amount of time like 2 or 3 seconds. If you are sure you need an infinite timeout, double check that your context meets the conditions outlined in the "Notes to Callers" section at the bottom of this page: https://docs.microsoft.com/en-us/dotnet/api/system.text.regularexpressions.regex.-ctor?view=net-6.0

---

**`ssrf`** | ERROR | `community-rules\csharp\lang\security\ssrf\http-client.yaml`
> SSRF is an attack vector that abuses an application to interact with the internal/external network or the machine itself.

---

**`ssrf`** | ERROR | `community-rules\csharp\lang\security\ssrf\rest-client.yaml`
> SSRF is an attack vector that abuses an application to interact with the internal/external network or the machine itself.

---

**`ssrf`** | ERROR | `community-rules\csharp\lang\security\ssrf\web-client.yaml`
> SSRF is an attack vector that abuses an application to interact with the internal/external network or the machine itself.

---

**`ssrf`** | ERROR | `community-rules\csharp\lang\security\ssrf\web-request.yaml`
> The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination. Many different options exist to fix this issue depending the use case (Application can send request only to identified and trusted applications, Application can send requests to ANY external IP address or domain name).

---

**`stacktrace-disclosure`** | WARNING | `community-rules\csharp\lang\security\stacktrace-disclosure.yaml`
> Stacktrace information is displayed in a non-Development environment. Accidentally disclosing sensitive stack trace information in a production environment aids an attacker in reconnaissance and information gathering.

---

**`structured-logging`** | INFO | `community-rules\csharp\lang\best-practice\structured-logging.yaml`
> String interpolation in log message obscures the distinction between variables and the log message. Use structured logging instead, where the variables are passed as additional arguments and the interpolation is performed by the logging library. This reduces the possibility of log injection and makes it easier to search through logs.

---

**`unsafe-path-combine`** | WARNING | `community-rules\csharp\lang\security\filesystem\unsafe-path-combine.yaml`
> String argument $A is used to read or write data from a file via Path.Combine without direct sanitization via Path.GetFileName. If the path is user-supplied data this can lead to path traversal.

---

**`unsigned-security-token`** | ERROR | `community-rules\csharp\lang\security\cryptography\unsigned-security-token.yaml`
> Accepting unsigned security tokens as valid security tokens allows an attacker to remove its signature and potentially forge an identity. As a fix, set RequireSignedTokens to be true.

---

**`use_deprecated_cipher_algorithm`** | ERROR | `community-rules\csharp\dotnet\security\use_deprecated_cipher_algorithm.yaml`
> Usage of deprecated cipher algorithm detected. Use Aes or ChaCha20Poly1305 instead.

---

**`use_ecb_mode`** | WARNING | `community-rules\csharp\dotnet\security\use_ecb_mode.yaml`
> Usage of the insecure ECB mode detected. You should use an authenticated encryption mode instead, which is implemented by the classes AesGcm or ChaCha20Poly1305.

---

**`use_weak_rng_for_keygeneration`** | ERROR | `community-rules\csharp\dotnet\security\use_weak_rng_for_keygeneration.yaml`
> You are using an insecure random number generator (RNG) to create a cryptographic key. System.Random must never be used for cryptographic purposes. Use System.Security.Cryptography.RandomNumberGenerator instead.

---

**`use_weak_rsa_encryption_padding`** | WARNING | `community-rules\csharp\dotnet\security\use_weak_rsa_encryption_padding.yaml`
> You are using the outdated PKCS#1 v1.5 encryption padding for your RSA key. Use the OAEP padding instead.

---

**`web-config-insecure-cookie-settings`** | WARNING | `community-rules\csharp\dotnet\security\web-config-insecure-cookie-settings.yaml`
> Cookie Secure flag is explicitly disabled. You should enforce this value to avoid accidentally presenting sensitive cookie values over plaintext HTTP connections.

---

**`xmldocument-unsafe-parser-override`** | WARNING | `community-rules\csharp\lang\security\xxe\xmldocument-unsafe-parser-override.yaml`
> XmlReaderSettings found with DtdProcessing.Parse on an XmlReader handling a string argument from a public method. Enabling Document Type Definition (DTD) parsing may cause XML External Entity (XXE) injection if supplied with user-controllable data.

---

**`xmlreadersettings-unsafe-parser-override`** | WARNING | `community-rules\csharp\lang\security\xxe\xmlreadersettings-unsafe-parser-override.yaml`
> XmlReaderSettings found with DtdProcessing.Parse on an XmlReader handling a string argument from a public method. Enabling Document Type Definition (DTD) parsing may cause XML External Entity (XXE) injection if supplied with user-controllable data.

---

**`xmltextreader-unsafe-defaults`** | WARNING | `community-rules\csharp\lang\security\xxe\xmltextreader-unsafe-defaults.yaml`
> XmlReaderSettings found with DtdProcessing.Parse on an XmlReader handling a string argument from a public method. Enabling Document Type Definition (DTD) parsing may cause XML External Entity (XXE) injection if supplied with user-controllable data.

---

**`xpath-injection`** | ERROR | `community-rules\csharp\dotnet\security\audit\xpath-injection.yaml`
> XPath queries are constructed dynamically on user-controlled input. This vulnerability in code could lead to an XPath Injection exploitation.

---

## Custom (1 rules)

**`--language-eval-usage`** | WARNING | `rules\--language-rules.yml`
> Avoid using eval() due to potential security risks and performance issues. Consider using safer alternatives, such as ast.literal_eval() for simple expressions or a parsing library for complex expressions.

---

## Dockerfile (37 rules)

**`avoid-apk-upgrade`** | INFO | `community-rules\dockerfile\best-practice\avoid-apk-upgrade.yaml`
> Packages in base images should be up-to-date, removing the need for 'apk upgrade'. If packages are out-of-date, consider contacting the base image maintainer.

---

**`avoid-apt-get-upgrade`** | WARNING | `community-rules\dockerfile\best-practice\avoid-apt-get-upgrade.yaml`
> Packages in base containers should be up-to-date, removing the need to upgrade or dist-upgrade. If a package is out of date, contact the maintainers.

---

**`avoid-dnf-update`** | INFO | `community-rules\dockerfile\best-practice\avoid-dnf-update.yaml`
> Packages in base images should be up-to-date, removing the need for 'dnf update'. If packages are out-of-date, consider contacting the base image maintainer.

---

**`avoid-latest-version`** | WARNING | `community-rules\dockerfile\best-practice\avoid-latest-version.yaml`
> Images should be tagged with an explicit version to produce deterministic container images. The 'latest' tag may change the base container without warning.

---

**`avoid-platform-with-from`** | INFO | `community-rules\dockerfile\best-practice\avoid-platform-with-from.yaml`
> Using '--platform' with FROM restricts the image to build on a single platform. Further, this must be the same as the build platform. If you intended to specify the target platform, use the utility 'docker buildx --platform=' instead.

---

**`avoid-yum-update`** | INFO | `community-rules\dockerfile\best-practice\avoid-yum-update.yaml`
> Packages in base images should be up-to-date, removing the need for 'yum update'. If packages are out-of-date, consider contacting the base image maintainer.

---

**`avoid-zypper-update`** | INFO | `community-rules\dockerfile\best-practice\avoid-zypper-update.yaml`
> Packages in base images should be up-to-date, removing the need for 'zypper update'. If packages are out-of-date, consider contacting the base image maintainer.

---

**`dockerfile-dockerd-socket-mount`** | ERROR | `community-rules\dockerfile\security\dockerd-socket-mount.yaml`
> The Dockerfile(image) mounts docker.sock to the container which may allow an attacker already inside of the container to escape container and execute arbitrary commands on the host machine.

---

**`dockerfile-pip-extra-index-url`** | INFO | `community-rules\dockerfile\audit\dockerfile-pip-extra-index-url.yaml`
> When `--extra-index-url` is used in a `pip install` command, this is usually meant to  install a package from a package index other than the public one.  However, if a package is added with the same name to the public PyPi repository, and if the version number is high enough, this package will be installed when building this docker image. This package may be a malicious dependency. Such an attack is called a dependency confusion attack. If using a private package index, prefer to use `--index-url` if possible. 

---

**`dockerfile-source-not-pinned`** | INFO | `community-rules\dockerfile\audit\dockerfile-source-not-pinned.yaml`
> To ensure reproducible builds, pin Dockerfile `FROM` commands to a specific hash. You can find the hash by running `docker pull $IMAGE` and then  specify it with `$IMAGE:$VERSION@sha256:<hash goes here>`

---

**`invalid-port`** | ERROR | `community-rules\dockerfile\correctness\invalid-port.yaml`
> Detected an invalid port number. Valid ports are 0 through 65535.

---

**`last-user-is-root`** | ERROR | `community-rules\dockerfile\security\last-user-is-root.yaml`
> The last user in the container is 'root'. This is a security hazard because if an attacker gains control of the container they will have root access. Switch back to another user after running commands as 'root'.

---

**`maintainer-is-deprecated`** | INFO | `community-rules\dockerfile\best-practice\maintainer-is-deprecated.yaml`
> MAINTAINER has been deprecated.

---

**`missing-apk-no-cache`** | INFO | `community-rules\dockerfile\best-practice\missing-apk-no-cache.yaml`
> This apk command is missing '--no-cache'. This forces apk to use a package index instead of a local package cache, removing the need for '--update' and the deletion of '/var/cache/apk/*'. Add '--no-cache' to your apk command.

---

**`missing-assume-yes-switch`** | WARNING | `community-rules\dockerfile\correctness\missing-assume-yes-switch.yaml`
> This 'apt-get install' is missing the '-y' switch. This might stall builds because it requires human intervention. Add the '-y' switch.

---

**`missing-dnf-assume-yes-switch`** | WARNING | `community-rules\dockerfile\best-practice\missing-dnf-assume-yes-switch.yaml`
> This 'dnf install' is missing the '-y' switch. This might stall builds because it requires human intervention. Add the '-y' switch.

---

**`missing-dnf-clean-all`** | WARNING | `community-rules\dockerfile\best-practice\missing-dnf-clean-all.yaml`
> This dnf command does not end with '&& dnf clean all'. Running 'dnf clean all' will remove cached data and reduce package size. (This must be performed in the same RUN step.)

---

**`missing-image-version`** | WARNING | `community-rules\dockerfile\best-practice\missing-image-version.yaml`
> Detected docker image with no explicit version attached. Images should be tagged with an explicit version to produce deterministic container images -- attach a version when using  `FROM <image>`.

---

**`missing-no-install-recommends`** | INFO | `community-rules\dockerfile\best-practice\missing-no-install-recommends.yaml`
> This 'apt-get install' is missing '--no-install-recommends'. This prevents unnecessary packages from being installed, thereby reducing image size. Add '--no-install-recommends'.

---

**`missing-pip-no-cache-dir`** | INFO | `community-rules\dockerfile\best-practice\missing-pip-no-cache-dir.yaml`
> This '$PIP install' is missing '--no-cache-dir'. This flag prevents package archives from being kept around, thereby reducing image size. Add '--no-cache-dir'.

---

**`missing-user`** | ERROR | `community-rules\dockerfile\security\missing-user.yaml`
> By not specifying a USER, a program in the container may run as 'root'. This is a security hazard. If an attacker can control a process running as root, they may have control over the container. Ensure that the last USER in a Dockerfile is a USER other than 'root'.

---

**`missing-user-entrypoint`** | ERROR | `community-rules\dockerfile\security\missing-user-entrypoint.yaml`
> By not specifying a USER, a program in the container may run as 'root'. This is a security hazard. If an attacker can control a process running as root, they may have control over the container. Ensure that the last USER in a Dockerfile is a USER other than 'root'.

---

**`missing-yum-assume-yes-switch`** | WARNING | `community-rules\dockerfile\best-practice\missing-yum-assume-yes-switch.yaml`
> This 'yum install' is missing the '-y' switch. This might stall builds because it requires human intervention. Add the '-y' switch.

---

**`missing-zypper-clean`** | WARNING | `community-rules\dockerfile\best-practice\missing-zypper-clean.yaml`
> This zypper command does not end with '&& zypper clean'. Running 'zypper clean' will remove cached data and reduce package size. (This must be performed in the same RUN step.)

---

**`multiple-entrypoint-instructions`** | ERROR | `community-rules\dockerfile\correctness\multiple-entrypoint-instructions.yaml`
> Multiple ENTRYPOINT instructions were found. Only the last one will take effect.

---

**`no-sudo-in-dockerfile`** | WARNING | `community-rules\dockerfile\security\no-sudo-in-dockerfile.yaml`
> Avoid using sudo in Dockerfiles. Running processes as a non-root user can help  reduce the potential impact of configuration errors and security vulnerabilities.

---

**`nonsensical-command`** | WARNING | `community-rules\dockerfile\best-practice\nonsensical-command.yaml`
> Some commands such as `$CMD` do not make sense in a container. Do not use these.

---

**`prefer-apt-get`** | INFO | `community-rules\dockerfile\best-practice\prefer-apt-get.yaml`
> 'apt-get' is preferred as an unattended tool for stability. 'apt' is discouraged.

---

**`prefer-copy-over-add`** | INFO | `community-rules\dockerfile\best-practice\prefer-copy-over-add.yaml`
> The ADD command will accept and include files from a URL and automatically extract archives. This potentially exposes the container to a man-in-the-middle attack or other attacks if a malicious actor can tamper with the source archive. Since ADD can have this and other unexpected side effects, the use of the more explicit COPY command is preferred.

---

**`prefer-json-notation`** | INFO | `community-rules\dockerfile\best-practice\prefer-json-notation.yaml`
> Prefer JSON notation when using CMD or ENTRYPOINT. This allows signals to be passed from the OS.

---

**`remove-package-cache`** | WARNING | `community-rules\dockerfile\best-practice\remove-package-cache.yaml`
> The package cache was not deleted after running 'apt-get update', which increases the size of the image. Remove the package cache by appending '&& apt-get clean' at the end of apt-get command chain.

---

**`remove-package-lists`** | WARNING | `community-rules\dockerfile\best-practice\remove-package-lists.yaml`
> The package lists were not deleted after running 'apt-get update', which increases the size of the image. Remove the package lists by appending '&& rm -rf /var/lib/apt/lists/*' at the end of apt-get command chain.

---

**`secret-in-build-arg`** | WARNING | `community-rules\dockerfile\security\secret-in-build-arg.yaml`
> Docker build time arguments are not suited for secrets, because the argument values are saved with the image. Running `docker image history` on the image will show information on how the image was built, including arguments. If these contain plain text secrets, anyone with access to the docker image can access those secrets and exploit them.

---

**`set-pipefail`** | WARNING | `community-rules\dockerfile\best-practice\set-pipefail.yaml`
> Only the exit code from the final command in this RUN instruction will be evaluated unless 'pipefail' is set. If you want to fail the command at any stage in the pipe, set 'pipefail' by including 'SHELL ["/bin/bash", "-o", "pipefail", "-c"] before the command. If you're using alpine and don't have bash installed, communicate this explicitly with `SHELL ["/bin/ash"]`.

---

**`use-either-wget-or-curl`** | INFO | `community-rules\dockerfile\best-practice\use-either-wget-or-curl.yaml`
> 'wget' and 'curl' are similar tools. Choose one and do not install the other to decrease image size.

---

**`use-shell-instruction`** | WARNING | `community-rules\dockerfile\best-practice\use-shell-instruction.yaml`
> Use the SHELL instruction to set the default shell instead of overwriting '/bin/sh'.

---

**`use-workdir`** | WARNING | `community-rules\dockerfile\best-practice\use-workdir.yaml`
> As recommended by Docker's documentation, it is best to use 'WORKDIR' instead of 'RUN cd ...' for improved clarity and reliability. Also, 'RUN cd ...' may not work as expected in a container.

---

## Elixir (7 rules)

**`atom_exhaustion`** | ERROR | `community-rules\elixir\lang\correctness\atom-exhaustion.yaml`
> Atom values are appended to a global table but never removed. If input is user-controlled, dynamic instantiations such as `String.to_atom` or `List.to_atom` can lead to possible memory leaks. Instead, use `String.to_existing_atom` or `List.to_existing_atom`.

---

**`deprecated_bnot_operator`** | WARNING | `community-rules\elixir\lang\best-practice\deprecated-bnot-operator.yaml`
> The bitwise operator (`^^^`) is already deprecated. Please use `Bitwise.bnot($VAL)` instead.

---

**`deprecated_bxor_operator`** | WARNING | `community-rules\elixir\lang\best-practice\deprecated-bxor-operator.yaml`
> The bitwise operator (`^^^`) is already deprecated. Please use `Bitwise.bxor($LEFT, $RIGHT)` instead.

---

**`deprecated_calendar_iso_day_of_week_3`** | WARNING | `community-rules\elixir\lang\best-practice\deprecated-calendar-iso-day-of-week-3.yaml`
> `Calendar.ISO.day_of_week/3` is already deprecated. Please use `Calendar.ISO.day_of_week/4` instead.

---

**`deprecated_use_bitwise`** | WARNING | `community-rules\elixir\lang\best-practice\deprecated-use-bitwise.yaml`
> The syntax `use Bitwise` is already deprecated. Please use `import Bitwise` instead.

---

**`enum_map_into`** | WARNING | `community-rules\elixir\lang\best-practice\enum-map-into.yaml`
> Using `Enum.into/3` is more efficient than using `Enum.map/2 |> Enum.into/2`.

---

**`enum_map_join`** | WARNING | `community-rules\elixir\lang\best-practice\enum-map-join.yaml`
> Using `Enum.map_join/3` is more efficient than using `Enum.map/2 |> Enum.join/2`.

---

## Generic (267 rules)

**`adafruit-api-key`** | INFO | `community-rules\generic\secrets\gitleaks\adafruit-api-key.yaml`
> A gitleaks adafruit-api-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`adobe-client-id`** | INFO | `community-rules\generic\secrets\gitleaks\adobe-client-id.yaml`
> A gitleaks adobe-client-id was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`adobe-client-secret`** | INFO | `community-rules\generic\secrets\gitleaks\adobe-client-secret.yaml`
> A gitleaks adobe-client-secret was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`age-secret-key`** | INFO | `community-rules\generic\secrets\gitleaks\age-secret-key.yaml`
> A gitleaks age-secret-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`airtable-api-key`** | INFO | `community-rules\generic\secrets\gitleaks\airtable-api-key.yaml`
> A gitleaks airtable-api-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`algolia-api-key`** | INFO | `community-rules\generic\secrets\gitleaks\algolia-api-key.yaml`
> A gitleaks algolia-api-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`alias-must-be-unique`** | ERROR | `community-rules\generic\dockerfile\correctness\alias-must-be-unique.yaml`
> Image aliases must have a unique name, and '$REF' is used twice. Use another name for '$REF'.

---

**`alias-path-traversal`** | WARNING | `community-rules\generic\nginx\security\alias-path-traversal.yaml`
> The alias in this location block is subject to a path traversal because the location path does not end in a path separator (e.g., '/'). To fix, add a path separator to the end of the path.

---

**`alibaba-access-key-id`** | INFO | `community-rules\generic\secrets\gitleaks\alibaba-access-key-id.yaml`
> A gitleaks alibaba-access-key-id was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`alibaba-secret-key`** | INFO | `community-rules\generic\secrets\gitleaks\alibaba-secret-key.yaml`
> A gitleaks alibaba-secret-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`asana-client-id`** | INFO | `community-rules\generic\secrets\gitleaks\asana-client-id.yaml`
> A gitleaks asana-client-id was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`asana-client-secret`** | INFO | `community-rules\generic\secrets\gitleaks\asana-client-secret.yaml`
> A gitleaks asana-client-secret was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`atlassian-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\atlassian-api-token.yaml`
> A gitleaks atlassian-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`authress-service-client-access-key`** | INFO | `community-rules\generic\secrets\gitleaks\authress-service-client-access-key.yaml`
> A gitleaks authress-service-client-access-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`aws-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\aws-access-token.yaml`
> A gitleaks aws-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`bash_reverse_shell`** | ERROR | `community-rules\generic\ci\security\bash-reverse-shell.yaml`
> Semgrep found a bash reverse shell

---

**`beamer-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\beamer-api-token.yaml`
> A gitleaks beamer-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`bitbucket-client-id`** | INFO | `community-rules\generic\secrets\gitleaks\bitbucket-client-id.yaml`
> A gitleaks bitbucket-client-id was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`bitbucket-client-secret`** | INFO | `community-rules\generic\secrets\gitleaks\bitbucket-client-secret.yaml`
> A gitleaks bitbucket-client-secret was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`bittrex-access-key`** | INFO | `community-rules\generic\secrets\gitleaks\bittrex-access-key.yaml`
> A gitleaks bittrex-access-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`bittrex-secret-key`** | INFO | `community-rules\generic\secrets\gitleaks\bittrex-secret-key.yaml`
> A gitleaks bittrex-secret-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`build-gradle-password-hardcoded`** | WARNING | `community-rules\generic\gradle\security\build-gradle-password-hardcoded.yaml`
> A secret is hard-coded in the application. Secrets stored in source code, such as credentials, identifiers, and other types of sensitive data, can be leaked and used by internal or external malicious actors. It is recommended to rotate the secret and retrieve them from a secure secret vault or Hardware Security Module (HSM), alternatively environment variables can be used if allowed by your company policy.

---

**`changed-semgrepignore`** | WARNING | `community-rules\generic\ci\audit\changed-semgrepignore.yaml`
> `$1` has been added to the .semgrepignore list of ignored paths. Someone from app-sec may want to audit these changes.

---

**`clojars-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\clojars-api-token.yaml`
> A gitleaks clojars-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`cloudflare-api-key`** | INFO | `community-rules\generic\secrets\gitleaks\cloudflare-api-key.yaml`
> A gitleaks cloudflare-api-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`cloudflare-global-api-key`** | INFO | `community-rules\generic\secrets\gitleaks\cloudflare-global-api-key.yaml`
> A gitleaks cloudflare-global-api-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`cloudflare-origin-ca-key`** | INFO | `community-rules\generic\secrets\gitleaks\cloudflare-origin-ca-key.yaml`
> A gitleaks cloudflare-origin-ca-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`codecov-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\codecov-access-token.yaml`
> A gitleaks codecov-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`coinbase-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\coinbase-access-token.yaml`
> A gitleaks coinbase-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`confluent-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\confluent-access-token.yaml`
> A gitleaks confluent-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`confluent-secret-key`** | INFO | `community-rules\generic\secrets\gitleaks\confluent-secret-key.yaml`
> A gitleaks confluent-secret-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`contains-bidirectional-characters`** | WARNING | `community-rules\generic\unicode\security\bidi.yml`
> This code contains bidirectional (bidi) characters. While this is useful for support of right-to-left languages such as Arabic or Hebrew, it can also be used to trick language parsers into executing code in a manner that is different from how it is displayed in code editing and review tools. If this is not what you were expecting, please review this code in an editor that can reveal hidden Unicode characters.

---

**`contentful-delivery-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\contentful-delivery-api-token.yaml`
> A gitleaks contentful-delivery-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`copy-from-own-alias`** | ERROR | `community-rules\generic\dockerfile\correctness\copy-from-own-alias.yaml`
> COPY instructions cannot copy from its own alias. The '$REF' alias is used before switching to a new image. If you meant to switch to a new image, include a new 'FROM' statement. Otherwise, remove the '--from=$REF' from the COPY statement.

---

**`csp-header-attribute`** | INFO | `community-rules\generic\visualforce\security\ncino\xml\CSPHeaderAttribute.yaml`
> Visualforce Pages must have the cspHeader attribute set to true. This attribute is available in API version 55 or higher.

---

**`dangerous-eval`** | ERROR | `rules\common-rules.yml`
> Avoid using eval(). It can execute arbitrary code and is a security risk

---

**`databricks-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\databricks-api-token.yaml`
> A gitleaks databricks-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`datadog-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\datadog-access-token.yaml`
> A gitleaks datadog-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`defined-networking-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\defined-networking-api-token.yaml`
> A gitleaks defined-networking-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`detected-amazon-mws-auth-token`** | ERROR | `community-rules\generic\secrets\security\detected-amazon-mws-auth-token.yaml`
> Amazon MWS Auth Token detected

---

**`detected-artifactory-password`** | ERROR | `community-rules\generic\secrets\security\detected-artifactory-password.yaml`
> Artifactory token detected

---

**`detected-artifactory-token`** | ERROR | `community-rules\generic\secrets\security\detected-artifactory-token.yaml`
> Artifactory token detected

---

**`detected-aws-access-key-id-value`** | ERROR | `community-rules\generic\secrets\security\detected-aws-access-key-id-value.yaml`
> AWS Access Key ID Value detected. This is a sensitive credential and should not be hardcoded here. Instead, read this value from an environment variable or keep it in a separate, private file.

---

**`detected-aws-account-id`** | INFO | `community-rules\generic\secrets\security\detected-aws-account-id.yaml`
> AWS Account ID detected. While not considered sensitive information, it is important to use them and share them carefully. For that reason it would be preferrable avoiding to hardcoded it here. Instead, read the value from an environment variable or keep the value in a separate, private file.

---

**`detected-aws-appsync-graphql-key`** | ERROR | `community-rules\generic\secrets\security\detected-aws-appsync-graphql-key.yaml`
> AWS AppSync GraphQL Key detected

---

**`detected-aws-secret-access-key`** | ERROR | `community-rules\generic\secrets\security\detected-aws-secret-access-key.yaml`
> AWS Secret Access Key detected

---

**`detected-aws-session-token`** | ERROR | `community-rules\generic\secrets\security\detected-aws-session-token.yaml`
> AWS Session Token detected

---

**`detected-bcrypt-hash`** | ERROR | `community-rules\generic\secrets\security\detected-bcrypt-hash.yaml`
> bcrypt hash detected

---

**`detected-codeclimate`** | ERROR | `community-rules\generic\secrets\security\detected-codeclimate.yaml`
> CodeClimate detected

---

**`detected-etc-shadow`** | ERROR | `community-rules\generic\secrets\security\detected-etc-shadow.yaml`
> linux shadow file detected

---

**`detected-facebook-access-token`** | ERROR | `community-rules\generic\secrets\security\detected-facebook-access-token.yaml`
> Facebook Access Token detected

---

**`detected-facebook-oauth`** | ERROR | `community-rules\generic\secrets\security\detected-facebook-oauth.yaml`
> Facebook OAuth detected

---

**`detected-generic-api-key`** | ERROR | `community-rules\generic\secrets\security\detected-generic-api-key.yaml`
> Generic API Key detected

---

**`detected-generic-secret`** | ERROR | `community-rules\generic\secrets\security\detected-generic-secret.yaml`
> Generic Secret detected

---

**`detected-github-token`** | ERROR | `community-rules\generic\secrets\security\detected-github-token.yaml`
> GitHub Token detected

---

**`detected-google-api-key`** | ERROR | `community-rules\generic\secrets\security\detected-google-api-key.yaml`
> Google API Key Detected

---

**`detected-google-cloud-api-key`** | ERROR | `community-rules\generic\secrets\security\detected-google-cloud-api-key.yaml`
> Google Cloud API Key detected

---

**`detected-google-gcm-service-account`** | ERROR | `community-rules\generic\secrets\security\detected-google-gcm-service-account.yaml`
> Google (GCM) Service account detected

---

**`detected-google-oauth-access-token`** | ERROR | `community-rules\generic\secrets\security\detected-google-oauth-access-token.yaml`
> Google OAuth Access Token detected

---

**`detected-google-oauth-url`** | ERROR | `community-rules\generic\secrets\security\detected-google-oauth.yaml`
> Google OAuth url detected

---

**`detected-heroku-api-key`** | ERROR | `community-rules\generic\secrets\security\detected-heroku-api-key.yaml`
> Heroku API Key detected

---

**`detected-hockeyapp`** | ERROR | `community-rules\generic\secrets\security\detected-hockeyapp.yaml`
> HockeyApp detected

---

**`detected-jwt-token`** | ERROR | `community-rules\generic\secrets\security\detected-jwt-token.yaml`
> JWT token detected

---

**`detected-kolide-api-key`** | ERROR | `community-rules\generic\secrets\security\detected-kolide-api-key.yaml`
> Kolide API Key detected

---

**`detected-mailchimp-api-key`** | ERROR | `community-rules\generic\secrets\security\detected-mailchimp-api-key.yaml`
> MailChimp API Key detected

---

**`detected-mailgun-api-key`** | ERROR | `community-rules\generic\secrets\security\detected-mailgun-api-key.yaml`
> Mailgun API Key detected

---

**`detected-npm-registry-auth-token`** | ERROR | `community-rules\generic\secrets\security\detected-npm-registry-auth-token.yaml`
> NPM registry authentication token detected

---

**`detected-onfido-live-api-token`** | ERROR | `community-rules\generic\secrets\security\detected-onfido-live-api-token.yaml`
> Onfido live API Token detected

---

**`detected-outlook-team`** | ERROR | `community-rules\generic\secrets\security\detected-outlook-team.yaml`
> Outlook Team detected

---

**`detected-paypal-braintree-access-token`** | ERROR | `community-rules\generic\secrets\security\detected-paypal-braintree-access-token.yaml`
> PayPal Braintree Access Token detected

---

**`detected-pgp-private-key-block`** | ERROR | `community-rules\generic\secrets\security\detected-pgp-private-key-block.yaml`
> Something that looks like a PGP private key block is detected. This is a potential hardcoded secret that could be leaked if this code is committed. Instead, remove this code block from the commit.

---

**`detected-picatic-api-key`** | ERROR | `community-rules\generic\secrets\security\detected-picatic-api-key.yaml`
> Picatic API Key detected

---

**`detected-private-key`** | ERROR | `community-rules\generic\secrets\security\detected-private-key.yaml`
> Private Key detected. This is a sensitive credential and should not be hardcoded here. Instead, store this in a separate, private file.

---

**`detected-sauce-token`** | ERROR | `community-rules\generic\secrets\security\detected-sauce-token.yaml`
> Sauce Token detected

---

**`detected-sendgrid-api-key`** | ERROR | `community-rules\generic\secrets\security\detected-sendgrid-api-key.yaml`
> SendGrid API Key detected

---

**`detected-slack-token`** | ERROR | `community-rules\generic\secrets\security\detected-slack-token.yaml`
> Slack Token detected

---

**`detected-slack-webhook`** | ERROR | `community-rules\generic\secrets\security\detected-slack-webhook.yaml`
> Slack Webhook detected

---

**`detected-snyk-api-key`** | ERROR | `community-rules\generic\secrets\security\detected-snyk-api-key.yaml`
> Snyk API Key detected

---

**`detected-softlayer-api-key`** | ERROR | `community-rules\generic\secrets\security\detected-softlayer-api-key.yaml`
> SoftLayer API Key detected

---

**`detected-sonarqube-docs-api-key`** | ERROR | `community-rules\generic\secrets\security\detected-sonarqube-docs-api-key.yaml`
> SonarQube Docs API Key detected

---

**`detected-square-access-token`** | ERROR | `community-rules\generic\secrets\security\detected-square-access-token.yaml`
> Square Access Token detected

---

**`detected-square-oauth-secret`** | ERROR | `community-rules\generic\secrets\security\detected-square-oauth-secret.yaml`
> Square OAuth Secret detected

---

**`detected-ssh-password`** | ERROR | `community-rules\generic\secrets\security\detected-ssh-password.yaml`
> SSH Password detected

---

**`detected-stripe-api-key`** | ERROR | `community-rules\generic\secrets\security\detected-stripe-api-key.yaml`
> Stripe API Key detected

---

**`detected-stripe-restricted-api-key`** | ERROR | `community-rules\generic\secrets\security\detected-stripe-restricted-api-key.yaml`
> Stripe Restricted API Key detected

---

**`detected-telegram-bot-api-key`** | ERROR | `community-rules\generic\secrets\security\detected-telegram-bot-api-key.yaml`
> Telegram Bot API Key detected

---

**`detected-twilio-api-key`** | ERROR | `community-rules\generic\secrets\security\detected-twilio-api-key.yaml`
> Twilio API Key detected

---

**`detected-username-and-password-in-uri`** | ERROR | `community-rules\generic\secrets\security\detected-username-and-password-in-uri.yaml`
> Username and password in URI detected

---

**`digitalocean-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\digitalocean-access-token.yaml`
> A gitleaks digitalocean-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`digitalocean-pat`** | INFO | `community-rules\generic\secrets\gitleaks\digitalocean-pat.yaml`
> A gitleaks digitalocean-pat was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`digitalocean-refresh-token`** | INFO | `community-rules\generic\secrets\gitleaks\digitalocean-refresh-token.yaml`
> A gitleaks digitalocean-refresh-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`discord-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\discord-api-token.yaml`
> A gitleaks discord-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`discord-client-id`** | INFO | `community-rules\generic\secrets\gitleaks\discord-client-id.yaml`
> A gitleaks discord-client-id was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`discord-client-secret`** | INFO | `community-rules\generic\secrets\gitleaks\discord-client-secret.yaml`
> A gitleaks discord-client-secret was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`dom-xss-innerhtml`** | ERROR | `rules\common-rules.yml`
> Setting innerHTML with user input can cause XSS. Use textContent or sanitize input

---

**`doppler-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\doppler-api-token.yaml`
> A gitleaks doppler-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`droneci-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\droneci-access-token.yaml`
> A gitleaks droneci-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`dropbox-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\dropbox-api-token.yaml`
> A gitleaks dropbox-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`dropbox-long-lived-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\dropbox-long-lived-api-token.yaml`
> A gitleaks dropbox-long-lived-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`dropbox-short-lived-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\dropbox-short-lived-api-token.yaml`
> A gitleaks dropbox-short-lived-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`duffel-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\duffel-api-token.yaml`
> A gitleaks duffel-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`duplicate-if-conditions`** | INFO | `rules\common-rules.yml`
> Duplicate code detected. Follow DRY principle

---

**`dynamic-proxy-host`** | WARNING | `community-rules\generic\nginx\security\dynamic-proxy-host.yaml`
> The host for this proxy URL is dynamically determined. This can be dangerous if the host can be injected by an attacker because it may forcibly alter destination of the proxy. Consider hardcoding acceptable destinations and retrieving them with 'map' or something similar.

---

**`dynamic-proxy-scheme`** | WARNING | `community-rules\generic\nginx\security\dynamic-proxy-scheme.yaml`
> The protocol scheme for this proxy is dynamically determined. This can be dangerous if the scheme can be injected by an attacker because it may forcibly alter the connection scheme. Consider hardcoding a scheme for this proxy.

---

**`dynatrace-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\dynatrace-api-token.yaml`
> A gitleaks dynatrace-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`easypost-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\easypost-api-token.yaml`
> A gitleaks easypost-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`easypost-test-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\easypost-test-api-token.yaml`
> A gitleaks easypost-test-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`etsy-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\etsy-access-token.yaml`
> A gitleaks etsy-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`facebook`** | INFO | `community-rules\generic\secrets\gitleaks\facebook.yaml`
> A gitleaks facebook was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`facebook-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\facebook-access-token.yaml`
> A gitleaks facebook-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`facebook-page-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\facebook-page-access-token.yaml`
> A gitleaks facebook-page-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`facebook-secret`** | INFO | `community-rules\generic\secrets\gitleaks\facebook-secret.yaml`
> A gitleaks facebook-secret was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`fastly-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\fastly-api-token.yaml`
> A gitleaks fastly-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`finicity-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\finicity-api-token.yaml`
> A gitleaks finicity-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`finicity-client-secret`** | INFO | `community-rules\generic\secrets\gitleaks\finicity-client-secret.yaml`
> A gitleaks finicity-client-secret was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`finnhub-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\finnhub-access-token.yaml`
> A gitleaks finnhub-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`flickr-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\flickr-access-token.yaml`
> A gitleaks flickr-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`flutterwave-encryption-key`** | INFO | `community-rules\generic\secrets\gitleaks\flutterwave-encryption-key.yaml`
> A gitleaks flutterwave-encryption-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`flutterwave-public-key`** | INFO | `community-rules\generic\secrets\gitleaks\flutterwave-public-key.yaml`
> A gitleaks flutterwave-public-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`flutterwave-secret-key`** | INFO | `community-rules\generic\secrets\gitleaks\flutterwave-secret-key.yaml`
> A gitleaks flutterwave-secret-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`frameio-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\frameio-api-token.yaml`
> A gitleaks frameio-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`freshbooks-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\freshbooks-access-token.yaml`
> A gitleaks freshbooks-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`gcp-api-key`** | INFO | `community-rules\generic\secrets\gitleaks\gcp-api-key.yaml`
> A gitleaks gcp-api-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`generic-api-key`** | INFO | `community-rules\generic\secrets\gitleaks\generic-api-key.yaml`
> A gitleaks generic-api-key was detected which attempts to identify hard-coded credentials.  It is not recommended to store credentials in source-code, as this risks secrets being leaked  and used by either an internal or external malicious adversary. It is recommended to use  environment variables to securely provide credentials or retrieve credentials from a  secure vault or HSM (Hardware Security Module). This rule can introduce a lot of false positives,  it is not recommended to be used in PR comments.

---

**`github-app-token`** | INFO | `community-rules\generic\secrets\gitleaks\github-app-token.yaml`
> A gitleaks github-app-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`github-fine-grained-pat`** | INFO | `community-rules\generic\secrets\gitleaks\github-fine-grained-pat.yaml`
> A gitleaks github-fine-grained-pat was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`github-oauth`** | INFO | `community-rules\generic\secrets\gitleaks\github-oauth.yaml`
> A gitleaks github-oauth was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`github-pat`** | INFO | `community-rules\generic\secrets\gitleaks\github-pat.yaml`
> A gitleaks github-pat was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`github-refresh-token`** | INFO | `community-rules\generic\secrets\gitleaks\github-refresh-token.yaml`
> A gitleaks github-refresh-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`gitlab-pat`** | INFO | `community-rules\generic\secrets\gitleaks\gitlab-pat.yaml`
> A gitleaks gitlab-pat was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`gitlab-ptt`** | INFO | `community-rules\generic\secrets\gitleaks\gitlab-ptt.yaml`
> A gitleaks gitlab-ptt was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`gitlab-rrt`** | INFO | `community-rules\generic\secrets\gitleaks\gitlab-rrt.yaml`
> A gitleaks gitlab-rrt was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`gitter-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\gitter-access-token.yaml`
> A gitleaks gitter-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`gocardless-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\gocardless-api-token.yaml`
> A gitleaks gocardless-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`google-maps-apikeyleak`** | WARNING | `community-rules\generic\secrets\security\google-maps-apikeyleak.yaml`
> Detects potential Google Maps API keys in code

---

**`grafana-api-key`** | INFO | `community-rules\generic\secrets\gitleaks\grafana-api-key.yaml`
> A gitleaks grafana-api-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`grafana-cloud-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\grafana-cloud-api-token.yaml`
> A gitleaks grafana-cloud-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`grafana-service-account-token`** | INFO | `community-rules\generic\secrets\gitleaks\grafana-service-account-token.yaml`
> A gitleaks grafana-service-account-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`hardcoded-token`** | ERROR | `rules\common-rules.yml`
> Hardcoded secret token detected (Stripe/GitHub/Slack). Use environment variables or secret management

---

**`harness-api-key`** | INFO | `community-rules\generic\secrets\gitleaks\harness-api-key.yaml`
> A gitleaks harness-api-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`hashicorp-tf-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\hashicorp-tf-api-token.yaml`
> A gitleaks hashicorp-tf-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`hashicorp-tf-password`** | INFO | `community-rules\generic\secrets\gitleaks\hashicorp-tf-password.yaml`
> A gitleaks hashicorp-tf-password was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`header-injection`** | ERROR | `community-rules\generic\nginx\security\header-injection.yaml`
> The $$VARIABLE path parameter is added as a header in the response. This could allow an attacker to inject a newline and add a new header into the response. This is called HTTP response splitting. To fix, do not allow whitespace in the path parameter: '[^\s]+'.

---

**`header-redefinition`** | WARNING | `community-rules\generic\nginx\security\header-redefinition.yaml`
> The 'add_header' directive is called in a 'location' block after headers have been set at the server block. Calling 'add_header' in the location block will actually overwrite the headers defined in the server block, no matter which headers are set. To fix this, explicitly set all headers or set all headers in the server block.

---

**`heroku-api-key`** | INFO | `community-rules\generic\secrets\gitleaks\heroku-api-key.yaml`
> A gitleaks heroku-api-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`hubspot-api-key`** | INFO | `community-rules\generic\secrets\gitleaks\hubspot-api-key.yaml`
> A gitleaks hubspot-api-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`huggingface-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\huggingface-access-token.yaml`
> A gitleaks huggingface-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`huggingface-organization-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\huggingface-organization-api-token.yaml`
> A gitleaks huggingface-organization-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`infracost-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\infracost-api-token.yaml`
> A gitleaks infracost-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`insecure-random`** | WARNING | `rules\common-rules.yml`
> Math.random() is not cryptographically secure. Use crypto.randomBytes()

---

**`insecure-redirect`** | WARNING | `community-rules\generic\nginx\security\insecure-redirect.yaml`
> Detected an insecure redirect in this nginx configuration. If no scheme is specified, nginx will forward the request with the incoming scheme. This could result in unencrypted communications. To fix this, include the 'https' scheme.

---

**`insecure-ssl-version`** | WARNING | `community-rules\generic\nginx\security\insecure-ssl-version.yaml`
> Detected use of an insecure SSL version. Secure SSL versions are TLSv1.2 and TLS1.3; older versions are known to be broken and are susceptible to attacks. Prefer use of TLSv1.2 or later.

---

**`intercom-api-key`** | INFO | `community-rules\generic\secrets\gitleaks\intercom-api-key.yaml`
> A gitleaks intercom-api-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`intra42-client-secret`** | INFO | `community-rules\generic\secrets\gitleaks\intra42-client-secret.yaml`
> A gitleaks intra42-client-secret was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`invalid-base-url`** | WARNING | `community-rules\generic\hugo\best-practice\invalid-base-url.yaml`
> The 'baseURL' is invalid. This may cause links to not work if deployed. Include the scheme (e.g., http:// or https://).

---

**`jfrog-api-key`** | INFO | `community-rules\generic\secrets\gitleaks\jfrog-api-key.yaml`
> A gitleaks jfrog-api-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`jfrog-identity-token`** | INFO | `community-rules\generic\secrets\gitleaks\jfrog-identity-token.yaml`
> A gitleaks jfrog-identity-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`jwt`** | INFO | `community-rules\generic\secrets\gitleaks\jwt.yaml`
> A gitleaks jwt was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`jwt-base64`** | INFO | `community-rules\generic\secrets\gitleaks\jwt-base64.yaml`
> A gitleaks jwt-base64 was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`kraken-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\kraken-access-token.yaml`
> A gitleaks kraken-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`kucoin-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\kucoin-access-token.yaml`
> A gitleaks kucoin-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`kucoin-secret-key`** | INFO | `community-rules\generic\secrets\gitleaks\kucoin-secret-key.yaml`
> A gitleaks kucoin-secret-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`launchdarkly-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\launchdarkly-access-token.yaml`
> A gitleaks launchdarkly-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`linear-api-key`** | INFO | `community-rules\generic\secrets\gitleaks\linear-api-key.yaml`
> A gitleaks linear-api-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`linear-client-secret`** | INFO | `community-rules\generic\secrets\gitleaks\linear-client-secret.yaml`
> A gitleaks linear-client-secret was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`linkedin-client-id`** | INFO | `community-rules\generic\secrets\gitleaks\linkedin-client-id.yaml`
> A gitleaks linkedin-client-id was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`linkedin-client-secret`** | INFO | `community-rules\generic\secrets\gitleaks\linkedin-client-secret.yaml`
> A gitleaks linkedin-client-secret was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`lob-api-key`** | INFO | `community-rules\generic\secrets\gitleaks\lob-api-key.yaml`
> A gitleaks lob-api-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`lob-pub-api-key`** | INFO | `community-rules\generic\secrets\gitleaks\lob-pub-api-key.yaml`
> A gitleaks lob-pub-api-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`localhost-base-url`** | WARNING | `community-rules\generic\hugo\best-practice\localhost-base-url.yaml`
> The 'baseURL' is set to localhost. This may cause links to not work if deployed.

---

**`mailchimp-api-key`** | INFO | `community-rules\generic\secrets\gitleaks\mailchimp-api-key.yaml`
> A gitleaks mailchimp-api-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`mailgun-private-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\mailgun-private-api-token.yaml`
> A gitleaks mailgun-private-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`mailgun-pub-key`** | INFO | `community-rules\generic\secrets\gitleaks\mailgun-pub-key.yaml`
> A gitleaks mailgun-pub-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`mailgun-signing-key`** | INFO | `community-rules\generic\secrets\gitleaks\mailgun-signing-key.yaml`
> A gitleaks mailgun-signing-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`mapbox-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\mapbox-api-token.yaml`
> A gitleaks mapbox-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`mattermost-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\mattermost-access-token.yaml`
> A gitleaks mattermost-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`messagebird-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\messagebird-api-token.yaml`
> A gitleaks messagebird-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`messagebird-client-id`** | INFO | `community-rules\generic\secrets\gitleaks\messagebird-client-id.yaml`
> A gitleaks messagebird-client-id was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`microsoft-teams-webhook`** | INFO | `community-rules\generic\secrets\gitleaks\microsoft-teams-webhook.yaml`
> A gitleaks microsoft-teams-webhook was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`missing-input-validation`** | WARNING | `rules\common-rules.yml`
> Missing input validation. Validate parameters before using them

---

**`missing-internal`** | WARNING | `community-rules\generic\nginx\security\missing-internal.yaml`
> This location block contains a 'proxy_pass' directive but does not contain the 'internal' directive. The 'internal' directive restricts access to this location to internal requests. Without 'internal', an attacker could use your server for server-side request forgeries (SSRF). Include the 'internal' directive in this block to limit exposure.

---

**`missing-ssl-version`** | WARNING | `community-rules\generic\nginx\security\missing-ssl-version.yaml`
> This server configuration is missing the 'ssl_protocols' directive. By default, this server will use 'ssl_protocols TLSv1 TLSv1.1 TLSv1.2', and versions older than TLSv1.2 are known to be broken. Explicitly specify 'ssl_protocols TLSv1.2 TLSv1.3' to use secure TLS versions.

---

**`missing-yum-clean-all`** | WARNING | `community-rules\generic\dockerfile\best-practice\missing-yum-clean-all.yaml`
> This yum command does not end with '&& yum clean all'. Running 'yum clean all' will remove cached data and reduce package size. (This must be performed in the same RUN step.)

---

**`missing-zypper-no-confirm-switch`** | WARNING | `community-rules\generic\dockerfile\missing-zypper-no-confirm-switch.yaml`
> This 'zypper install' is missing the '-y' switch. This might stall builds because it requires human intervention. Add the '-y' switch.

---

**`multiple-cmd-instructions`** | ERROR | `community-rules\generic\dockerfile\correctness\multiple-cmd-instructions.yaml`
> Multiple CMD instructions were found. Only the last one will take effect.

---

**`netlify-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\netlify-access-token.yaml`
> A gitleaks netlify-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`new-relic-browser-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\new-relic-browser-api-token.yaml`
> A gitleaks new-relic-browser-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`new-relic-insert-key`** | INFO | `community-rules\generic\secrets\gitleaks\new-relic-insert-key.yaml`
> A gitleaks new-relic-insert-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`new-relic-user-api-id`** | INFO | `community-rules\generic\secrets\gitleaks\new-relic-user-api-id.yaml`
> A gitleaks new-relic-user-api-id was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`new-relic-user-api-key`** | INFO | `community-rules\generic\secrets\gitleaks\new-relic-user-api-key.yaml`
> A gitleaks new-relic-user-api-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`npm-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\npm-access-token.yaml`
> A gitleaks npm-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`nytimes-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\nytimes-access-token.yaml`
> A gitleaks nytimes-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`okta-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\okta-access-token.yaml`
> A gitleaks okta-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`openai-api-key`** | INFO | `community-rules\generic\secrets\gitleaks\openai-api-key.yaml`
> A gitleaks openai-api-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`plaid-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\plaid-api-token.yaml`
> A gitleaks plaid-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`plaid-client-id`** | INFO | `community-rules\generic\secrets\gitleaks\plaid-client-id.yaml`
> A gitleaks plaid-client-id was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`plaid-secret-key`** | INFO | `community-rules\generic\secrets\gitleaks\plaid-secret-key.yaml`
> A gitleaks plaid-secret-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`planetscale-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\planetscale-api-token.yaml`
> A gitleaks planetscale-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`planetscale-oauth-token`** | INFO | `community-rules\generic\secrets\gitleaks\planetscale-oauth-token.yaml`
> A gitleaks planetscale-oauth-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`planetscale-password`** | INFO | `community-rules\generic\secrets\gitleaks\planetscale-password.yaml`
> A gitleaks planetscale-password was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`possible-nginx-h2c-smuggling`** | WARNING | `community-rules\generic\nginx\security\possible-h2c-smuggling.yaml`
> Conditions for Nginx H2C smuggling identified. H2C smuggling allows upgrading HTTP/1.1 connections to lesser-known HTTP/2 over cleartext (h2c) connections which can allow a bypass of reverse proxy access controls, and lead to long-lived, unrestricted HTTP traffic directly to back-end servers. To mitigate: WebSocket support required: Allow only the value websocket for HTTP/1.1 upgrade headers (e.g., Upgrade: websocket). WebSocket support not required: Do not forward Upgrade headers.

---

**`postman-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\postman-api-token.yaml`
> A gitleaks postman-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`prefect-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\prefect-api-token.yaml`
> A gitleaks prefect-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`private-key`** | INFO | `community-rules\generic\secrets\gitleaks\private-key.yaml`
> A gitleaks private-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`prototype-pollution`** | ERROR | `rules\common-rules.yml`
> Prototype pollution vulnerability detected

---

**`pulumi-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\pulumi-api-token.yaml`
> A gitleaks pulumi-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`pypi-upload-token`** | INFO | `community-rules\generic\secrets\gitleaks\pypi-upload-token.yaml`
> A gitleaks pypi-upload-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`rapidapi-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\rapidapi-access-token.yaml`
> A gitleaks rapidapi-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`readme-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\readme-api-token.yaml`
> A gitleaks readme-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`request-host-used`** | WARNING | `community-rules\generic\nginx\security\request-host-used.yaml`
> '$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation.

---

**`rubygems-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\rubygems-api-token.yaml`
> A gitleaks rubygems-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`scalingo-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\scalingo-api-token.yaml`
> A gitleaks scalingo-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`secure-parameter-for-secrets`** | WARNING | `community-rules\generic\bicep\security\secure-parameter-for-secrets.yaml`
> Mark sensitive parameters with the @secure() decorator. This avoids logging the value or displaying it in the Azure portal, Azure CLI, or Azure PowerShell.

---

**`sendbird-access-id`** | INFO | `community-rules\generic\secrets\gitleaks\sendbird-access-id.yaml`
> A gitleaks sendbird-access-id was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`sendbird-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\sendbird-access-token.yaml`
> A gitleaks sendbird-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`sendgrid-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\sendgrid-api-token.yaml`
> A gitleaks sendgrid-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`sendinblue-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\sendinblue-api-token.yaml`
> A gitleaks sendinblue-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`sentry-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\sentry-access-token.yaml`
> A gitleaks sentry-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`shippo-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\shippo-api-token.yaml`
> A gitleaks shippo-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`shopify-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\shopify-access-token.yaml`
> A gitleaks shopify-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`shopify-custom-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\shopify-custom-access-token.yaml`
> A gitleaks shopify-custom-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`shopify-private-app-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\shopify-private-app-access-token.yaml`
> A gitleaks shopify-private-app-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`shopify-shared-secret`** | INFO | `community-rules\generic\secrets\gitleaks\shopify-shared-secret.yaml`
> A gitleaks shopify-shared-secret was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`sidekiq-secret`** | INFO | `community-rules\generic\secrets\gitleaks\sidekiq-secret.yaml`
> A gitleaks sidekiq-secret was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`sidekiq-sensitive-url`** | INFO | `community-rules\generic\secrets\gitleaks\sidekiq-sensitive-url.yaml`
> A gitleaks sidekiq-sensitive-url was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`slack-app-token`** | INFO | `community-rules\generic\secrets\gitleaks\slack-app-token.yaml`
> A gitleaks slack-app-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`slack-bot-token`** | INFO | `community-rules\generic\secrets\gitleaks\slack-bot-token.yaml`
> A gitleaks slack-bot-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`slack-config-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\slack-config-access-token.yaml`
> A gitleaks slack-config-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`slack-config-refresh-token`** | INFO | `community-rules\generic\secrets\gitleaks\slack-config-refresh-token.yaml`
> A gitleaks slack-config-refresh-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`slack-legacy-bot-token`** | INFO | `community-rules\generic\secrets\gitleaks\slack-legacy-bot-token.yaml`
> A gitleaks slack-legacy-bot-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`slack-legacy-token`** | INFO | `community-rules\generic\secrets\gitleaks\slack-legacy-token.yaml`
> A gitleaks slack-legacy-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`slack-legacy-workspace-token`** | INFO | `community-rules\generic\secrets\gitleaks\slack-legacy-workspace-token.yaml`
> A gitleaks slack-legacy-workspace-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`slack-user-token`** | INFO | `community-rules\generic\secrets\gitleaks\slack-user-token.yaml`
> A gitleaks slack-user-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`slack-webhook-url`** | INFO | `community-rules\generic\secrets\gitleaks\slack-webhook-url.yaml`
> A gitleaks slack-webhook-url was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`snyk-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\snyk-api-token.yaml`
> A gitleaks snyk-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`sql-injection-risk`** | ERROR | `rules\common-rules.yml`
> Potential SQL injection vulnerability. Use parameterized queries

---

**`square-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\square-access-token.yaml`
> A gitleaks square-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`squarespace-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\squarespace-access-token.yaml`
> A gitleaks squarespace-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`stripe-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\stripe-access-token.yaml`
> A gitleaks stripe-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`sumologic-access-id`** | INFO | `community-rules\generic\secrets\gitleaks\sumologic-access-id.yaml`
> A gitleaks sumologic-access-id was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`sumologic-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\sumologic-access-token.yaml`
> A gitleaks sumologic-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`telegram-bot-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\telegram-bot-api-token.yaml`
> A gitleaks telegram-bot-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`travisci-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\travisci-access-token.yaml`
> A gitleaks travisci-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`twilio-api-key`** | INFO | `community-rules\generic\secrets\gitleaks\twilio-api-key.yaml`
> A gitleaks twilio-api-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`twitch-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\twitch-api-token.yaml`
> A gitleaks twitch-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`twitter-access-secret`** | INFO | `community-rules\generic\secrets\gitleaks\twitter-access-secret.yaml`
> A gitleaks twitter-access-secret was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`twitter-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\twitter-access-token.yaml`
> A gitleaks twitter-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`twitter-api-key`** | INFO | `community-rules\generic\secrets\gitleaks\twitter-api-key.yaml`
> A gitleaks twitter-api-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`twitter-api-secret`** | INFO | `community-rules\generic\secrets\gitleaks\twitter-api-secret.yaml`
> A gitleaks twitter-api-secret was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`twitter-bearer-token`** | INFO | `community-rules\generic\secrets\gitleaks\twitter-bearer-token.yaml`
> A gitleaks twitter-bearer-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`typeform-api-token`** | INFO | `community-rules\generic\secrets\gitleaks\typeform-api-token.yaml`
> A gitleaks typeform-api-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`unquoted-attribute-var`** | WARNING | `community-rules\generic\html-templates\security\unquoted-attribute-var.yaml`
> Detected a unquoted template variable as an attribute. If unquoted, a malicious actor could inject custom JavaScript handlers. To fix this, add quotes around the template expression, like this: "{{ expr }}".

---

**`unvalidated-redirect`** | ERROR | `rules\common-rules.yml`
> Unvalidated redirect can lead to phishing attacks. Validate URL first

---

**`use-SRI-for-CDNs`** | WARNING | `community-rules\generic\visualforce\security\ncino\html\UseSRIForCDNs.yaml`
> Consuming CDNs without including a SubResource Integrity (SRI) can expose your application and its users to compromised code. SRIs allow you to consume specific versions of content where if even a single byte is compromised, the resource will not be loaded. Add an integrity attribute to your <script> and <link> tags pointing to CDN content to ensure the resources have not been compromised. A crossorigin attribute should also be added. For a more thorough explanation along with explicit instructions on remediating, follow the directions from Mozilla here: https://developer.mozilla.org/en-US/blog/securing-cdn-using-sri-why-how/

---

**`use-absolute-workdir`** | WARNING | `community-rules\generic\dockerfile\best-practice\use-absolute-workdir.yaml`
> Detected a relative WORKDIR. Use absolute paths. This prevents issues based on assumptions about the WORKDIR of previous containers.

---

**`var-in-href`** | WARNING | `community-rules\generic\html-templates\security\var-in-href.yaml`
> Detected a template variable used in an anchor tag with the 'href' attribute. This allows a malicious actor to input the 'javascript:' URI and is subject to cross- site scripting (XSS) attacks. If using Flask, use 'url_for()' to safely generate a URL. If using Django, use the 'url' filter to safely generate a URL. If using Mustache, use a URL encoding library, or prepend a slash '/' to the variable for relative links (`href="/{{link}}"`). You may also consider setting the Content Security Policy (CSP) header.

---

**`var-in-script-src`** | WARNING | `community-rules\generic\html-templates\security\var-in-script-src.yaml`
> Detected a template variable used as the 'src' in a script tag. Although template variables are HTML escaped, HTML escaping does not always prevent malicious URLs from being injected and could results in a cross-site scripting (XSS) vulnerability. Prefer not to dynamically generate the 'src' attribute and use static URLs instead. If you must do this, carefully check URLs against an allowlist and be sure to URL-encode the result.

---

**`var-in-script-tag`** | WARNING | `community-rules\generic\html-templates\security\var-in-script-tag.yaml`
> Detected a template variable used in a script tag. Although template variables are HTML escaped, HTML escaping does not always prevent cross-site scripting (XSS) attacks when used directly in JavaScript. If you need this data on the rendered page, consider placing it in the HTML portion (outside of a script tag). Alternatively, use a JavaScript-specific encoder, such as the one available in OWASP ESAPI. For Django, you may also consider using the 'json_script' template tag and retrieving the data in your script by using the element ID (e.g., `document.getElementById`).

---

**`vault-batch-token`** | INFO | `community-rules\generic\secrets\gitleaks\vault-batch-token.yaml`
> A gitleaks vault-batch-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`vault-service-token`** | INFO | `community-rules\generic\secrets\gitleaks\vault-service-token.yaml`
> A gitleaks vault-service-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`visualforce-page-api-version`** | WARNING | `community-rules\generic\visualforce\security\ncino\xml\VisualForceAPIVersion.yaml`
> Visualforce Pages must use API version 55 or higher for required use of the cspHeader attribute set to true.

---

**`weak-crypto-md5`** | ERROR | `rules\common-rules.yml`
> MD5 is cryptographically broken. Use SHA-256 or stronger

---

**`xss-from-unescaped-url-param`** | ERROR | `community-rules\generic\visualforce\security\ncino\vf\XSSFromUnescapedURLParam.yaml`
> To remediate this issue, ensure that all URL parameters are properly escaped before including them in scripts. Please update your code to use either the JSENCODE method to escape URL parameters or the escape="true" attribute on <apex:outputText> tags. Passing URL parameters directly into scripts and DOM sinks creates an opportunity for Cross-Site Scripting attacks. Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted websites. To remediate this issue, ensure that all URL parameters are properly escaped before including them in scripts.

---

**`yandex-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\yandex-access-token.yaml`
> A gitleaks yandex-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`yandex-api-key`** | INFO | `community-rules\generic\secrets\gitleaks\yandex-api-key.yaml`
> A gitleaks yandex-api-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`yandex-aws-access-token`** | INFO | `community-rules\generic\secrets\gitleaks\yandex-aws-access-token.yaml`
> A gitleaks yandex-aws-access-token was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`zendesk-secret-key`** | INFO | `community-rules\generic\secrets\gitleaks\zendesk-secret-key.yaml`
> A gitleaks zendesk-secret-key was detected which attempts to identify hard-coded credentials. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

## Go (101 rules)

**`avoid-bind-to-all-interfaces`** | WARNING | `community-rules\go\lang\security\audit\net\bind_all.yaml`
> Detected a network listener listening on 0.0.0.0 or an empty string. This could unexpectedly expose the server publicly as it binds to all available interfaces. Instead, specify another IP address that is not 0.0.0.0 nor the empty string.

---

**`avoid-ssh-insecure-ignore-host-key`** | WARNING | `community-rules\go\lang\security\audit\crypto\insecure_ssh.yaml`
> Disabled host key verification detected. This allows man-in-the-middle attacks. Use the 'golang.org/x/crypto/ssh/knownhosts' package to do host key verification. See https://skarlso.github.io/2019/02/17/go-ssh-with-host-key-verification/ to learn more about the problem and how to fix it.

---

**`bad-tmp-file-creation`** | WARNING | `community-rules\go\lang\security\bad_tmp.yaml`
> File creation in shared tmp directory without using `io.CreateTemp`.

---

**`channel-guarded-with-mutex`** | WARNING | `community-rules\go\lang\best-practice\channel-guarded-with-mutex.yaml`
> Detected a channel guarded with a mutex. Channels already have an internal mutex, so this is unnecessary. Remove the mutex. See https://hackmongo.com/page/golang-antipatterns/#guarded-channel for more information.

---

**`cookie-missing-httponly`** | WARNING | `community-rules\go\lang\security\audit\net\cookie-missing-httponly.yaml`
> A session cookie was detected without setting the 'HttpOnly' flag. The 'HttpOnly' flag for cookies instructs the browser to forbid client-side scripts from reading the cookie which mitigates XSS attacks. Set the 'HttpOnly' flag by setting 'HttpOnly' to 'true' in the Cookie.

---

**`cookie-missing-secure`** | WARNING | `community-rules\go\lang\security\audit\net\cookie-missing-secure.yaml`
> A session cookie was detected without setting the 'Secure' flag. The 'secure' flag for cookies prevents the client from transmitting the cookie over insecure channels such as HTTP. Set the 'Secure' flag by setting 'Secure' to 'true' in the Options struct.

---

**`dangerous-command-write`** | ERROR | `community-rules\go\lang\security\audit\dangerous-command-write.yaml`
> Detected non-static command inside Write. Audit the input to '$CW.Write'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code.

---

**`dangerous-exec-cmd`** | ERROR | `community-rules\go\lang\security\audit\dangerous-exec-cmd.yaml`
> Detected non-static command inside exec.Cmd. Audit the input to 'exec.Cmd'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code.

---

**`dangerous-exec-command`** | ERROR | `community-rules\go\lang\security\audit\dangerous-exec-command.yaml`
> Detected non-static command inside Command. Audit the input to 'exec.Command'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code.

---

**`dangerous-execution`** | ERROR | `community-rules\go\otto\security\audit\dangerous-execution.yaml`
> Detected non-static script inside otto VM. Audit the input to 'VM.Run'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code.

---

**`dangerous-syscall-exec`** | ERROR | `community-rules\go\lang\security\audit\dangerous-syscall-exec.yaml`
> Detected non-static command inside Exec. Audit the input to 'syscall.Exec'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code.

---

**`database-sqli`** | WARNING | `community-rules\go\aws-lambda\security\database-sqli.yaml`
> Detected SQL statement that is tainted by `$EVENT` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries or prepared statements instead. You can use prepared statements with the 'Prepare' and 'PrepareContext' calls.

---

**`dynamic-httptrace-clienttrace`** | WARNING | `community-rules\go\lang\security\audit\net\dynamic-httptrace-clienttrace.yaml`
> Detected a potentially dynamic ClientTrace. This occurred because semgrep could not find a static definition for '$TRACE'. Dynamic ClientTraces are dangerous because they deserialize function code to run when certain Request events occur, which could lead to code being run without your knowledge. Ensure that your ClientTrace is statically defined.

---

**`eqeq-is-bad`** | INFO | `community-rules\go\lang\correctness\useless-eqeq.yaml`
> Detected useless comparison operation `$X == $X` or `$X != $X`. This will always return 'True' or 'False' and therefore is not necessary. Instead, remove this comparison operation or use another comparison expression that is not deterministic.

---

**`exported_loop_pointer`** | WARNING | `community-rules\go\lang\correctness\looppointer.yaml`
> `$VALUE` is a loop pointer that may be exported from the loop. This pointer is shared between loop iterations, so the exported reference will always point to the last loop value, which is likely unintentional. To fix, copy the pointer to a new pointer within the loop.

---

**`filepath-clean-misuse`** | ERROR | `community-rules\go\lang\security\filepath-clean-misuse.yaml`
> `Clean` is not intended to sanitize against path traversal attacks. This function is for finding the shortest path name equivalent to the given input. Using `Clean` to sanitize file reads may expose this application to path traversal attacks, where an attacker could access arbitrary files on the server. To fix this easily, write this: `filepath.FromSlash(path.Clean("/"+strings.Trim(req.URL.Path, "/")))` However, a better solution is using the `SecureJoin` function in the package `filepath-securejoin`. See https://pkg.go.dev/github.com/cyphar/filepath-securejoin#section-readme.

---

**`formatted-template-string`** | WARNING | `community-rules\go\lang\security\audit\net\formatted-template-string.yaml`
> Found a formatted template string passed to 'template.HTML()'. 'template.HTML()' does not escape contents. Be absolutely sure there is no user-controlled data in this template. If user data can reach this template, you may have a XSS vulnerability.

---

**`fs-directory-listing`** | WARNING | `community-rules\go\lang\security\audit\net\fs-directory-listing.yaml`
> Detected usage of 'http.FileServer' as handler: this allows directory listing and an attacker could navigate through directories looking for sensitive files. Be sure to disable directory listing or restrict access to specific directories/files.

---

**`go-insecure-templates`** | WARNING | `community-rules\go\template\security\insecure-types.yaml`
> usage of insecure template types. They are documented as a security risk. See https://golang.org/pkg/html/template/#HTML.

---

**`go-rule-1-unhandled-error`** | WARNING | `rules\go-rules.yml`
> Rule 1: Always handle errors immediately. Check if err != nil after assignment

---

**`go-rule-10-goroutine-leak`** | WARNING | `rules\go-rules.yml`
> Rule 10: Ensure goroutines can exit. Use context or done channels

---

**`go-rule-12-empty-interface`** | WARNING | `rules\go-rules.yml`
> Rule 12: Avoid empty interface (interface{}). Use specific types or generics

---

**`go-rule-13-unclosed-channel`** | INFO | `rules\go-rules.yml`
> Rule 13: Ensure channels are properly closed to avoid goroutine leaks

---

**`go-rule-14-time-after-leak`** | ERROR | `rules\go-rules.yml`
> Rule 14: Avoid time.After in loops. Use time.NewTicker instead

---

**`go-rule-15-weak-random`** | WARNING | `rules\go-rules.yml`
> Rule 15: Use crypto/rand for security-sensitive random numbers, not math/rand

---

**`go-rule-18-long-function`** | INFO | `rules\go-rules.yml`
> Rule 18: Keep functions small and focused. Break down large functions

---

**`go-rule-19-sql-injection`** | ERROR | `rules\go-rules.yml`
> Rule 19: Avoid SQL string concatenation. Use parameterized queries

---

**`go-rule-20-no-fmt-println`** | WARNING | `rules\go-rules.yml`
> Go Rule 20: Avoid fmt.Println in production. Use proper logging (log package or structured logger)

---

**`go-rule-21-exported-naming-pascalcase`** | INFO | `rules\go-rules.yml`
> Go Rule 21: Exported types should use PascalCase (e.g., UserService, not userService)

---

**`go-rule-22-function-naming`** | INFO | `rules\go-rules.yml`
> Go Rule 22: Use PascalCase for exported functions, camelCase for unexported (e.g., CalculateTotal or calculateTotal)

---

**`go-rule-23-variable-naming-camelcase`** | INFO | `rules\go-rules.yml`
> Go Rule 23: Variable names should use camelCase (e.g., userName, not user_name or UserName for local vars)

---

**`go-rule-24-constant-naming`** | INFO | `rules\go-rules.yml`
> Go Rule 24: Use PascalCase for exported constants, camelCase for unexported (e.g., MaxRetries or maxRetries)

---

**`go-rule-25-package-naming-lowercase`** | INFO | `rules\go-rules.yml`
> Go Rule 25: Package names should be lowercase, single word (e.g., package http, not package HTTP or httpUtils)

---

**`go-rule-3-avoid-panic`** | WARNING | `rules\go-rules.yml`
> Rule 3: Avoid using panic in application code. Return errors instead

---

**`go-rule-6-global-var`** | INFO | `rules\go-rules.yml`
> Rule 6: Avoid global variables. Use dependency injection or structs

---

**`go-rule-8-defer-in-loop`** | ERROR | `rules\go-rules.yml`
> Rule 8: Do not use defer inside loops. Move defer outside or use a function

---

**`go-ssti`** | ERROR | `community-rules\go\template\security\ssti.yaml`
> A server-side template injection occurs when an attacker is able to use native template syntax to inject a malicious payload into a template, which is then executed server-side. When using "html/template" always check that user inputs are validated and sanitized before included within the template.

---

**`go-unsafe-deserialization-interface`** | WARNING | `community-rules\go\lang\security\deserialization\unsafe-deserialization-interface.yaml`
> Deserializing into `interface{}` allows arbitrary data structures and types, which can lead to security vulnerabilities (CWE-502). Use a concrete struct type instead. Consider using github.com/ravisastryk/go-safeinput/safedeserialize for automatic protection.

---

**`gorm-dangerous-method-usage`** | WARNING | `community-rules\go\gorm\security\audit\gorm-dangerous-methods-usage.yaml`
> Detected usage of dangerous method $METHOD which does not escape inputs (see link in references). If the argument is user-controlled, this can lead to SQL injection. When using $METHOD function, do not trust user-submitted data and only allow approved list of input (possibly, use an allowlist approach).

---

**`gosql-sqli`** | ERROR | `community-rules\go\lang\security\audit\sqli\gosql-sqli.yaml`
> Detected string concatenation with a non-literal variable in a "database/sql" Go SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries or prepared statements instead. You can use prepared statements with the 'Prepare' and 'PrepareContext' calls.

---

**`grpc-client-insecure-connection`** | ERROR | `community-rules\go\grpc\security\grpc-client-insecure-connection.yaml`
> Found an insecure gRPC connection using 'grpc.WithInsecure()'. This creates a connection without encryption to a gRPC server. A malicious attacker could tamper with the gRPC message, which could compromise the machine. Instead, establish a secure connection with an SSL certificate using the 'grpc.WithTransportCredentials()' function. You can create a create credentials using a 'tls.Config{}' struct with 'credentials.NewTLS()'. The final fix looks like this: 'grpc.WithTransportCredentials(credentials.NewTLS(<config>))'.

---

**`grpc-server-insecure-connection`** | ERROR | `community-rules\go\grpc\security\grpc-server-insecure-connection.yaml`
> Found an insecure gRPC server without 'grpc.Creds()' or options with credentials. This allows for a connection without encryption to this server. A malicious attacker could tamper with the gRPC message, which could compromise the machine. Include credentials derived from an SSL certificate in order to create a secure gRPC connection. You can create credentials using 'credentials.NewServerTLSFromFile("cert.pem", "cert.key")'.

---

**`handler-assignment-from-multiple-sources`** | WARNING | `community-rules\go\gorilla\security\audit\handler-assignment-from-multiple-sources.yaml`
> Variable $VAR is assigned from two different sources: '$Y' and '$R'. Make sure this is intended, as this could cause logic bugs if they are treated as they are the same object.

---

**`hardcoded-eq-true-or-false`** | INFO | `community-rules\go\lang\correctness\useless-eqeq.yaml`
> Detected useless if statement. 'if (True)' and 'if (False)' always result in the same behavior, and therefore is not necessary in the code. Remove the 'if (False)' expression completely or just the 'if (True)' comparison depending on which expression is in the code.

---

**`hardcoded-jwt-key`** | WARNING | `community-rules\go\jwt-go\security\jwt.yaml`
> A hard-coded credential was detected. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`hidden-goroutine`** | WARNING | `community-rules\go\lang\best-practice\hidden-goroutine.yaml`
> Detected a hidden goroutine. Function invocations are expected to synchronous, and this function will execute asynchronously because all it does is call a goroutine. Instead, remove the internal goroutine and call the function using 'go'.

---

**`import-text-template`** | WARNING | `community-rules\go\lang\security\audit\xss\import-text-template.yaml`
> When working with web applications that involve rendering user-generated  content, it's important to properly escape any HTML content to prevent  Cross-Site Scripting (XSS) attacks. In Go, the `text/template` package does  not automatically escape HTML content, which can leave your application  vulnerable to these types of attacks. To mitigate this risk, it's  recommended to use the `html/template` package instead, which provides  built-in functionality for HTML escaping. By using `html/template` to render  your HTML content, you can help to ensure that your web application is more  secure and less susceptible to XSS vulnerabilities.

---

**`incorrect-default-permission`** | WARNING | `community-rules\go\lang\correctness\permissions\file_permission.yaml`
> Detected file permissions that are set to more than `0600` (user/owner can read and write). Setting file permissions to higher than `0600` is most likely unnecessary and violates the principle of least privilege. Instead, set permissions to be `0600` or less for os.Chmod, os.Mkdir, os.OpenFile, os.MkdirAll, and ioutil.WriteFile

---

**`insecure-module-used`** | WARNING | `community-rules\go\lang\security\audit\crypto\bad_imports.yaml`
> The package `net/http/cgi` is on the import blocklist.  The package is vulnerable to httpoxy attacks (CVE-2015-5386). It is recommended to use `net/http` or a web framework to build a web application instead.

---

**`integer-overflow-int16`** | WARNING | `community-rules\go\lang\correctness\overflow\overflow.yaml`
> Detected conversion of the result of a strconv.Atoi command to an int16. This could lead to an integer overflow, which could possibly result in unexpected behavior and even privilege escalation. Instead, use `strconv.ParseInt`.

---

**`integer-overflow-int32`** | WARNING | `community-rules\go\lang\correctness\overflow\overflow.yaml`
> Detected conversion of the result of a strconv.Atoi command to an int32. This could lead to an integer overflow, which could possibly result in unexpected behavior and even privilege escalation. Instead, use `strconv.ParseInt`.

---

**`jwt-go-none-algorithm`** | ERROR | `community-rules\go\jwt-go\security\jwt-none-alg.yaml`
> Detected use of the 'none' algorithm in a JWT token. The 'none' algorithm assumes the integrity of the token has already been verified. This would allow a malicious actor to forge a JWT token that will automatically be verified. Do not explicitly use the 'none' algorithm. Instead, use an algorithm such as 'HS256'.

---

**`jwt-go-parse-unverified`** | WARNING | `community-rules\go\jwt-go\security\audit\jwt-parse-unverified.yaml`
> Detected the decoding of a JWT token without a verify step. Don't use `ParseUnverified` unless you know what you're doing This method parses the token but doesn't validate the signature. It's only ever useful in cases where you know the signature is valid (because it has been checked previously in the stack) and you want to extract values from it.

---

**`math-random-used`** | WARNING | `community-rules\go\lang\security\audit\crypto\math_random.yaml`
> Do not use `math/rand`. Use `crypto/rand` instead.

---

**`md5-used-as-password`** | WARNING | `community-rules\go\lang\security\audit\md5-used-as-password.yaml`
> It looks like MD5 is used as a password hash. MD5 is not considered a secure password hash because it can be cracked by an attacker in a short amount of time. Use a suitable password hashing function such as bcrypt. You can use the `golang.org/x/crypto/bcrypt` package.

---

**`missing-ssl-minversion`** | WARNING | `community-rules\go\lang\security\audit\crypto\missing-ssl-minversion.yaml`
> `MinVersion` is missing from this TLS configuration.  By default, as of Go 1.22, TLS 1.2 is currently used as the minimum. General purpose web applications should default to TLS 1.3 with all other protocols disabled.  Only where it is known that a web server must support legacy clients with unsupported an insecure browsers (such as Internet Explorer 10), it may be necessary to enable TLS 1.0 to provide support. Add `MinVersion: tls.VersionTLS13' to the TLS configuration to bump the minimum version to TLS 1.3.

---

**`no-direct-write-to-responsewriter`** | WARNING | `community-rules\go\lang\security\audit\xss\no-direct-write-to-responsewriter.yaml`
> Detected directly writing or similar in 'http.ResponseWriter.write()'. This bypasses HTML escaping that prevents cross-site scripting vulnerabilities. Instead, use the 'html/template' package and render data using 'template.Execute()'.

---

**`no-fprintf-to-responsewriter`** | WARNING | `community-rules\go\lang\security\audit\xss\no-fprintf-to-responsewriter.yaml`
> Detected 'Fprintf' or similar writing to 'http.ResponseWriter'. This bypasses HTML escaping that prevents cross-site scripting vulnerabilities. Instead, use the 'html/template' package to render data to users.

---

**`no-interpolation-in-tag`** | WARNING | `community-rules\go\lang\security\audit\xss\no-interpolation-in-tag.yaml`
> Detected template variable interpolation in an HTML tag. This is potentially vulnerable to cross-site scripting (XSS) attacks because a malicious actor has control over HTML but without the need to use escaped characters. Use explicit tags instead.

---

**`no-interpolation-js-template-string`** | WARNING | `community-rules\go\lang\security\audit\xss\no-interpolation-js-template-string.yaml`
> Detected template variable interpolation in a JavaScript template string. This is potentially vulnerable to cross-site scripting (XSS) attacks because a malicious actor has control over JavaScript but without the need to use escaped characters. Instead, obtain this variable outside of the template string and ensure your template is properly escaped.

---

**`no-io-writestring-to-responsewriter`** | WARNING | `community-rules\go\lang\security\audit\xss\no-io-writestring-to-responsewriter.yaml`
> Detected 'io.WriteString()' writing directly to 'http.ResponseWriter'. This bypasses HTML escaping that prevents cross-site scripting vulnerabilities. Instead, use the 'html/template' package to render data to users.

---

**`no-printf-in-responsewriter`** | WARNING | `community-rules\go\lang\security\audit\xss\no-printf-in-responsewriter.yaml`
> Detected 'printf' or similar in 'http.ResponseWriter.write()'. This bypasses HTML escaping that prevents cross-site scripting vulnerabilities. Instead, use the 'html/template' package to render data to users.

---

**`open-redirect`** | WARNING | `community-rules\go\lang\security\injection\open-redirect.yaml`
> An HTTP redirect was found to be crafted from user-input `$REQUEST`. This can lead to open redirect vulnerabilities, potentially allowing attackers to redirect users to malicious web sites. It is recommend where possible to not allow user-input to craft the redirect URL. When user-input is necessary to craft the request, it is recommended to follow OWASP best practices to restrict the URL to domains in an allowlist.

---

**`parsing-external-entities-enabled`** | WARNING | `community-rules\go\lang\security\audit\xxe\parsing-external-entities-enabled.yaml`
> Detected enabling of "XMLParseNoEnt", which allows parsing of external entities and can lead to XXE if user controlled data is parsed by the library. Instead, do not enable "XMLParseNoEnt" or be sure to adequately sanitize user-controlled data when it is being parsed by this library.

---

**`path-traversal-inside-zip-extraction`** | WARNING | `community-rules\go\lang\security\zip.yaml`
> File traversal when extracting zip archive

---

**`pg-orm-sqli`** | ERROR | `community-rules\go\lang\security\audit\sqli\pg-orm-sqli.yaml`
> Detected string concatenation with a non-literal variable in a go-pg ORM SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, do not use strings concatenated with user-controlled input. Instead, use parameterized statements.

---

**`pg-sqli`** | ERROR | `community-rules\go\lang\security\audit\sqli\pg-sqli.yaml`
> Detected string concatenation with a non-literal variable in a go-pg SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries instead of string concatenation. You can use parameterized queries like so: '(SELECT ? FROM table, data1)'

---

**`pgx-sqli`** | ERROR | `community-rules\go\lang\security\audit\sqli\pgx-sqli.yaml`
> Detected string concatenation with a non-literal variable in a pgx Go SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries instead. You can use parameterized queries like so: (`SELECT $1 FROM table`, `data1)

---

**`potential-dos-via-decompression-bomb`** | WARNING | `community-rules\go\lang\security\decompression_bomb.yaml`
> Detected a possible denial-of-service via a zip bomb attack. By limiting the max bytes read, you can mitigate this attack. `io.CopyN()` can specify a size. 

---

**`pprof-debug-exposure`** | WARNING | `community-rules\go\lang\security\audit\net\pprof.yaml`
> The profiling 'pprof' endpoint is automatically exposed on /debug/pprof. This could leak information about the server. Instead, use `import "net/http/pprof"`. See https://www.farsightsecurity.com/blog/txt-record/go-remote-profiling-20161028/ for more information and mitigation.

---

**`raw-html-format`** | WARNING | `community-rules\go\lang\security\injection\raw-html-format.yaml`
> Detected user input flowing into a manually constructed HTML string. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross-site scripting vulnerability, which could let attackers steal sensitive user data. Use the `html/template` package which will safely render HTML instead, or inspect that the HTML is rendered safely.

---

**`reflect-makefunc`** | ERROR | `community-rules\go\lang\security\audit\reflect-makefunc.yaml`
> 'reflect.MakeFunc' detected. This will sidestep protections that are normally afforded by Go's type system. Audit this call and be sure that user input cannot be used to affect the code generated by MakeFunc; otherwise, you will have a serious security vulnerability.

---

**`reverseproxy-director`** | WARNING | `community-rules\go\lang\security\reverseproxy-director.yaml`
> ReverseProxy can remove headers added by Director. Consider using ReverseProxy.Rewrite instead of ReverseProxy.Director.

---

**`session-cookie-missing-httponly`** | WARNING | `community-rules\go\gorilla\security\audit\session-cookie-missing-httponly.yaml`
> A session cookie was detected without setting the 'HttpOnly' flag. The 'HttpOnly' flag for cookies instructs the browser to forbid client-side scripts from reading the cookie which mitigates XSS attacks. Set the 'HttpOnly' flag by setting 'HttpOnly' to 'true' in the Options struct.

---

**`session-cookie-missing-secure`** | WARNING | `community-rules\go\gorilla\security\audit\session-cookie-missing-secure.yaml`
> A session cookie was detected without setting the 'Secure' flag. The 'secure' flag for cookies prevents the client from transmitting the cookie over insecure channels such as HTTP. Set the 'Secure' flag by setting 'Secure' to 'true' in the Options struct.

---

**`session-cookie-samesitenone`** | WARNING | `community-rules\go\gorilla\security\audit\session-cookie-samesitenone.yaml`
> Found SameSiteNoneMode setting in Gorilla session options. Consider setting SameSite to Lax, Strict or Default for enhanced security.

---

**`sha224-hash`** | WARNING | `community-rules\go\lang\security\audit\crypto\sha224-hash.yaml`
> This code uses a 224-bit hash function, which is deprecated or disallowed in some security policies. Consider updating to a stronger hash function such as SHA-384 or higher to ensure compliance and security.

---

**`shared-url-struct-mutation`** | WARNING | `community-rules\go\lang\security\shared-url-struct-mutation.yaml`
> Shared URL struct may have been accidentally mutated. Ensure that this behavior is intended.

---

**`ssl-v3-is-insecure`** | WARNING | `community-rules\go\lang\security\audit\crypto\ssl.yaml`
> SSLv3 is insecure because it has known vulnerabilities. Starting with go1.14, SSLv3 will be removed. Instead, use 'tls.VersionTLS13'.

---

**`string-formatted-query`** | WARNING | `community-rules\go\lang\security\audit\database\string-formatted-query.yaml`
> String-formatted SQL query detected. This could lead to SQL injection if the string is not sanitized properly. Audit this call to ensure the SQL is not manipulable by external data.

---

**`tainted-sql-string`** | ERROR | `community-rules\go\aws-lambda\security\tainted-sql-string.yaml`
> Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify contents of the database. Instead, use a parameterized query which is available by default in most database engines. Alternatively, consider using an object-relational mapper (ORM) such as Sequelize which will protect your queries.

---

**`tainted-sql-string`** | ERROR | `community-rules\go\lang\security\injection\tainted-sql-string.yaml`
> User data flows into this manually-constructed SQL string. User data can be safely inserted into SQL strings using prepared statements or an object-relational mapper (ORM). Manually-constructed SQL strings is a possible indicator of SQL injection, which could let an attacker steal or manipulate data from the database. Instead, use prepared statements (`db.Query("SELECT * FROM t WHERE id = ?", id)`) or a safe library.

---

**`tainted-url-host`** | WARNING | `community-rules\go\lang\security\injection\tainted-url-host.yaml`
> A request was found to be crafted from user-input `$REQUEST`. This can lead to Server-Side Request Forgery (SSRF) vulnerabilities, potentially exposing sensitive data. It is recommend where possible to not allow user-input to craft the base request, but to be treated as part of the path or query parameter. When user-input is necessary to craft the request, it is recommended to follow OWASP best practices to prevent abuse, including using an allowlist.

---

**`tls-with-insecure-cipher`** | WARNING | `community-rules\go\lang\security\audit\crypto\tls.yaml`
> Detected an insecure CipherSuite via the 'tls' module. This suite is considered weak. Use the function 'tls.CipherSuites()' to get a list of good cipher suites. See https://golang.org/pkg/crypto/tls/#InsecureCipherSuites for why and what other cipher suites to use.

---

**`unescaped-data-in-htmlattr`** | WARNING | `community-rules\go\lang\security\audit\net\unescaped-data-in-htmlattr.yaml`
> Found a formatted template string passed to 'template. HTMLAttr()'. 'template.HTMLAttr()' does not escape contents. Be absolutely sure there is no user-controlled data in this template or validate and sanitize the data before passing it into the template.

---

**`unescaped-data-in-js`** | WARNING | `community-rules\go\lang\security\audit\net\unescaped-data-in-js.yaml`
> Found a formatted template string passed to 'template.JS()'. 'template.JS()' does not escape contents. Be absolutely sure there is no user-controlled data in this template.

---

**`unescaped-data-in-url`** | WARNING | `community-rules\go\lang\security\audit\net\unescaped-data-in-url.yaml`
> Found a formatted template string passed to 'template.URL()'. 'template.URL()' does not escape contents, and this could result in XSS (cross-site scripting) and therefore confidential data being stolen. Sanitize data coming into this function or make sure that no user-controlled input is coming into the function.

---

**`unsafe-reflect-by-name`** | WARNING | `community-rules\go\lang\security\audit\unsafe-reflect-by-name.yaml`
> If an attacker can supply values that the application then uses to determine which method or field to invoke, the potential exists for the attacker to create control flow paths through the application that were not intended by the application developers. This attack vector may allow the attacker to bypass authentication or access control checks or otherwise cause the application to behave in an unexpected manner.

---

**`unsafe-template-type`** | WARNING | `community-rules\go\lang\security\audit\xss\template-html-does-not-escape.yaml`
> Semgrep could not determine that the argument to 'template.HTML()' is a constant. 'template.HTML()' and similar does not escape contents. Be absolutely sure there is no user-controlled data in this template. If user data can reach this template, you may have a XSS vulnerability. Instead, do not use this function and use 'template.Execute()'.

---

**`use-filepath-join`** | WARNING | `community-rules\go\lang\correctness\use-filepath-join.yaml`
> `path.Join(...)` always joins using a forward slash. This may cause issues on Windows or other systems using a different delimiter. Use `filepath.Join(...)` instead which uses OS-specific path separators.

---

**`use-of-DES`** | WARNING | `community-rules\go\lang\security\audit\crypto\use_of_weak_crypto.yaml`
> Detected DES cipher algorithm which is insecure. The algorithm is considered weak and has been deprecated. Use AES instead.

---

**`use-of-md5`** | WARNING | `community-rules\go\lang\security\audit\crypto\use_of_weak_crypto.yaml`
> Detected MD5 hash algorithm which is considered insecure. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.

---

**`use-of-rc4`** | WARNING | `community-rules\go\lang\security\audit\crypto\use_of_weak_crypto.yaml`
> Detected RC4 cipher algorithm which is insecure. The algorithm has many known vulnerabilities. Use AES instead.

---

**`use-of-sha1`** | WARNING | `community-rules\go\lang\security\audit\crypto\use_of_weak_crypto.yaml`
> Detected SHA1 hash algorithm which is considered insecure. SHA1 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.

---

**`use-of-unsafe-block`** | WARNING | `community-rules\go\lang\security\audit\unsafe.yaml`
> Using the unsafe package in Go gives you low-level memory management and many of the strengths of the C language, but also steps around the type safety of Go and can lead to buffer overflows and possible arbitrary code execution by an attacker. Only use this package if you absolutely know what you're doing.

---

**`use-of-weak-rsa-key`** | WARNING | `community-rules\go\lang\security\audit\crypto\use_of_weak_rsa_key.yaml`
> RSA keys should be at least 2048 bits

---

**`use-tls`** | WARNING | `community-rules\go\lang\security\audit\net\use-tls.yaml`
> Found an HTTP server without TLS. Use 'http.ListenAndServeTLS' instead. See https://golang.org/pkg/net/http/#ListenAndServeTLS for more information.

---

**`useless-if-body`** | WARNING | `community-rules\go\lang\maintainability\useless-ifelse.yaml`
> Detected identical statements in the if body and the else body of an if-statement. This will lead to the same code being executed no matter what the if-expression evaluates to. Instead, remove the if statement.

---

**`useless-if-conditional`** | WARNING | `community-rules\go\lang\maintainability\useless-ifelse.yaml`
> Detected an if block that checks for the same condition on both branches (`$X`). The second condition check is useless as it is the same as the first, and therefore can be removed from the code,

---

**`websocket-missing-origin-check`** | WARNING | `community-rules\go\gorilla\security\audit\websocket-missing-origin-check.yaml`
> The Origin header in the HTTP WebSocket handshake is used to guarantee that the connection accepted by the WebSocket is from a trusted origin domain. Failure to enforce can lead to Cross Site Request Forgery (CSRF). As per "gorilla/websocket" documentation: "A CheckOrigin function should carefully validate the request origin to prevent cross-site request forgery."

---

**`wip-xss-using-responsewriter-and-printf`** | WARNING | `community-rules\go\lang\security\audit\net\wip-xss-using-responsewriter-and-printf.yaml`
> Found data going from url query parameters into formatted data written to ResponseWriter. This could be XSS and should not be done. If you must do this, ensure your data is sanitized or escaped.

---

## Html (6 rules)

**`eval-detected`** | WARNING | `community-rules\html\security\audit\eval-detected.yaml`
> Detected the use of eval(...). This can introduce  a Cross-Site-Scripting (XSS) vulnerability if this  comes from user-provided input. Follow OWASP best  practices to ensure you handle XSS within a JavaScript context correct, and consider using safer APIs to evaluate  user-input such as JSON.parse(...). 

---

**`https-equiv`** | ERROR | `community-rules\html\correctness\https-equiv.yaml`
> The correct attribute name for this meta tag is `http-equiv`, not `https-equiv`.

---

**`insecure-document-method`** | WARNING | `community-rules\html\security\audit\insecure-document-method.yaml`
> Detected the use of an inner/outerHTML assignment.  This can introduce a Cross-Site-Scripting (XSS) vulnerability if this  comes from user-provided input. If you have to use a dangerous web API,  consider using a sanitization library such as DOMPurify to sanitize  the HTML before it is assigned.

---

**`missing-integrity`** | WARNING | `community-rules\html\security\audit\missing-integrity.yaml`
> This tag is missing an 'integrity' subresource integrity attribute. The 'integrity' attribute allows for the browser to verify that externally hosted files (for example from a CDN) are delivered without unexpected manipulation. Without this attribute, if an attacker can modify the externally hosted resource, this could lead to XSS and other types of attacks. To prevent this, include the base64-encoded cryptographic hash of the resource (file) you’re telling the browser to fetch in the 'integrity' attribute for all externally hosted files.

---

**`plaintext-http-link`** | WARNING | `community-rules\html\security\plaintext-http-link.yaml`
> This link points to a plaintext HTTP URL. Prefer an encrypted HTTPS URL if possible.

---

**`robots-denied`** | INFO | `community-rules\html\best-practice\robots-denied.yaml`
> This page denies crawlers from indexing the page. Remove the robots 'meta' tag.

---

## Java (190 rules)

**`anonymous-ldap-bind`** | WARNING | `community-rules\java\lang\security\audit\anonymous-ldap-bind.yaml`
> Detected anonymous LDAP bind. This permits anonymous users to execute LDAP statements. Consider enforcing authentication for LDAP. See https://docs.oracle.com/javase/tutorial/jndi/ldap/auth_mechs.html for more information.

---

**`assignment-comparison`** | ERROR | `community-rules\java\lang\correctness\assignment-comparison.yaml`
> The value of `$X` is being ignored and will be used in the conditional test

---

**`autoescape-disabled`** | WARNING | `community-rules\java\lang\security\audit\xss\jsf\autoescape-disabled.yaml`
> Detected an element with disabled HTML escaping. If external data can reach this, this is a cross-site scripting (XSS) vulnerability. Ensure no external data can reach here, or remove 'escape=false' from this element.

---

**`avoid-implementing-custom-digests`** | WARNING | `community-rules\java\lang\security\audit\crypto\ssl\avoid-implementing-custom-digests.yaml`
> Cryptographic algorithms are notoriously difficult to get right. By implementing a custom message digest, you risk introducing security issues into your program. Use one of the many sound message digests already available to you: MessageDigest sha256Digest = MessageDigest.getInstance("SHA256");

---

**`bad-hexa-conversion`** | WARNING | `community-rules\java\lang\security\audit\bad-hexa-conversion.yaml`
> 'Integer.toHexString()' strips leading zeroes from each byte if read byte-by-byte. This mistake weakens the hash value computed since it introduces more collisions. Use 'String.format("%02X", ...)' instead.

---

**`blowfish-insufficient-key-size`** | WARNING | `community-rules\java\lang\security\audit\blowfish-insufficient-key-size.yaml`
> Using less than 128 bits for Blowfish is considered insecure. Use 128 bits or more, or switch to use AES instead.

---

**`cbc-padding-oracle`** | WARNING | `community-rules\java\lang\security\audit\cbc-padding-oracle.yaml`
> Using CBC with PKCS5Padding is susceptible to padding oracle attacks. A malicious actor could discern the difference between plaintext with valid or invalid padding. Further, CBC mode does not include any integrity checks. Use 'AES/GCM/NoPadding' instead.

---

**`command-injection-formatted-runtime-call`** | ERROR | `community-rules\java\lang\security\audit\command-injection-formatted-runtime-call.yaml`
> A formatted or concatenated string was detected as input to a java.lang.Runtime call. This is dangerous if a variable is controlled by user input and could result in a command injection. Ensure your variables are not controlled by users or sufficiently sanitized.

---

**`command-injection-process-builder`** | ERROR | `community-rules\java\lang\security\audit\command-injection-process-builder.yaml`
> A formatted or concatenated string was detected as input to a ProcessBuilder call. This is dangerous if a variable is controlled by user input and could result in a command injection. Ensure your variables are not controlled by users or sufficiently sanitized.

---

**`cookie-issecure-false`** | WARNING | `community-rules\java\servlets\security\cookie-issecure-false.yaml`
> Default session middleware settings: `setSecure` not set to true. This ensures that the cookie is sent only over HTTPS to prevent cross-site scripting attacks.

---

**`cookie-missing-httponly`** | WARNING | `community-rules\java\lang\security\audit\cookie-missing-httponly.yaml`
> A cookie was detected without setting the 'HttpOnly' flag. The 'HttpOnly' flag for cookies instructs the browser to forbid client-side scripts from reading the cookie. Set the 'HttpOnly' flag by calling 'cookie.setHttpOnly(true);'

---

**`cookie-missing-secure-flag`** | WARNING | `community-rules\java\lang\security\audit\cookie-missing-secure-flag.yaml`
> A cookie was detected without setting the 'secure' flag. The 'secure' flag for cookies prevents the client from transmitting the cookie over insecure channels such as HTTP. Set the 'secure' flag by calling '$COOKIE.setSecure(true);'

---

**`cookie-setSecure`** | WARNING | `community-rules\java\servlets\security\cookie-setSecure.yaml`
> Default session middleware settings: `setSecure` not set to true. This ensures that the cookie is sent only over HTTPS to prevent cross-site scripting attacks.

---

**`crlf-injection-logs`** | WARNING | `community-rules\java\lang\security\audit\crlf-injection-logs.yaml`
> When data from an untrusted source is put into a logger and not neutralized correctly, an attacker could forge log entries or include malicious content.

---

**`dangerous-groovy-shell`** | WARNING | `community-rules\java\lang\security\audit\dangerous-groovy-shell.yaml`
> A expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.

---

**`default-resteasy-provider-abuse`** | WARNING | `community-rules\java\jax-rs\security\insecure-resteasy.yaml`
> When a Restful webservice endpoint isn't configured with a @Consumes annotation, an attacker could abuse the SerializableProvider by sending a HTTP Request with a Content-Type of application/x-java-serialized-object. The body of that request would be processed by the SerializationProvider and could contain a malicious payload, which may lead to arbitrary code execution. Instead, add a @Consumes annotation to the function or class.

---

**`defaulthttpclient-is-deprecated`** | WARNING | `community-rules\java\lang\security\audit\crypto\ssl\defaulthttpclient-is-deprecated.yaml`
> DefaultHttpClient is deprecated. Further, it does not support connections using TLS1.2, which makes using DefaultHttpClient a security hazard. Use HttpClientBuilder instead.

---

**`des-is-deprecated`** | WARNING | `community-rules\java\lang\security\audit\crypto\des-is-deprecated.yaml`
> DES is considered deprecated. AES is the recommended cipher. Upgrade to use AES. See https://www.nist.gov/news-events/news/2005/06/nist-withdraws-outdated-data-encryption-standard for more information.

---

**`desede-is-deprecated`** | WARNING | `community-rules\java\lang\security\audit\crypto\desede-is-deprecated.yaml`
> Triple DES (3DES or DESede) is considered deprecated. AES is the recommended cipher. Upgrade to use AES.

---

**`do-privileged-use`** | WARNING | `community-rules\java\lang\security\do-privileged-use.yaml`
> Marking code as privileged enables a piece of trusted code to temporarily enable access to more resources than are available directly to the code that called it. Be very careful in your use of the privileged construct, and always remember to make the privileged code section as small as possible.

---

**`documentbuilderfactory-disallow-doctype-decl-false`** | ERROR | `community-rules\java\lang\security\audit\xxe\documentbuilderfactory-disallow-doctype-decl-false.yaml`
> DOCTYPE declarations are enabled for $DBFACTORY. Without prohibiting external entity declarations, this is vulnerable to XML external entity attacks. Disable this by setting the feature "http://apache.org/xml/features/disallow-doctype-decl" to true. Alternatively, allow DOCTYPE declarations and only prohibit external entities declarations. This can be done by setting the features "http://xml.org/sax/features/external-general-entities" and "http://xml.org/sax/features/external-parameter-entities" to false.

---

**`documentbuilderfactory-disallow-doctype-decl-missing`** | ERROR | `community-rules\java\lang\security\audit\xxe\documentbuilderfactory-disallow-doctype-decl-missing.yaml`
> DOCTYPE declarations are enabled for this DocumentBuilderFactory. This is vulnerable to XML external entity attacks. Disable this by setting the feature "http://apache.org/xml/features/disallow-doctype-decl" to true. Alternatively, allow DOCTYPE declarations and only prohibit external entities declarations. This can be done by setting the features "http://xml.org/sax/features/external-general-entities" and "http://xml.org/sax/features/external-parameter-entities" to false.

---

**`documentbuilderfactory-external-general-entities-true`** | ERROR | `community-rules\java\lang\security\audit\xxe\documentbuilderfactory-external-general-entities-true.yaml`
> External entities are allowed for $DBFACTORY. This is vulnerable to XML external entity attacks. Disable this by setting the feature "http://xml.org/sax/features/external-general-entities" to false.

---

**`documentbuilderfactory-external-parameter-entities-true`** | ERROR | `community-rules\java\lang\security\audit\xxe\documentbuilderfactory-external-parameter-entities-true.yaml`
> External entities are allowed for $DBFACTORY. This is vulnerable to XML external entity attacks. Disable this by setting the feature "http://xml.org/sax/features/external-parameter-entities" to false.

---

**`ecb-cipher`** | WARNING | `community-rules\java\lang\security\audit\crypto\ecb-cipher.yaml`
> Cipher in ECB mode is detected. ECB mode produces the same output for the same input each time which allows an attacker to intercept and replay the data. Further, ECB mode does not provide any integrity checking. See https://find-sec-bugs.github.io/bugs.htm#CIPHER_INTEGRITY.

---

**`el-injection`** | WARNING | `community-rules\java\lang\security\audit\el-injection.yaml`
> An expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.

---

**`eqeq`** | ERROR | `community-rules\java\lang\correctness\eqeq.yaml`
> `$X == $X` or `$X != $X` is always true. (Unless the value compared is a float or double). To test if `$X` is not-a-number, use `Double.isNaN($X)`.

---

**`exported_activity`** | WARNING | `community-rules\java\android\security\exported_activity.yaml`
> The application exports an activity. Any application on the device can launch the exported activity which may compromise the integrity of your application or its data.  Ensure that any exported activities do not have privileged access to your application's control plane.

---

**`feign-without-fallback`** | WARNING | `rules\java-rules.yml`
> Feign clients should specify fallback for graceful degradation

---

**`find-sql-string-concatenation`** | ERROR | `community-rules\java\jboss\security\session_sqli.yaml`
> In $METHOD, $X is used to construct a SQL query via string concatenation.

---

**`formatted-sql-string`** | ERROR | `community-rules\java\lang\security\audit\formatted-sql-string.yaml`
> Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) instead. You can obtain a PreparedStatement using 'connection.prepareStatement'.

---

**`gcm-detection`** | INFO | `community-rules\java\lang\security\audit\crypto\gcm-detection.yaml`
> GCM detected, please check that IV/nonce is not reused, an Initialization Vector (IV) is a nonce used to randomize the encryption, so that even if multiple messages with identical plaintext are encrypted, the generated corresponding ciphertexts are different. Unlike the Key, the IV usually does not need to be secret, rather it is important that it is random and unique. Certain encryption schemes the IV is exchanged in public as part of the ciphertext. Reusing same Initialization Vector with the same Key to encrypt multiple plaintext blocks allows an attacker to compare the ciphertexts and then, with some assumptions on the content of the messages, to gain important information about the data being encrypted.

---

**`gcm-nonce-reuse`** | ERROR | `community-rules\java\lang\security\audit\crypto\gcm-nonce-reuse.yaml`
> GCM IV/nonce is reused: encryption can be totally useless

---

**`hardcoded-conditional`** | ERROR | `community-rules\java\lang\correctness\hardcoded-conditional.yaml`
> This if statement will always have the same behavior and is therefore unnecessary.

---

**`hibernate-sqli`** | WARNING | `community-rules\java\lang\security\audit\sqli\hibernate-sqli.yaml`
> Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) instead. You can obtain a PreparedStatement using 'connection.prepareStatement'.

---

**`http-response-splitting`** | INFO | `community-rules\java\lang\security\audit\http-response-splitting.yaml`
> Older Java application servers are vulnerable to HTTP response splitting, which may occur if an HTTP request can be injected with CRLF characters. This finding is reported for completeness; it is recommended to ensure your environment is not affected by testing this yourself.

---

**`httpservlet-path-traversal`** | ERROR | `community-rules\java\lang\security\httpservlet-path-traversal.yaml`
> Detected a potential path traversal. A malicious actor could control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables in file paths are sanitized. You may also consider using a utility method such as org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path.

---

**`insecure-hostname-verifier`** | WARNING | `community-rules\java\lang\security\audit\crypto\ssl\insecure-hostname-verifier.yaml`
> Insecure HostnameVerifier implementation detected. This will accept any SSL certificate with any hostname, which creates the possibility for man-in-the-middle attacks.

---

**`insecure-jms-deserialization`** | WARNING | `community-rules\java\lang\security\insecure-jms-deserialization.yaml`
> JMS Object messages depend on Java Serialization for marshalling/unmarshalling of the message payload when ObjectMessage.getObject() is called. Deserialization of untrusted data can lead to security flaws; a remote attacker could via a crafted JMS ObjectMessage to execute arbitrary code with the permissions of the application listening/consuming JMS Messages. In this case, the JMS MessageListener consume an ObjectMessage type received inside the onMessage method, which may lead to arbitrary code execution when calling the $Y.getObject method.

---

**`insecure-resteasy-deserialization`** | WARNING | `community-rules\java\jax-rs\security\insecure-resteasy.yaml`
> When a Restful webservice endpoint is configured to use wildcard mediaType {*/*} as a value for the @Consumes annotation, an attacker could abuse the SerializableProvider by sending a HTTP Request with a Content-Type of application/x-java-serialized-object. The body of that request would be processed by the SerializationProvider and could contain a malicious payload, which may lead to arbitrary code execution when calling the $Y.getObject method.

---

**`insecure-smtp-connection`** | WARNING | `community-rules\java\lang\security\audit\insecure-smtp-connection.yaml`
> Insecure SMTP connection detected. This connection will trust any SSL certificate. Enable certificate verification by setting 'email.setSSLCheckServerIdentity(true)'.

---

**`insecure-trust-manager`** | WARNING | `community-rules\java\lang\security\audit\crypto\ssl\insecure-trust-manager.yaml`
> Detected empty trust manager implementations. This is dangerous because it accepts any certificate, enabling man-in-the-middle attacks. Consider using a KeyStore and TrustManagerFactory instead. See https://stackoverflow.com/questions/2642777/trusting-all-certificates-using-httpclient-over-https for more information.

---

**`jackson-enable-default-typing`** | ERROR | `rules\java-rules.yml`
> Security Risk: enableDefaultTyping allows arbitrary class deserialization. Use @JsonTypeInfo with allowlist

---

**`jackson-missing-ignore-properties`** | INFO | `rules\java-rules.yml`
> Add @JsonIgnoreProperties(ignoreUnknown=true) to prevent deserialization errors

---

**`jackson-sensitive-field-exposed`** | ERROR | `rules\java-rules.yml`
> Sensitive field may be exposed in JSON. Add @JsonIgnore annotation

---

**`jackson-unsafe-deserialization`** | WARNING | `community-rules\java\lang\security\jackson-unsafe-deserialization.yaml`
> When using Jackson to marshall/unmarshall JSON to Java objects, enabling default typing is dangerous and can lead to RCE. If an attacker can control `$JSON` it might be possible to provide a malicious JSON which can be used to exploit unsecure deserialization. In order to prevent this issue, avoid to enable default typing (globally or by using "Per-class" annotations) and avoid using `Object` and other dangerous types for member variable declaration which creating classes for Jackson based deserialization.

---

**`java-autoboxing-in-loop`** | WARNING | `rules\java-rules.yml`
> Autoboxing primitives in loops creates unnecessary objects. Use primitives directly

---

**`java-double-checked-locking`** | ERROR | `rules\java-rules.yml`
> Double-checked locking is broken without volatile. Mark instance as volatile

---

**`java-inefficient-collection-contains`** | WARNING | `rules\java-rules.yml`
> Using ArrayList.contains() in a loop is O(n²). Consider using HashSet for O(1) lookups

---

**`java-inefficient-map-iteration`** | INFO | `rules\java-rules.yml`
> Inefficient map iteration. Use entrySet() instead of keySet() to avoid double lookup

---

**`java-jwt-decode-without-verify`** | WARNING | `community-rules\java\java-jwt\security\audit\jwt-decode-without-verify.yaml`
> Detected the decoding of a JWT token without a verify step. JWT tokens must be verified before use, otherwise the token's integrity is unknown. This means a malicious actor could forge a JWT token with any claims. Call '.verify()' before using the token.

---

**`java-jwt-hardcoded-secret`** | WARNING | `community-rules\java\java-jwt\security\jwt-hardcode.yaml`
> A hard-coded credential was detected. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`java-jwt-none-alg`** | ERROR | `community-rules\java\java-jwt\security\jwt-none-alg.yaml`
> Detected use of the 'none' algorithm in a JWT token. The 'none' algorithm assumes the integrity of the token has already been verified. This would allow a malicious actor to forge a JWT token that will automatically be verified. Do not explicitly use the 'none' algorithm. Instead, use an algorithm such as 'HS256'.

---

**`java-non-atomic-operation`** | WARNING | `rules\java-rules.yml`
> Increment operation is not atomic in concurrent context. Use AtomicInteger or synchronization

---

**`java-null-check-missing`** | WARNING | `rules\java-rules.yml`
> Potential null pointer exception. Check for null before use

---

**`java-object-creation-in-loop`** | INFO | `rules\java-rules.yml`
> Creating objects in loops can impact performance. Consider object reuse or caching

---

**`java-optional-get-without-check`** | ERROR | `rules\java-rules.yml`
> Calling Optional.get() without isPresent() can throw NoSuchElementException. Use orElse() or orElseThrow()

---

**`java-parallel-stream-small-collection`** | INFO | `rules\java-rules.yml`
> Parallel streams have overhead. Only use for large datasets (>10k elements) with CPU-intensive operations

---

**`java-pattern-from-string-parameter`** | INFO | `community-rules\java\lang\security\java-pattern-from-string-parameter.yaml`
> A regular expression is being used directly from a String method parameter. This could be a Regular Expression Denial of Service (ReDoS) vulnerability if the parameter is user-controlled and not properly validated. Ensure that a validation is in place to prevent evaluation using a regular expression prone to ReDoS.

---

**`java-resource-leak`** | WARNING | `rules\java-rules.yml`
> Resource may not be closed. Use try-with-resources

---

**`java-reverse-shell`** | WARNING | `community-rules\java\lang\security\audit\java-reverse-shell.yaml`
> Semgrep found potential reverse shell behavior

---

**`java-rule-1-string-equals`** | ERROR | `rules\java-rules.yml`
> Rule 1: Use .equals() for string comparison, not ==

---

**`java-rule-11-generic-exception`** | WARNING | `rules\java-rules.yml`
> Rule 11: Avoid catching generic Exception. Catch specific exceptions

---

**`java-rule-14-string-concat-loop`** | WARNING | `rules\java-rules.yml`
> Rule 14: Use StringBuilder for string concatenation in loops

---

**`java-rule-15-sql-injection`** | ERROR | `rules\java-rules.yml`
> Rule 15: Use PreparedStatement to prevent SQL injection

---

**`java-rule-19-sleep-in-loop`** | WARNING | `rules\java-rules.yml`
> Rule 19: Avoid Thread.sleep() in loops. Use ScheduledExecutorService

---

**`java-rule-2-no-system-out`** | WARNING | `rules\java-rules.yml`
> Rule 2: Avoid System.out.println in production. Use proper logging framework (log4j, slf4j)

---

**`java-rule-21-class-naming-pascalcase`** | WARNING | `rules\java-rules.yml`
> Java Rule 21: Class names should use PascalCase (e.g., UserService, not userService or user_service)

---

**`java-rule-22-method-naming-camelcase`** | WARNING | `rules\java-rules.yml`
> Java Rule 22: Method names should use camelCase (e.g., calculateTotal, not CalculateTotal or calculate_total)

---

**`java-rule-23-variable-naming-camelcase`** | INFO | `rules\java-rules.yml`
> Java Rule 23: Variable names should use camelCase (e.g., userName, not user_name or UserName)

---

**`java-rule-24-constant-naming-uppercase`** | INFO | `rules\java-rules.yml`
> Java Rule 24: Constants should use UPPER_CASE with underscores (e.g., MAX_RETRIES, API_KEY)

---

**`java-rule-25-package-naming-lowercase`** | INFO | `rules\java-rules.yml`
> Java Rule 25: Package names should be all lowercase (e.g., com.example.project, not com.Example.Project)

---

**`java-rule-3-handle-exceptions`** | WARNING | `rules\java-rules.yml`
> Rule 3: Handle exceptions properly. Use logger.error() instead of System.out

---

**`java-rule-4-empty-catch`** | ERROR | `rules\java-rules.yml`
> Rule 4: Do not leave empty catch blocks. Log or rethrow exceptions

---

**`java-rule-6-use-interface`** | INFO | `rules\java-rules.yml`
> Rule 6: Use interface types (List, Map, Set) instead of concrete implementations

---

**`java-rule-7-private-fields`** | WARNING | `rules\java-rules.yml`
> Rule 7: Keep fields private. Use getters/setters for access

---

**`java-stream-peek-side-effects`** | WARNING | `rules\java-rules.yml`
> Don't use peek() for side effects. Use forEach() or collect() instead

---

**`java-stream-unnecessary-collect`** | WARNING | `rules\java-rules.yml`
> Inefficient: Use .count() instead of .collect().size()

---

**`java-string-format-in-loop`** | WARNING | `rules\java-rules.yml`
> String.format() is expensive in loops. Consider StringBuilder or simple concatenation

---

**`java-sync-on-string`** | ERROR | `rules\java-rules.yml`
> Never synchronize on String literals - they are interned and shared. Use dedicated lock object

---

**`java-test-hardcoded-production-data`** | INFO | `rules\java-rules.yml`
> Avoid hardcoded production-like data in tests. Use test-specific data

---

**`java-test-no-assertions`** | WARNING | `rules\java-rules.yml`
> Test method has no assertions. Tests without assertions don't verify behavior

---

**`java-test-sleep-instead-of-wait`** | WARNING | `rules\java-rules.yml`
> Don't use Thread.sleep() in tests. Use proper waiting mechanisms (Awaitility, CountDownLatch)

---

**`java-threadlocal-no-cleanup`** | WARNING | `rules\java-rules.yml`
> ThreadLocal can cause memory leaks. Always call remove() in finally block, especially in thread pools

---

**`java-volatile-instead-of-atomic`** | INFO | `rules\java-rules.yml`
> For counters and numeric operations, use AtomicInteger instead of volatile int

---

**`java-weak-hash`** | ERROR | `rules\java-rules.yml`
> MD5 and SHA1 are weak. Use SHA-256 or stronger

---

**`jax-rs-path-traversal`** | WARNING | `community-rules\java\jax-rs\security\jax-rs-path-traversal.yaml`
> Detected a potential path traversal. A malicious actor could control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables in file paths are sanitized. You may also consider using a utility method such as org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path.

---

**`jdbc-sql-formatted-string`** | WARNING | `community-rules\java\lang\security\audit\jdbc-sql-formatted-string.yaml`
> Possible JDBC injection detected. Use the parameterized query feature available in queryForObject instead of concatenating or formatting strings: 'jdbc.queryForObject("select * from table where name = ?", Integer.class, parameterName);'

---

**`jdbc-sqli`** | WARNING | `community-rules\java\lang\security\audit\sqli\jdbc-sqli.yaml`
> Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) instead. You can obtain a PreparedStatement using 'connection.prepareStatement'.

---

**`jdo-sqli`** | WARNING | `community-rules\java\lang\security\audit\sqli\jdo-sqli.yaml`
> Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) instead. You can obtain a PreparedStatement using 'connection.prepareStatement'.

---

**`jjwt-none-alg`** | ERROR | `community-rules\java\jjwt\security\jwt-none-alg.yaml`
> Detected use of the 'none' algorithm in a JWT token. The 'none' algorithm assumes the integrity of the token has already been verified. This would allow a malicious actor to forge a JWT token that will automatically be verified. Do not explicitly use the 'none' algorithm. Instead, use an algorithm such as 'HS256'.

---

**`jpa-bidirectional-no-mappedby`** | WARNING | `rules\java-rules.yml`
> For bidirectional relationships, use mappedBy to avoid duplicate foreign keys

---

**`jpa-entity-missing-equals-hashcode`** | WARNING | `rules\java-rules.yml`
> JPA entities should override equals() and hashCode() for proper collection handling

---

**`jpa-missing-fetch-type`** | INFO | `rules\java-rules.yml`
> Explicitly specify fetch type (LAZY/EAGER) for @OneToMany relationships

---

**`jpa-potential-n-plus-one`** | WARNING | `rules\java-rules.yml`
> Potential N+1 query issue. Add @BatchSize or use JOIN FETCH in queries

---

**`jpa-sqli`** | WARNING | `community-rules\java\lang\security\audit\sqli\jpa-sqli.yaml`
> Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) instead. You can obtain a PreparedStatement using 'connection.prepareStatement'.

---

**`ldap-entry-poisoning`** | WARNING | `community-rules\java\lang\security\audit\ldap-entry-poisoning.yaml`
> An object-returning LDAP search will allow attackers to control the LDAP response. This could lead to Remote Code Execution.

---

**`ldap-injection`** | WARNING | `community-rules\java\lang\security\audit\ldap-injection.yaml`
> Detected non-constant data passed into an LDAP query. If this data can be controlled by an external user, this is an LDAP injection. Ensure data passed to an LDAP query is not controllable; or properly sanitize the data.

---

**`manifest-usesCleartextTraffic-ignored-by-nsc`** | INFO | `community-rules\java\android\best-practice\manifest-security-features.yaml`
> Manifest uses both `android:usesCleartextTraffic` and Network Security Config. The `usesCleartextTraffic` directive is ignored on Android 7 (API 24) and above if a Network Security Config is present.

---

**`manifest-usesCleartextTraffic-true`** | INFO | `community-rules\java\android\best-practice\manifest-security-features.yaml`
> The Android manifest is configured to allow non-encrypted connections. Evaluate if this is necessary for your app, and disable it if appropriate. This flag is ignored on Android 7 (API 24) and above if a Network Security Config is present.

---

**`md5-used-as-password`** | WARNING | `community-rules\java\lang\security\audit\md5-used-as-password.yaml`
> It looks like MD5 is used as a password hash. MD5 is not considered a secure password hash because it can be cracked by an attacker in a short amount of time. Use a suitable password hashing function such as PBKDF2 or bcrypt. You can use `javax.crypto.SecretKeyFactory` with `SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")` or, if using Spring, `org.springframework.security.crypto.bcrypt`.

---

**`mongodb-nosqli`** | WARNING | `community-rules\java\mongodb\security\injection\audit\mongodb-nosqli.yaml`
> Detected non-constant data passed into a NoSQL query using the 'where' evaluation operator. If this data can be controlled by an external user, this is a NoSQL injection. Ensure data passed to the NoSQL query is not user controllable, or properly sanitize the data. Ideally, avoid using the 'where' operator at all and instead use the helper methods provided by com.mongodb.client.model.Filters with comparative operators such as eq, ne, lt, gt, etc.

---

**`no-direct-response-writer`** | WARNING | `community-rules\java\lang\security\audit\xss\no-direct-response-writer.yaml`
> Detected a request with potential user-input going into a OutputStream or Writer object. This bypasses any view or template environments, including HTML escaping, which may expose this application to cross-site scripting (XSS) vulnerabilities. Consider using a view technology such as JavaServer Faces (JSFs) which automatically escapes HTML views.

---

**`no-null-cipher`** | WARNING | `community-rules\java\lang\security\audit\crypto\no-null-cipher.yaml`
> NullCipher was detected. This will not encrypt anything; the cipher text will be the same as the plain text. Use a valid, secure cipher: Cipher.getInstance("AES/CBC/PKCS7PADDING"). See https://owasp.org/www-community/Using_the_Java_Cryptographic_Extensions for more information.

---

**`no-scriptlets`** | WARNING | `community-rules\java\lang\security\audit\xss\jsp\no-scriptlets.yaml`
> JSP scriptlet detected. Scriptlets are difficult to use securely and are considered bad practice. See https://stackoverflow.com/a/3180202. Instead, consider migrating to JSF or using the Expression Language '${...}' with the escapeXml function in your JSP files.

---

**`no-static-initialization-vector`** | WARNING | `community-rules\java\lang\security\audit\crypto\no-static-initialization-vector.yaml`
> Initialization Vectors (IVs) for block ciphers should be randomly generated each time they are used. Using a static IV means the same plaintext encrypts to the same ciphertext every time, weakening the strength of the encryption.

---

**`no-string-eqeq`** | WARNING | `community-rules\java\lang\correctness\no-string-eqeq.yaml`
> Strings should not be compared with '=='. This is a reference comparison operator. Use '.equals()' instead.

---

**`nsc-allows-plaintext-traffic`** | INFO | `community-rules\java\android\best-practice\network-security-config.yml`
> The Network Security Config is set to allow non-encrypted connections. Evaluate if this is necessary for your app, and disable it if appropriate. (To hide this warning, set `xmlns:tools="http://schemas.android.com/tools" tools:ignore="InsecureBaseConfiguration"` as parameters to your `<network-security-config>`)

---

**`nsc-allows-user-ca-certs`** | WARNING | `community-rules\java\android\best-practice\network-security-config.yml`
> The Network Security Config is set to accept user-installed CAs. Evaluate if this is necessary for your app, and disable it if appropriate. (To hide this warning, set `xmlns:tools="http://schemas.android.com/tools" tools:ignore="AcceptsUserCertificates"` as parameters to your `<network-security-config>`)

---

**`nsc-allows-user-ca-certs-for-domain`** | WARNING | `community-rules\java\android\best-practice\network-security-config.yml`
> The Network Security Config is set to accept user-installed CAs for the domain `$DOMAIN`. Evaluate if this is necessary for your app, and disable it if appropriate. (To hide this warning, set `xmlns:tools="http://schemas.android.com/tools" tools:ignore="AcceptsUserCertificates"` as parameters to your `<network-security-config>`)

---

**`nsc-pinning-without-backup`** | INFO | `community-rules\java\android\best-practice\network-security-config.yml`
> Your app uses TLS public key pinning without specifying a backup key. If you are forced to change TLS keys or CAs on short notice, not having a backup pin can lead to connectivity issues until you can push out an update. It is considered best practice to add at least one additional pin as a backup.

---

**`nsc-pinning-without-expiration`** | INFO | `community-rules\java\android\best-practice\network-security-config.yml`
> Your app uses TLS public key pinning without specifying an expiration date. If your users do not update the app to receive new pins in time, expired or replaced certificates can lead to connectivity issues until they install an update. It is considered best practice to set an expiration time, after which the system will default to trusting system CAs and disregard the pin.

---

**`object-deserialization`** | WARNING | `community-rules\java\lang\security\audit\object-deserialization.yaml`
> Found object deserialization using ObjectInputStream. Deserializing entire Java objects is dangerous because malicious actors can create Java object streams with unintended consequences. Ensure that the objects being deserialized are not user-controlled. If this must be done, consider using HMACs to sign the data stream to make sure it is not tampered with, or consider only transmitting object fields and populating a new object.

---

**`ognl-injection`** | WARNING | `community-rules\java\lang\security\audit\ognl-injection.yaml`
> A expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.

---

**`overly-permissive-file-permission`** | WARNING | `community-rules\java\lang\security\audit\overly-permissive-file-permission.yaml`
> Detected file permissions that are overly permissive (read, write, and execute). It is generally a bad practices to set overly permissive file permission such as read+write+exec for all users. If the file affected is a configuration, a binary, a script or sensitive data, it can lead to privilege escalation or information leakage. Instead, follow the principle of least privilege and give users only the  permissions they need.

---

**`permissive-cors`** | WARNING | `community-rules\java\lang\security\audit\permissive-cors.yaml`
> https://find-sec-bugs.github.io/bugs.htm#PERMISSIVE_CORS Permissive CORS policy will allow a malicious application to communicate with the victim application in an inappropriate way, leading to spoofing, data theft, relay and other attacks.

---

**`rsa-no-padding`** | WARNING | `community-rules\java\lang\security\audit\crypto\rsa-no-padding.yaml`
> Using RSA without OAEP mode weakens the encryption.

---

**`saxparserfactory-disallow-doctype-decl-missing`** | ERROR | `community-rules\java\lang\security\audit\xxe\saxparserfactory-disallow-doctype-decl-missing.yaml`
> DOCTYPE declarations are enabled for this SAXParserFactory. This is vulnerable to XML external entity attacks. Disable this by setting the feature `http://apache.org/xml/features/disallow-doctype-decl` to true. Alternatively, allow DOCTYPE declarations and only prohibit external entities declarations. This can be done by setting the features `http://xml.org/sax/features/external-general-entities` and `http://xml.org/sax/features/external-parameter-entities` to false. NOTE - The previous links are not meant to be clicked. They are the literal config key values that are supposed to be used to disable these features. For more information, see https://semgrep.dev/docs/cheat-sheets/java-xxe/#3a-documentbuilderfactory.

---

**`script-engine-injection`** | WARNING | `community-rules\java\lang\security\audit\script-engine-injection.yaml`
> Detected potential code injection using ScriptEngine. Ensure user-controlled data cannot enter '.eval()', otherwise, this is a code injection vulnerability.

---

**`seam-log-injection`** | ERROR | `community-rules\java\jboss\security\seam-log-injection.yaml`
> Seam Logging API support an expression language to introduce bean property to log messages. The expression language can also be the source to unwanted code execution. In this context, an expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.

---

**`security-constraint-http-method`** | WARNING | `community-rules\java\servlets\security\security-constraint-http-method.yaml`
> The tag "http-method" is used to specify on which HTTP methods the java web security constraint apply. The target security constraints could be bypassed if a non listed HTTP method is used. Inverse the logic by using the tag "http-method-omission" to define for which HTTP methods the security constraint do not apply. Using this way, only expected allowed HTTP methods will be skipped by the security constraint.

---

**`server-dangerous-class-deserialization`** | WARNING | `community-rules\java\rmi\security\server-dangerous-class-deserialization.yaml`
> Using a non-primitive class with Java RMI may be an insecure deserialization vulnerability. Depending on the underlying implementation. This object could be manipulated by a malicious actor allowing them to execute code on your system. Instead, use an integer ID to look up your object, or consider alternative serialization schemes such as JSON.

---

**`server-dangerous-object-deserialization`** | ERROR | `community-rules\java\rmi\security\server-dangerous-object-deserialization.yaml`
> Using an arbitrary object ('$PARAMTYPE $PARAM') with Java RMI is an insecure deserialization vulnerability. This object can be manipulated by a malicious actor allowing them to execute code on your system. Instead, use an integer ID to look up your object, or consider alternative serialization schemes such as JSON.

---

**`servletresponse-writer-xss`** | ERROR | `community-rules\java\lang\security\servletresponse-writer-xss.yaml`
> Cross-site scripting detected in HttpServletResponse writer with variable '$VAR'. User input was detected going directly from the HttpServletRequest into output. Ensure your data is properly encoded using org.owasp.encoder.Encode.forHtml: 'Encode.forHtml($VAR)'.

---

**`spel-injection`** | WARNING | `community-rules\java\spring\security\audit\spel-injection.yaml`
> A Spring expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.

---

**`spring-actuator-dangerous-endpoints-enabled`** | WARNING | `community-rules\java\spring\security\audit\spring-actuator-non-health-enabled.yaml`
> Spring Boot Actuators "$...ACTUATORS" are enabled. Depending on the actuators, this can pose a significant security risk. Please double-check if the actuators are needed and properly secured.

---

**`spring-actuator-dangerous-endpoints-enabled-yaml`** | WARNING | `community-rules\java\spring\security\audit\spring-actuator-non-health-enabled-yaml.yaml`
> Spring Boot Actuator "$ACTUATOR" is enabled. Depending on the actuator, this can pose a significant security risk. Please double-check if the actuator is needed and properly secured.

---

**`spring-actuator-fully-enabled`** | ERROR | `community-rules\java\spring\security\audit\spring-actuator-fully-enabled.yaml`
> Spring Boot Actuator is fully enabled. This exposes sensitive endpoints such as /actuator/env, /actuator/logfile, /actuator/heapdump and others. Unless you have Spring Security enabled or another means to protect these endpoints, this functionality is available without authentication, causing a significant security risk.

---

**`spring-actuator-fully-enabled-yaml`** | WARNING | `community-rules\java\spring\security\audit\spring-actuator-fully-enabled-yaml.yaml`
> Spring Boot Actuator is fully enabled. This exposes sensitive endpoints such as /actuator/env, /actuator/logfile, /actuator/heapdump and others. Unless you have Spring Security enabled or another means to protect these endpoints, this functionality is available without authentication, causing a severe security risk.

---

**`spring-cors-allow-all`** | ERROR | `rules\java-rules.yml`
> SPRING BOOT: CORS allows all origins (*). Restrict to specific domains for security

---

**`spring-csrf-disabled`** | WARNING | `community-rules\java\spring\security\audit\spring-csrf-disabled.yaml`
> CSRF protection is disabled for this configuration. This is a security risk.

---

**`spring-csrf-disabled`** | WARNING | `rules\java-rules.yml`
> SPRING BOOT: CSRF protection disabled. Only disable for stateless APIs with proper authentication

---

**`spring-exposed-actuator`** | ERROR | `rules\java-rules.yml`
> SPRING BOOT: All actuator endpoints exposed. Limit to specific endpoints (health, info)

---

**`spring-field-injection`** | WARNING | `rules\java-rules.yml`
> SPRING BOOT: Avoid field injection. Use constructor injection for better testability

---

**`spring-hardcoded-credentials`** | ERROR | `rules\java-rules.yml`
> SPRING BOOT: Hardcoded database credentials. Use environment variables or vault

---

**`spring-insecure-deserialization`** | ERROR | `rules\java-rules.yml`
> SPRING BOOT: Insecure deserialization detected. Validate input or use safe alternatives

---

**`spring-jsp-eval`** | WARNING | `community-rules\java\spring\security\audit\spring-jsp-eval.yaml`
> A Spring expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.

---

**`spring-missing-authorization`** | ERROR | `rules\java-rules.yml`
> SPRING BOOT: DELETE endpoint lacks authorization check. Add @PreAuthorize or @Secured

---

**`spring-missing-circuit-breaker`** | WARNING | `rules\java-rules.yml`
> External HTTP calls should use @CircuitBreaker for resilience

---

**`spring-missing-exception-handler`** | WARNING | `rules\java-rules.yml`
> SPRING BOOT: Controller lacks @ExceptionHandler. Add global exception handling

---

**`spring-missing-rate-limit`** | INFO | `rules\java-rules.yml`
> SPRING BOOT: POST endpoint lacks rate limiting. Consider adding @RateLimiter for API protection

---

**`spring-missing-response-entity`** | INFO | `rules\java-rules.yml`
> SPRING BOOT: Return ResponseEntity for better HTTP status control

---

**`spring-missing-retry`** | INFO | `rules\java-rules.yml`
> HTTP calls should have @Retryable for transient failure handling

---

**`spring-missing-transactional`** | WARNING | `rules\java-rules.yml`
> SPRING BOOT: Method performs database operations but lacks @Transactional annotation

---

**`spring-missing-validation`** | WARNING | `rules\java-rules.yml`
> SPRING BOOT: Missing @Valid annotation. Always validate request bodies

---

**`spring-path-traversal`** | ERROR | `rules\java-rules.yml`
> SPRING BOOT: Path traversal risk. Sanitize user input before file operations

---

**`spring-plaintext-password`** | ERROR | `rules\java-rules.yml`
> SPRING BOOT: Plaintext password encoder detected. Use BCryptPasswordEncoder or Argon2

---

**`spring-sql-injection-native-query`** | ERROR | `rules\java-rules.yml`
> SPRING BOOT: SQL Injection risk. Use parameterized queries with setParameter()

---

**`spring-sqli`** | WARNING | `community-rules\java\spring\security\audit\spring-sqli.yaml`
> Detected a string argument from a public method contract in a raw SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) instead. You can obtain a PreparedStatement using 'connection.prepareStatement'.

---

**`spring-unvalidated-redirect`** | WARNING | `community-rules\java\spring\security\audit\spring-unvalidated-redirect.yaml`
> Application redirects a user to a destination URL specified by a user supplied parameter that is not validated.

---

**`tainted-cmd-from-http-request`** | ERROR | `community-rules\java\lang\security\audit\tainted-cmd-from-http-request.yaml`
> Detected input from a HTTPServletRequest going into a 'ProcessBuilder' or 'exec' command. This could lead to command injection if variables passed into the exec commands are not properly sanitized. Instead, avoid using these OS commands with user-supplied input, or, if you must use these commands, use a whitelist of specific values.

---

**`tainted-env-from-http-request`** | ERROR | `community-rules\java\lang\security\audit\tainted-env-from-http-request.yaml`
> Detected input from a HTTPServletRequest going into the environment variables of an 'exec' command.  Instead, call the command with user-supplied arguments by using the overloaded method with one String array as the argument. `exec({"command", "arg1", "arg2"})`.

---

**`tainted-file-path`** | ERROR | `community-rules\java\spring\security\injection\tainted-file-path.yaml`
> Detected user input controlling a file path. An attacker could control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables in file paths are sanitized. You may also consider using a utility method such as org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path.

---

**`tainted-html-string`** | ERROR | `community-rules\java\spring\security\injection\tainted-html-string.yaml`
> Detected user input flowing into a manually constructed HTML string. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross-site scripting vulnerability, which could let attackers steal sensitive user data. To be sure this is safe, check that the HTML is rendered safely. You can use the OWASP ESAPI encoder if you must render user data.

---

**`tainted-ldapi-from-http-request`** | WARNING | `community-rules\java\lang\security\audit\tainted-ldapi-from-http-request.yaml`
> Detected input from a HTTPServletRequest going into an LDAP query. This could lead to LDAP injection if the input is not properly sanitized, which could result in attackers modifying objects in the LDAP tree structure. Ensure data passed to an LDAP query is not controllable or properly sanitize the data.

---

**`tainted-session-from-http-request`** | WARNING | `community-rules\java\lang\security\audit\tainted-session-from-http-request.yaml`
> Detected input from a HTTPServletRequest going into a session command, like `setAttribute`. User input into such a command could lead to an attacker inputting malicious code into your session parameters, blurring the line between what's trusted and untrusted, and therefore leading to a trust boundary violation. This could lead to programmers trusting unvalidated data. Instead, thoroughly sanitize user input before passing it into such function calls.

---

**`tainted-sql-from-http-request`** | WARNING | `community-rules\java\lang\security\audit\sqli\tainted-sql-from-http-request.yaml`
> Detected input from a HTTPServletRequest going into a SQL sink or statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use parameterized SQL queries or properly sanitize user input instead.

---

**`tainted-sql-string`** | ERROR | `community-rules\java\aws-lambda\security\tainted-sql-string.yaml`
> Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify contents of the database. Instead, use a parameterized query which is available by default in most database engines. Alternatively, consider using an object-relational mapper (ORM) such as Sequelize which will protect your queries.

---

**`tainted-sql-string`** | ERROR | `community-rules\java\spring\security\injection\tainted-sql-string.yaml`
> User data flows into this manually-constructed SQL string. User data can be safely inserted into SQL strings using prepared statements or an object-relational mapper (ORM). Manually-constructed SQL strings is a possible indicator of SQL injection, which could let an attacker steal or manipulate data from the database. Instead, use prepared statements (`connection.PreparedStatement`) or a safe library.

---

**`tainted-sqli`** | WARNING | `community-rules\java\aws-lambda\security\tainted-sqli.yaml`
> Detected SQL statement that is tainted by `$EVENT` object. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use parameterized SQL queries or properly sanitize user input instead.

---

**`tainted-system-command`** | ERROR | `community-rules\java\spring\security\injection\tainted-system-command.yaml`
> Detected user input entering a method which executes a system command. This could result in a command injection vulnerability, which allows an attacker to inject an arbitrary system command onto the server. The attacker could download malware onto or steal data from the server. Instead, use ProcessBuilder, separating the command into individual arguments, like this: `new ProcessBuilder("ls", "-al", targetDirectory)`. Further, make sure you hardcode or allowlist the actual command so that attackers can't run arbitrary commands.

---

**`tainted-url-host`** | ERROR | `community-rules\java\spring\security\injection\tainted-url-host.yaml`
> User data flows into the host portion of this manually-constructed URL. This could allow an attacker to send data to their own server, potentially exposing sensitive data such as cookies or authorization information sent with this request. They could also probe internal servers or other resources that the server running this code can access. (This is called server-side request forgery, or SSRF.) Do not allow arbitrary hosts. Instead, create an allowlist for approved hosts, hardcode the correct host, or ensure that the user data can only affect the path or parameters.

---

**`tainted-xpath-from-http-request`** | WARNING | `community-rules\java\lang\security\audit\tainted-xpath-from-http-request.yaml`
> Detected input from a HTTPServletRequest going into a XPath evaluate or compile command. This could lead to xpath injection if variables passed into the evaluate or compile commands are not properly sanitized. Xpath injection could lead to unauthorized access to sensitive information in XML documents. Instead, thoroughly sanitize user input or use parameterized xpath queries if you can.

---

**`transformerfactory-dtds-not-disabled`** | ERROR | `community-rules\java\lang\security\audit\xxe\transformerfactory-dtds-not-disabled.yaml`
> DOCTYPE declarations are enabled for this TransformerFactory. This is vulnerable to XML external entity attacks. Disable this by setting the attributes "accessExternalDTD" and "accessExternalStylesheet" to "".

---

**`turbine-sqli`** | WARNING | `community-rules\java\lang\security\audit\sqli\turbine-sqli.yaml`
> Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) instead. You can obtain a PreparedStatement using 'connection.prepareStatement'.

---

**`unencrypted-socket`** | WARNING | `community-rules\java\lang\security\audit\crypto\unencrypted-socket.yaml`
> Detected use of a Java socket that is not encrypted. As a result, the traffic could be read by an attacker intercepting the network traffic. Use an SSLSocket created by 'SSLSocketFactory' or 'SSLServerSocketFactory' instead.

---

**`unrestricted-request-mapping`** | WARNING | `community-rules\java\spring\security\unrestricted-request-mapping.yaml`
> Detected a method annotated with 'RequestMapping' that does not specify the HTTP method. CSRF protections are not enabled for GET, HEAD, TRACE, or OPTIONS, and by default all HTTP methods are allowed when the HTTP method is not explicitly specified. This means that a method that performs state changes could be vulnerable to CSRF attacks. To mitigate, add the 'method' field and specify the HTTP method (such as 'RequestMethod.POST').

---

**`unsafe-reflection`** | WARNING | `community-rules\java\lang\security\audit\unsafe-reflection.yaml`
> If an attacker can supply values that the application then uses to determine which class to instantiate or which method to invoke, the potential exists for the attacker to create control flow paths through the application that were not intended by the application developers. This attack vector may allow the attacker to bypass authentication or access control checks or otherwise cause the application to behave in an unexpected manner.

---

**`unvalidated-redirect`** | WARNING | `community-rules\java\lang\security\audit\unvalidated-redirect.yaml`
> Application redirects to a destination URL specified by a user-supplied parameter that is not validated. This could direct users to malicious locations. Consider using an allowlist to validate URLs.

---

**`url-rewriting`** | WARNING | `community-rules\java\lang\security\audit\url-rewriting.yaml`
> URL rewriting has significant security risks. Since session ID appears in the URL, it may be easily seen by third parties.

---

**`use-escapexml`** | WARNING | `community-rules\java\lang\security\audit\xss\jsp\use-escapexml.yaml`
> Detected an Expression Language segment that does not escape output. This is dangerous because if any data in this expression can be controlled externally, it is a cross-site scripting vulnerability. Instead, use the 'escapeXml' function from the JSTL taglib. See https://www.tutorialspoint.com/jsp/jstl_function_escapexml.htm for more information.

---

**`use-jstl-escaping`** | WARNING | `community-rules\java\lang\security\audit\xss\jsp\use-jstl-escaping.yaml`
> Detected an Expression Language segment in a tag that does not escape output. This is dangerous because if any data in this expression can be controlled externally, it is a cross-site scripting vulnerability. Instead, use the 'out' tag from the JSTL taglib to escape this expression. See https://www.tutorialspoint.com/jsp/jstl_core_out_tag.htm for more information.

---

**`use-of-aes-ecb`** | WARNING | `community-rules\java\lang\security\audit\crypto\use-of-aes-ecb.yaml`
> Use of AES with ECB mode detected. ECB doesn't provide message confidentiality and  is not semantically secure so should not be used. Instead, use a strong, secure cipher: Cipher.getInstance("AES/CBC/PKCS7PADDING"). See https://owasp.org/www-community/Using_the_Java_Cryptographic_Extensions for more information.

---

**`use-of-blowfish`** | WARNING | `community-rules\java\lang\security\audit\crypto\use-of-blowfish.yaml`
> Use of Blowfish was detected. Blowfish uses a 64-bit block size that  makes it vulnerable to birthday attacks, and is therefore considered non-compliant.  Instead, use a strong, secure cipher: Cipher.getInstance("AES/CBC/PKCS7PADDING"). See https://owasp.org/www-community/Using_the_Java_Cryptographic_Extensions for more information.

---

**`use-of-default-aes`** | WARNING | `community-rules\java\lang\security\audit\crypto\use-of-default-aes.yaml`
> Use of AES with no settings detected. By default, java.crypto.Cipher uses ECB mode. ECB doesn't  provide message confidentiality and is not semantically secure so should not be used. Instead, use a strong, secure cipher: java.crypto.Cipher.getInstance("AES/CBC/PKCS7PADDING"). See https://owasp.org/www-community/Using_the_Java_Cryptographic_Extensions for more information.

---

**`use-of-md5`** | WARNING | `community-rules\java\lang\security\audit\crypto\use-of-md5.yaml`
> Detected MD5 hash algorithm which is considered insecure. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature. Use HMAC instead.

---

**`use-of-md5-digest-utils`** | WARNING | `community-rules\java\lang\security\audit\crypto\use-of-md5-digest-utils.yaml`
> Detected MD5 hash algorithm which is considered insecure. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature. Use HMAC instead.

---

**`use-of-rc2`** | WARNING | `community-rules\java\lang\security\audit\crypto\use-of-rc2.yaml`
> Use of RC2 was detected. RC2 is vulnerable to related-key attacks, and is therefore considered non-compliant. Instead, use a strong, secure cipher: Cipher.getInstance("AES/CBC/PKCS7PADDING"). See https://owasp.org/www-community/Using_the_Java_Cryptographic_Extensions for more information.

---

**`use-of-rc4`** | WARNING | `community-rules\java\lang\security\audit\crypto\use-of-rc4.yaml`
> Use of RC4 was detected. RC4 is vulnerable to several attacks, including stream cipher attacks and bit flipping attacks. Instead, use a strong, secure cipher: Cipher.getInstance("AES/CBC/PKCS7PADDING"). See https://owasp.org/www-community/Using_the_Java_Cryptographic_Extensions for more information.

---

**`use-of-sha1`** | WARNING | `community-rules\java\lang\security\audit\crypto\use-of-sha1.yaml`
> Detected SHA1 hash algorithm which is considered insecure. SHA1 is not collision resistant and is therefore not suitable as a cryptographic signature. Instead, use PBKDF2 for password hashing or SHA256 or SHA512 for other hash function applications.

---

**`use-of-sha224`** | WARNING | `community-rules\java\lang\security\audit\crypto\use-of-sha224.yaml`
> This code uses a 224-bit hash function, which is deprecated or disallowed in some security policies. Consider updating to a stronger hash function such as SHA-384 or higher to ensure compliance and security.

---

**`use-of-weak-rsa-key`** | WARNING | `community-rules\java\lang\security\audit\crypto\weak-rsa.yaml`
> RSA keys should be at least 2048 bits based on NIST recommendation.

---

**`use-snakeyaml-constructor`** | WARNING | `community-rules\java\lang\security\use-snakeyaml-constructor.yaml`
> Used SnakeYAML org.yaml.snakeyaml.Yaml() constructor with no arguments, which is vulnerable to deserialization attacks. Use the one-argument Yaml(...) constructor instead, with SafeConstructor or a custom Constructor as the argument.

---

**`vertx-sqli`** | WARNING | `community-rules\java\lang\security\audit\sqli\vertx-sqli.yaml`
> Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) instead. You can obtain a PreparedStatement using 'connection.prepareStatement'.

---

**`weak-random`** | WARNING | `community-rules\java\lang\security\audit\crypto\weak-random.yaml`
> Detected use of the functions `Math.random()` or `java.util.Random()`. These are both not cryptographically strong random number generators (RNGs). If you are using these RNGs to create passwords or secret tokens, use `java.security.SecureRandom` instead.

---

**`weak-ssl-context`** | WARNING | `community-rules\java\lang\security\audit\weak-ssl-context.yaml`
> An insecure SSL context was detected. TLS versions 1.0, 1.1, and all SSL versions are considered weak encryption and are deprecated. Use SSLContext.getInstance("TLSv1.2") for the best security.

---

**`xml-decoder`** | WARNING | `community-rules\java\lang\security\audit\xml-decoder.yaml`
> XMLDecoder should not be used to parse untrusted data. Deserializing user input can lead to arbitrary code execution. Use an alternative and explicitly disable external entities. See https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html for alternatives and vulnerability prevention.

---

**`xmlinputfactory-external-entities-enabled`** | ERROR | `community-rules\java\lang\security\xmlinputfactory-external-entities-enabled.yaml`
> XML external entities are enabled for this XMLInputFactory. This is vulnerable to XML external entity attacks. Disable external entities by setting "javax.xml.stream.isSupportingExternalEntities" to false.

---

**`xmlinputfactory-possible-xxe`** | WARNING | `community-rules\java\lang\security\xmlinputfactory-possible-xxe.yaml`
> XML external entities are not explicitly disabled for this XMLInputFactory. This could be vulnerable to XML external entity vulnerabilities. Explicitly disable external entities by setting "javax.xml.stream.isSupportingExternalEntities" to false.

---

**`xssrequestwrapper-is-insecure`** | WARNING | `community-rules\java\lang\security\audit\xssrequestwrapper-is-insecure.yaml`
> It looks like you're using an implementation of XSSRequestWrapper from dzone. (https://www.javacodegeeks.com/2012/07/anti-cross-site-scripting-xss-filter.html) The XSS filtering in this code is not secure and can be bypassed by malicious actors. It is recommended to use a stack that automatically escapes in your view or templates instead of filtering yourself.

---

## Javascript (236 rules)

**`aead-no-final`** | ERROR | `community-rules\javascript\node-crypto\security\aead-no-final.yaml`
> The 'final' call of a Decipher object checks the authentication tag in a mode for authenticated encryption. Failing to call 'final' will invalidate all integrity guarantees of the released ciphertext.

---

**`ajv-allerrors-true`** | WARNING | `community-rules\javascript\ajv\security\audit\ajv-allerrors-true.yaml`
> By setting `allErrors: true` in `Ajv` library, all error objects will be allocated without limit. This allows the attacker to produce a huge number of errors which can lead to denial of service. Do not use `allErrors: true` in production.

---

**`apollo-axios-ssrf`** | WARNING | `community-rules\javascript\apollo\security\apollo-axios-ssrf.yaml`
> User-controllable argument $DATAVAL to $METHOD passed to Axios via internal handler $INNERFUNC. This could be a server-side request forgery. A user could call a restricted API or leak internal headers to an unauthorized party. Validate your user arguments against an allowlist of known URLs, or consider refactoring so that user-controlled data is not necessary.

---

**`assigned-undefined`** | WARNING | `community-rules\javascript\lang\best-practice\assigned-undefined.yaml`
> `undefined` is not a reserved keyword in Javascript, so this is "valid" Javascript but highly confusing and likely to result in bugs.

---

**`avoid-v-html`** | WARNING | `community-rules\javascript\vue\security\audit\xss\templates\avoid-v-html.yaml`
> Dynamically rendering arbitrary HTML on your website can be very dangerous because it can easily lead to XSS vulnerabilities. Only use HTML interpolation on trusted content and never on user-provided content.

---

**`calling-set-state-on-current-state`** | ERROR | `community-rules\javascript\react\correctness\hooks\set-state-no-op.yaml`
> Calling setState on the current state is always a no-op. Did you mean to change the state like $Y(!$X) instead?

---

**`chrome-remote-interface-compilescript-injection`** | WARNING | `community-rules\javascript\chrome-remote-interface\security\audit\chrome-remote-interface-compilescript-injection.yaml`
> If unverified user data can reach the `compileScript` method it can result in Server-Side Request Forgery vulnerabilities

---

**`code-string-concat`** | ERROR | `community-rules\javascript\lang\security\audit\code-string-concat.yaml`
> Found data from an Express or Next web request flowing to `eval`. If this data is user-controllable this can lead to execution of arbitrary system commands in the context of your application process. Avoid `eval` whenever possible.

---

**`cors-misconfiguration`** | WARNING | `community-rules\javascript\express\security\cors-misconfiguration.yaml`
> By letting user input control CORS parameters, there is a risk that software does not properly verify that the source of data or communication is valid. Use literal values for CORS settings.

---

**`create-de-cipher-no-iv`** | ERROR | `community-rules\javascript\node-crypto\security\create-de-cipher-no-iv.yaml`
> The deprecated functions 'createCipher' and 'createDecipher' generate the same initialization vector every time. For counter modes such as CTR, GCM, or CCM this leads to break of both confidentiality and integrity, if the key is used more than once. Other modes are still affected in their strength, though they're not completely broken. Use 'createCipheriv' or 'createDecipheriv' instead.

---

**`dangerous-spawn-shell`** | ERROR | `community-rules\javascript\lang\security\audit\dangerous-spawn-shell.yaml`
> Detected non-literal calls to $EXEC(). This could lead to a command injection vulnerability.

---

**`deno-dangerous-run`** | ERROR | `community-rules\javascript\deno\security\audit\deno-dangerous-run.yaml`
> Detected non-literal calls to Deno.run(). This could lead to a command injection vulnerability.

---

**`detect-angular-element-methods`** | INFO | `community-rules\javascript\angular\security\detect-angular-element-methods.yaml`
> Use of angular.element can lead to XSS if user-input is treated as part of the HTML element within `$SINK`. It is recommended to contextually output encode user-input, before inserting into `$SINK`. If the HTML needs to be preserved it is recommended to sanitize the input using $sce.getTrustedHTML or $sanitize.

---

**`detect-angular-element-taint`** | WARNING | `community-rules\javascript\angular\security\detect-angular-element-taint.yaml`
> Use of angular.element can lead to XSS if user-input is treated as part of the HTML element within `$SINK`. It is recommended to contextually output encode user-input, before inserting into `$SINK`. If the HTML needs to be preserved it is recommended to sanitize the input using $sce.getTrustedHTML or $sanitize.

---

**`detect-angular-open-redirect`** | ERROR | `community-rules\javascript\angular\security\detect-angular-open-redirect.yaml`
> Use of $window.location.href can lead to open-redirect if user input is used for redirection.

---

**`detect-angular-resource-loading`** | WARNING | `community-rules\javascript\angular\security\detect-angular-resource-loading.yaml`
> $sceDelegateProvider allowlisting can introduce security issues if wildcards are used.

---

**`detect-angular-sce-disabled`** | ERROR | `community-rules\javascript\angular\security\detect-angular-sce-disabled.yaml`
> $sceProvider is set to false. Disabling Strict Contextual escaping (SCE) in an AngularJS application could provide additional attack surface for XSS vulnerabilities.

---

**`detect-angular-translateprovider-translations-method`** | WARNING | `community-rules\javascript\angular\security\detect-third-party-angular-translate.yaml`
> The use of $translateProvider.translations method can be dangerous if user input is provided to this API.

---

**`detect-angular-trust-as-css-method`** | WARNING | `community-rules\javascript\angular\security\detect-angular-trust-as-css.yaml`
> The use of $sce.trustAsCss can be dangerous if unsanitized user input flows through this API.

---

**`detect-angular-trust-as-html-method`** | WARNING | `community-rules\javascript\angular\security\detect-angular-trust-as-html-method.yaml`
> The use of $sce.trustAsHtml can be dangerous if unsanitized user input flows through this API.

---

**`detect-angular-trust-as-js-method`** | WARNING | `community-rules\javascript\angular\security\detect-angular-trust-as-js-method.yaml`
> The use of $sce.trustAsJs can be dangerous if unsanitized user input flows through this API.

---

**`detect-angular-trust-as-method`** | WARNING | `community-rules\javascript\angular\security\detect-angular-trust-as-method.yaml`
> The use of $sce.trustAs can be dangerous if unsanitized user input flows through this API.

---

**`detect-angular-trust-as-resourceurl-method`** | WARNING | `community-rules\javascript\angular\security\detect-angular-trust-as-resourceurl-method.yaml`
> The use of $sce.trustAsResourceUrl can be dangerous if unsanitized user input flows through this API.

---

**`detect-angular-trust-as-url-method`** | WARNING | `community-rules\javascript\angular\security\detect-angular-trust-as-url-method.yaml`
> The use of $sce.trustAsUrl can be dangerous if unsanitized user input flows through this API.

---

**`detect-buffer-noassert`** | WARNING | `community-rules\javascript\lang\security\detect-buffer-noassert.yaml`
> Detected usage of noassert in Buffer API, which allows the offset the be beyond the end of the buffer. This could result in writing or reading beyond the end of the buffer.

---

**`detect-child-process`** | ERROR | `community-rules\javascript\aws-lambda\security\detect-child-process.yaml`
> Allowing spawning arbitrary programs or running shell processes with arbitrary arguments may end up in a command injection vulnerability. Try to avoid non-literal values for the command string. If it is not possible, then do not let running arbitrary commands, use a white list for inputs.

---

**`detect-child-process`** | ERROR | `community-rules\javascript\lang\security\detect-child-process.yaml`
> Detected calls to child_process from a function argument `$FUNC`. This could lead to a command injection if the input is user controllable. Try to avoid calls to child_process, and if it is needed ensure user input is correctly sanitized or sandboxed. 

---

**`detect-disable-mustache-escape`** | WARNING | `community-rules\javascript\lang\security\detect-disable-mustache-escape.yaml`
> Markup escaping disabled. This can be used with some template engines to escape disabling of HTML entities, which can lead to XSS attacks.

---

**`detect-eval-with-expression`** | WARNING | `community-rules\javascript\lang\security\detect-eval-with-expression.yaml`
> Detected use of dynamic execution of JavaScript which may come from user-input, which can lead to Cross-Site-Scripting (XSS). Where possible avoid including user-input in functions which dynamically execute user-input.

---

**`detect-insecure-websocket`** | ERROR | `community-rules\javascript\lang\security\detect-insecure-websocket.yaml`
> Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.

---

**`detect-no-csrf-before-method-override`** | WARNING | `community-rules\javascript\lang\security\detect-no-csrf-before-method-override.yaml`
> Detected use of express.csrf() middleware before express.methodOverride(). This can allow GET requests (which are not checked by csrf) to turn into POST requests later.

---

**`detect-non-literal-fs-filename`** | WARNING | `community-rules\javascript\lang\security\audit\detect-non-literal-fs-filename.yaml`
> Detected that function argument `$ARG` has entered the fs module. An attacker could potentially control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables in file paths are validated.

---

**`detect-non-literal-regexp`** | WARNING | `community-rules\javascript\lang\security\audit\detect-non-literal-regexp.yaml`
> RegExp() called with a `$ARG` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

---

**`detect-non-literal-require`** | WARNING | `community-rules\javascript\lang\security\audit\detect-non-literal-require.yaml`
> Detected the use of require(variable). Calling require with a non-literal argument might allow an attacker to load and run arbitrary code, or access arbitrary files.

---

**`detect-pseudoRandomBytes`** | WARNING | `community-rules\javascript\lang\security\detect-pseudoRandomBytes.yaml`
> Detected usage of crypto.pseudoRandomBytes, which does not produce secure random numbers.

---

**`detect-redos`** | WARNING | `community-rules\javascript\lang\security\audit\detect-redos.yaml`
> Detected the use of a regular expression `$REDOS` which appears to be vulnerable to a Regular expression Denial-of-Service (ReDoS). For this reason, it is recommended to review the regex and ensure it is not vulnerable to catastrophic backtracking, and if possible use a library which offers default safety against ReDoS vulnerabilities.

---

**`detect-replaceall-sanitization`** | INFO | `community-rules\javascript\audit\detect-replaceall-sanitization.yaml`
> Detected a call to `$FUNC()` in an attempt to HTML escape the string `$STR`. Manually sanitizing input through a manually built list can be circumvented in many situations, and it's better to use a well known sanitization library such as `sanitize-html` or `DOMPurify`.

---

**`direct-response-write`** | WARNING | `community-rules\javascript\express\security\audit\xss\direct-response-write.yaml`
> Detected directly writing to a Response object from user-defined input. This bypasses any HTML escaping and may expose your application to a Cross-Site-scripting (XSS) vulnerability. Instead, use 'resp.render()' to render safely escaped HTML.

---

**`dom-based-xss`** | ERROR | `community-rules\javascript\browser\security\dom-based-xss.yaml`
> Detected possible DOM-based XSS. This occurs because a portion of the URL is being used to construct an element added directly to the page. For example, a malicious actor could send someone a link like this: http://www.some.site/page.html?default=<script>alert(document.cookie)</script> which would add the script to the page. Consider allowlisting appropriate values or using an approach which does not involve the URL.

---

**`dynamodb-request-object`** | ERROR | `community-rules\javascript\aws-lambda\security\dynamodb-request-object.yaml`
> Detected DynamoDB query params that are tainted by `$EVENT` object. This could lead to NoSQL injection if the variable is user-controlled and not properly sanitized. Explicitly assign query params instead of passing data from `$EVENT` directly to DynamoDB client.

---

**`eqeq-is-bad`** | INFO | `community-rules\javascript\lang\correctness\useless-eqeq.yaml`
> Detected a useless comparison operation `$X == $X` or `$X != $X`. This operation is always true. If testing for floating point NaN, use `math.isnan`, or `cmath.isnan` if the number is complex.

---

**`escape-function-overwrite`** | WARNING | `community-rules\javascript\express\security\audit\xss\mustache\escape-function-overwrite.yaml`
> The Mustache escape function is being overwritten. This could bypass HTML escaping safety measures built into the rendering engine, exposing your application to cross-site scripting (XSS) vulnerabilities. If you need unescaped HTML, use the triple brace operator in your template: '{{{ ... }}}'.

---

**`eval-detected`** | WARNING | `community-rules\javascript\browser\security\eval-detected.yaml`
> Detected the use of eval(). eval() can be dangerous if used to evaluate dynamic content. If this content can be input from outside the program, this may be a code injection vulnerability. Ensure evaluated content is not definable by external sources.

---

**`expat-xxe`** | WARNING | `community-rules\javascript\node-expat\security\audit\expat-xxe.yaml`
> If unverified user data can reach the XML Parser it can result in XML External or Internal Entity (XXE) Processing vulnerabilities

---

**`express-check-csurf-middleware-usage`** | INFO | `community-rules\javascript\express\security\audit\express-check-csurf-middleware-usage.yaml`
> A CSRF middleware was not detected in your express application. Ensure you are either using one such as `csurf` or `csrf` (see rule references) and/or you are properly doing CSRF validation in your routes with a token or cookies.

---

**`express-check-directory-listing`** | WARNING | `community-rules\javascript\express\security\audit\express-check-directory-listing.yaml`
> Directory listing/indexing is enabled, which may lead to disclosure of sensitive directories and files. It is recommended to disable directory listing unless it is a public resource. If you need directory listing, ensure that sensitive files are inaccessible when querying the resource.

---

**`express-cookie-session-default-name`** | WARNING | `community-rules\javascript\express\security\audit\express-cookie-settings.yaml`
> Don’t use the default session cookie name Using the default session cookie name can open your app to attacks. The security issue posed is similar to X-Powered-By: a potential attacker can use it to fingerprint the server and target attacks accordingly.

---

**`express-cookie-session-no-domain`** | WARNING | `community-rules\javascript\express\security\audit\express-cookie-settings.yaml`
> Default session middleware settings: `domain` not set. It indicates the domain of the cookie; use it to compare against the domain of the server in which the URL is being requested. If they match, then check the path attribute next.

---

**`express-cookie-session-no-expires`** | WARNING | `community-rules\javascript\express\security\audit\express-cookie-settings.yaml`
> Default session middleware settings: `expires` not set. Use it to set expiration date for persistent cookies.

---

**`express-cookie-session-no-httponly`** | WARNING | `community-rules\javascript\express\security\audit\express-cookie-settings.yaml`
> Default session middleware settings: `httpOnly` not set. It ensures the cookie is sent only over HTTP(S), not client JavaScript, helping to protect against cross-site scripting attacks.

---

**`express-cookie-session-no-path`** | WARNING | `community-rules\javascript\express\security\audit\express-cookie-settings.yaml`
> Default session middleware settings: `path` not set. It indicates the path of the cookie; use it to compare against the request path. If this and domain match, then send the cookie in the request.

---

**`express-cookie-session-no-secure`** | WARNING | `community-rules\javascript\express\security\audit\express-cookie-settings.yaml`
> Default session middleware settings: `secure` not set. It ensures the browser only sends the cookie over HTTPS.

---

**`express-data-exfiltration`** | WARNING | `community-rules\javascript\express\security\express-data-exfiltration.yaml`
> Depending on the context, user control data in `Object.assign` can cause web response to include data that it should not have or can lead to a mass assignment vulnerability.

---

**`express-detect-notevil-usage`** | WARNING | `community-rules\javascript\express\security\audit\express-detect-notevil-usage.yaml`
> Detected usage of the `notevil` package, which is unmaintained and has vulnerabilities. Using any sort of `eval()` functionality can be very dangerous, but if you must, the `eval` package is an up to date alternative. Be sure that only trusted input reaches an `eval()` function.

---

**`express-expat-xxe`** | ERROR | `community-rules\javascript\express\security\express-expat-xxe.yaml`
> Make sure that unverified user data can not reach the XML Parser, as it can result in XML External or Internal Entity (XXE) Processing vulnerabilities.

---

**`express-insecure-template-usage`** | WARNING | `community-rules\javascript\express\security\express-insecure-template-usage.yaml`
> User data from `$REQ` is being compiled into the template, which can lead to a Server Side Template Injection (SSTI) vulnerability.

---

**`express-jwt-hardcoded-secret`** | WARNING | `community-rules\javascript\express\security\express-jwt-hardcoded-secret.yaml`
> A hard-coded credential was detected. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`express-jwt-not-revoked`** | WARNING | `community-rules\javascript\express\security\audit\express-jwt-not-revoked.yaml`
> No token revoking configured for `express-jwt`. A leaked token could still be used and unable to be revoked. Consider using function as the `isRevoked` option.

---

**`express-libxml-noent`** | ERROR | `community-rules\javascript\express\security\audit\express-libxml-noent.yaml`
> The libxml library processes user-input with the `noent` attribute is set to `true` which can lead to being vulnerable to XML External Entities (XXE) type attacks. It is recommended to set `noent` to `false` when using this feature to ensure you are protected.

---

**`express-libxml-vm-noent`** | WARNING | `community-rules\javascript\express\security\audit\express-libxml-vm-noent.yaml`
> Detected use of parseXml() function with the `noent` field set to `true`. This can lead to an XML External Entities (XXE) attack if untrusted data is passed into it.

---

**`express-open-redirect`** | WARNING | `community-rules\javascript\express\security\audit\express-open-redirect.yaml`
> The application redirects to a URL specified by user-supplied input `$REQ` that is not validated. This could redirect users to malicious locations. Consider using an allow-list approach to validate URLs, or warn users they are being redirected to a third-party website.

---

**`express-path-join-resolve-traversal`** | WARNING | `community-rules\javascript\express\security\audit\express-path-join-resolve-traversal.yaml`
> Possible writing outside of the destination, make sure that the target path is nested in the intended destination

---

**`express-phantom-injection`** | ERROR | `community-rules\javascript\express\security\express-phantom-injection.yaml`
> If unverified user data can reach the `phantom` methods it can result in Server-Side Request Forgery vulnerabilities

---

**`express-puppeteer-injection`** | ERROR | `community-rules\javascript\express\security\express-puppeteer-injection.yaml`
> If unverified user data can reach the `puppeteer` methods it can result in Server-Side Request Forgery vulnerabilities

---

**`express-res-sendfile`** | WARNING | `community-rules\javascript\express\security\audit\express-res-sendfile.yaml`
> The application processes user-input, this is passed to res.sendFile which can allow an attacker to arbitrarily read files on the system through path traversal. It is recommended to perform input validation in addition to canonicalizing the path. This allows you to validate the path against the intended directory it should be accessing.

---

**`express-sandbox-code-injection`** | ERROR | `community-rules\javascript\express\security\express-sandbox-injection.yaml`
> Make sure that unverified user data can not reach `sandbox`.

---

**`express-sequelize-injection`** | ERROR | `community-rules\javascript\sequelize\security\audit\sequelize-injection-express.yaml`
> Detected a sequelize statement that is tainted by user-input. This could lead to SQL injection if the variable is user-controlled and is not properly sanitized. In order to prevent SQL injection, it is recommended to use parameterized queries or prepared statements.

---

**`express-session-hardcoded-secret`** | WARNING | `community-rules\javascript\express\security\audit\express-session-hardcoded-secret.yaml`
> A hard-coded credential was detected. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`express-ssrf`** | WARNING | `community-rules\javascript\express\security\audit\express-ssrf.yaml`
> The following request $REQUEST.$METHOD() was found to be crafted from user-input `$REQ` which can lead to Server-Side Request Forgery (SSRF) vulnerabilities. It is recommended where possible to not allow user-input to craft the base request, but to be treated as part of the path or query parameter. When user-input is necessary to craft the request, it is recommeneded to follow OWASP best practices to prevent abuse. 

---

**`express-third-party-object-deserialization`** | WARNING | `community-rules\javascript\express\security\audit\express-third-party-object-deserialization.yaml`
> The following function call $SER.$FUNC accepts user controlled data which can result in Remote Code Execution (RCE) through Object Deserialization. It is recommended to use secure data processing alternatives such as JSON.parse() and Buffer.from().

---

**`express-vm-injection`** | ERROR | `community-rules\javascript\express\security\express-vm-injection.yaml`
> Make sure that unverified user data can not reach `$VM`.

---

**`express-vm2-injection`** | WARNING | `community-rules\javascript\express\security\express-vm2-injection.yaml`
> Make sure that unverified user data can not reach `vm2`.

---

**`express-wkhtmltoimage-injection`** | ERROR | `community-rules\javascript\express\security\express-wkhtml-injection.yaml`
> If unverified user data can reach the `phantom` methods it can result in Server-Side Request Forgery vulnerabilities

---

**`express-wkhtmltopdf-injection`** | ERROR | `community-rules\javascript\express\security\express-wkhtml-injection.yaml`
> If unverified user data can reach the `wkhtmltopdf` methods it can result in Server-Side Request Forgery vulnerabilities

---

**`express-xml2json-xxe`** | ERROR | `community-rules\javascript\express\security\express-xml2json-xxe.yaml`
> Make sure that unverified user data can not reach the XML Parser, as it can result in XML External or Internal Entity (XXE) Processing vulnerabilities

---

**`express-xml2json-xxe-event`** | WARNING | `community-rules\javascript\express\security\audit\express-xml2json-xxe-event.yaml`
> Xml Parser is used inside Request Event. Make sure that unverified user data can not reach the XML Parser, as it can result in XML External or Internal Entity (XXE) Processing vulnerabilities

---

**`gcm-no-tag-length`** | ERROR | `community-rules\javascript\node-crypto\security\gcm-no-tag-length.yaml`
> The call to 'createDecipheriv' with the Galois Counter Mode (GCM) mode of operation is missing an expected authentication tag length. If the expected authentication tag length is not specified or otherwise checked, the application might be tricked into verifying a shorter-than-expected authentication tag. This can be abused by an attacker to spoof ciphertexts or recover the implicit authentication key of GCM, allowing arbitrary forgeries.

---

**`grpc-nodejs-insecure-connection`** | ERROR | `community-rules\javascript\grpc\security\grpc-nodejs-insecure-connection.yaml`
> Found an insecure gRPC connection. This creates a connection without encryption to a gRPC client/server. A malicious attacker could tamper with the gRPC message, which could compromise the machine.

---

**`hardcoded-hmac-key`** | WARNING | `community-rules\javascript\lang\security\audit\hardcoded-hmac-key.yaml`
> Detected a hardcoded hmac key. Avoid hardcoding secrets and consider using an alternate option such as reading the secret from a config file or using an environment variable.

---

**`hardcoded-jwt-secret`** | WARNING | `community-rules\javascript\jose\security\jwt-hardcode.yaml`
> A hard-coded credential was detected. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`hardcoded-jwt-secret`** | WARNING | `community-rules\javascript\jsonwebtoken\security\jwt-hardcode.yaml`
> A hard-coded credential was detected. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`hardcoded-passport-secret`** | WARNING | `community-rules\javascript\passport-jwt\security\passport-hardcode.yaml`
> A hard-coded credential was detected. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`html-in-template-string`** | WARNING | `community-rules\javascript\lang\security\html-in-template-string.yaml`
> This template literal looks like HTML and has interpolated variables. These variables are not HTML-encoded by default. If the variables contain HTML tags, these may be interpreted by the browser, resulting in cross-site scripting (XSS).

---

**`incomplete-sanitization`** | WARNING | `community-rules\javascript\lang\security\audit\incomplete-sanitization.yaml`
> `$STR.replace` method will only replace the first occurrence when used with a string argument ($CHAR). If this method is used for escaping of dangerous data then there is a possibility for a bypass. Try to use sanitization library instead or use a Regex with a global flag.

---

**`insecure-createnodesfrommarkup`** | WARNING | `community-rules\javascript\fbjs\security\audit\insecure-createnodesfrommarkup.yaml`
> User controlled data in a `createNodesFromMarkup` is an anti-pattern that can lead to XSS vulnerabilities

---

**`insecure-document-method`** | ERROR | `community-rules\javascript\browser\security\insecure-document-method.yaml`
> User controlled data in methods like `innerHTML`, `outerHTML` or `document.write` is an anti-pattern that can lead to XSS vulnerabilities

---

**`insecure-innerhtml`** | ERROR | `community-rules\javascript\browser\security\insecure-innerhtml.yaml`
> User controlled data in a `$EL.innerHTML` is an anti-pattern that can lead to XSS vulnerabilities

---

**`insecure-object-assign`** | WARNING | `community-rules\javascript\lang\security\insecure-object-assign.yaml`
> Depending on the context, user control data in `Object.assign` can cause web response to include data that it should not have or can lead to a mass assignment vulnerability.

---

**`insufficient-postmessage-origin-validation`** | WARNING | `community-rules\javascript\browser\security\insufficient-postmessage-origin-validation.yaml`
> No validation of origin is done by the addEventListener API. It may be possible to exploit this flaw to perform Cross Origin attacks such as Cross-Site Scripting(XSS).

---

**`intercom-settings-user-identifier-without-user-hash`** | WARNING | `community-rules\javascript\intercom\security\audit\intercom-settings-user-identifier-without-user-hash.yaml`
> Found an initialization of the Intercom Messenger that identifies a User, but does not specify a `user_hash`. This configuration allows users to impersonate one another. See the Intercom Identity Verification docs for more context https://www.intercom.com/help/en/articles/183-set-up-identity-verification-for-web-and-mobile

---

**`javascript-alert`** | WARNING | `community-rules\javascript\lang\best-practice\leftover_debugging.yaml`
> found alert() call; should this be in production code?

---

**`javascript-avoid-eval`** | WARNING | `rules\javascript-rules-original-backup.yml`
> Avoid using eval() as it can pose a security risk by allowing arbitrary code execution. Consider using a safer alternative, such as JSON.parse() for parsing JSON data.

---

**`javascript-confirm`** | WARNING | `community-rules\javascript\lang\best-practice\leftover_debugging.yaml`
> found confirm() call; should this be in production code?

---

**`javascript-debugger`** | WARNING | `community-rules\javascript\lang\best-practice\leftover_debugging.yaml`
> found debugger call; should this be in production code?

---

**`javascript-hardcoded-api-key`** | WARNING | `rules\javascript-rules-original-backup.yml`
> Hardcoded API keys are a security risk. Consider using environment variables or a secure secrets management system to store sensitive credentials

---

**`javascript-insecure-cors`** | ERROR | `rules\javascript-rules-original-backup.yml`
> Insecure CORS configuration. Use literal values for CORS settings instead of user input to prevent security vulnerabilities.

---

**`javascript-prompt`** | WARNING | `community-rules\javascript\lang\best-practice\leftover_debugging.yaml`
> found prompt() call; should this be in production code?

---

**`javascript-rule-1-avoid-string-arguments`** | WARNING | `rules\javascript-rules-original-backup.yml`
> Rule 1: Avoid using string arguments in setTimeout/setInterval as they can lead to code injection, use function references instead

---

**`javascript-rule-1-object-mutability`** | WARNING | `rules\javascript-rules-original-backup.yml`
> Rule 1: Avoid mutating objects by reassigning or using Object.assign, instead create a new object to prevent unintended side effects

---

**`jose-exposed-data`** | WARNING | `community-rules\javascript\jose\security\audit\jose-exposed-data.yaml`
> The object is passed strictly to jose.JWT.sign(...) Make sure that sensitive information is not exposed through JWT token payload.

---

**`jquery-insecure-method`** | WARNING | `community-rules\javascript\jquery\security\audit\jquery-insecure-method.yaml`
> User controlled data in a jQuery's `.$METHOD(...)` is an anti-pattern that can lead to XSS vulnerabilities

---

**`jquery-insecure-selector`** | WARNING | `community-rules\javascript\jquery\security\audit\jquery-insecure-selector.yaml`
> User controlled data in a `$(...)` is an anti-pattern that can lead to XSS vulnerabilities

---

**`js-open-redirect`** | WARNING | `community-rules\javascript\browser\security\open-redirect.yaml`
> The application accepts potentially user-controlled input `$PROP` which can control the location of the current window context. This can lead two types of vulnerabilities open-redirection and Cross-Site-Scripting (XSS) with JavaScript URIs. It is recommended to validate user-controllable input before allowing it to control the redirection.

---

**`js-open-redirect-from-function`** | INFO | `community-rules\javascript\browser\security\open-redirect-from-function.yaml`
> The application accepts potentially user-controlled input `$PROP` which can control the location of the current window context. This can lead two types of vulnerabilities open-redirection and Cross-Site-Scripting (XSS) with JavaScript URIs. It is recommended to validate user-controllable input before allowing it to control the redirection.

---

**`js-rule-1-strict-equality-check`** | WARNING | `rules\javascript-rules-original-backup.yml`
> Rule 1: Use strict equality (===) instead of == to prevent unexpected type coercion

---

**`js-rule-1-strict-equality-check`** | WARNING | `rules\javascript-rules.yml`
> Rule 1: Use strict equality (===) instead of == to prevent unexpected type coercion

---

**`js-rule-1-strict-inequality-check`** | WARNING | `rules\javascript-rules-original-backup.yml`
> Rule 1: Use strict inequality (!==) instead of != to prevent unexpected type coercion

---

**`js-rule-1-strict-inequality-check`** | WARNING | `rules\javascript-rules.yml`
> Rule 1: Use strict inequality (!==) instead of != to prevent unexpected type coercion

---

**`js-rule-10-missing-validation`** | WARNING | `rules\javascript-rules-original-backup.yml`
> Rule 10: Validate inputs before using them. Check for null/undefined and validate data types

---

**`js-rule-10-missing-validation-db`** | WARNING | `rules\javascript-rules.yml`
> Rule 10: Validate inputs before database operations. Check for null/undefined and validate data types

---

**`js-rule-11-no-param-mutation`** | WARNING | `rules\javascript-rules-original-backup.yml`
> Rule 11: Do not modify function parameters. Return new objects to avoid side effects

---

**`js-rule-11-no-param-mutation`** | WARNING | `rules\javascript-rules.yml`
> Rule 11: Do not modify function parameters. Return new objects to avoid side effects

---

**`js-rule-12-no-eval`** | ERROR | `rules\javascript-rules-original-backup.yml`
> Rule 12: Never use eval(). It executes arbitrary code and is a major security risk

---

**`js-rule-12-no-eval`** | ERROR | `rules\javascript-rules.yml`
> Rule 12: Never use eval() or Function constructor. They execute arbitrary code and are major security risks

---

**`js-rule-13-no-innerhtml`** | ERROR | `rules\javascript-rules-original-backup.yml`
> Rule 13: Avoid innerHTML with user data. Use textContent or sanitize input to prevent XSS attacks

---

**`js-rule-13-no-innerhtml`** | ERROR | `rules\javascript-rules.yml`
> Rule 13: Avoid innerHTML with user data. Use textContent or sanitize input to prevent XSS attacks

---

**`js-rule-14-parseint-radix`** | WARNING | `rules\javascript-rules-original-backup.yml`
> Rule 14: Always specify radix in parseInt(). Use parseInt(value, 10) for decimal numbers

---

**`js-rule-14-parseint-radix`** | WARNING | `rules\javascript-rules.yml`
> Rule 14: Always specify radix in parseInt(). Use parseInt(value, 10) for decimal numbers

---

**`js-rule-15-no-async-foreach`** | ERROR | `rules\javascript-rules-original-backup.yml`
> Rule 15: Avoid async inside forEach. Use for...of loop or Promise.all() with map()

---

**`js-rule-15-no-async-foreach`** | ERROR | `rules\javascript-rules.yml`
> Rule 15: Avoid async inside forEach. Use for...of loop or Promise.all() with map()

---

**`js-rule-18-default-params`** | INFO | `rules\javascript-rules-original-backup.yml`
> Rule 18: Use default parameters instead of manual checks (e.g., function log(level = 'info'))

---

**`js-rule-18-default-params`** | INFO | `rules\javascript-rules.yml`
> Rule 18: Use default parameters instead of manual checks (e.g., function log(level = 'info'))

---

**`js-rule-19-reduce-nesting`** | INFO | `rules\javascript-rules-original-backup.yml`
> Rule 19: Reduce nested code. Use early returns to improve readability

---

**`js-rule-19-reduce-nesting`** | INFO | `rules\javascript-rules.yml`
> Rule 19: Reduce nested code. Use early returns to improve readability

---

**`js-rule-2-no-var`** | ERROR | `rules\javascript-rules-original-backup.yml`
> Rule 2: Never use 'var'. Use 'const' or 'let' to avoid scope and hoisting issues

---

**`js-rule-2-no-var`** | ERROR | `rules\javascript-rules.yml`
> Rule 2: Never use 'var'. Use 'const' or 'let' to avoid scope and hoisting issues

---

**`js-rule-20-single-responsibility`** | WARNING | `rules\javascript-rules-original-backup.yml`
> Rule 20: One function should do one thing. Break down large functions following Single Responsibility Principle

---

**`js-rule-20-single-responsibility`** | WARNING | `rules\javascript-rules.yml`
> Rule 20: One function should do one thing. Break down large functions following Single Responsibility Principle

---

**`js-rule-21-class-naming-pascalcase`** | WARNING | `rules\javascript-rules-original-backup.yml`
> Rule 21: Class names should use PascalCase (e.g., UserProfile, not userProfile or user_profile)

---

**`js-rule-21-class-naming-pascalcase`** | WARNING | `rules\javascript-rules.yml`
> Rule 21: Class names should use PascalCase (e.g., UserProfile, not userProfile or user_profile)

---

**`js-rule-22-function-naming-camelcase`** | WARNING | `rules\javascript-rules-original-backup.yml`
> Rule 22: Function names should use camelCase (e.g., calculateTotal, not CalculateTotal or calculate_total)

---

**`js-rule-22-function-naming-camelcase`** | WARNING | `rules\javascript-rules.yml`
> Rule 22: Function names should use camelCase (e.g., calculateTotal, not CalculateTotal or calculate_total)

---

**`js-rule-23-variable-naming-camelcase`** | INFO | `rules\javascript-rules-original-backup.yml`
> Rule 23: Variable names should use camelCase (e.g., userName, not user_name or UserName)

---

**`js-rule-24-constant-naming-uppercase`** | INFO | `rules\javascript-rules-original-backup.yml`
> Rule 24: Constants should use UPPER_CASE with underscores (e.g., MAX_RETRIES, API_KEY, not maxRetries or apiKey for true constants)

---

**`js-rule-25-no-single-letter-vars`** | INFO | `rules\javascript-rules-original-backup.yml`
> Rule 25: Avoid single-letter variable names except for loop counters (i, j, k). Use descriptive names

---

**`js-rule-25-no-single-letter-vars`** | INFO | `rules\javascript-rules.yml`
> Rule 25: Avoid single-letter variable names except for loop counters (i, j, k). Use descriptive names

---

**`js-rule-3-prefer-const`** | INFO | `rules\javascript-rules-original-backup.yml`
> Rule 3: Prefer 'const' over 'let' to prevent accidental reassignment (use let only if reassignment is needed)

---

**`js-rule-3-prefer-const`** | INFO | `rules\javascript-rules.yml`
> Rule 3: Prefer 'const' over 'let' when variable is never reassigned

---

**`js-rule-5-empty-catch`** | ERROR | `rules\javascript-rules-original-backup.yml`
> Rule 5: Always handle errors. Never leave catch blocks empty - log errors or rethrow them

---

**`js-rule-5-empty-catch`** | ERROR | `rules\javascript-rules.yml`
> Rule 5: Always handle errors. Never leave catch blocks empty - log errors or rethrow them

---

**`js-rule-6-promise-without-catch`** | WARNING | `rules\javascript-rules-original-backup.yml`
> Rule 6: Handle promises properly. Always add .catch() to handle rejections

---

**`js-rule-6-promise-without-catch`** | WARNING | `rules\javascript-rules.yml`
> Rule 6: Handle promises properly. Always add .catch() to handle rejections

---

**`js-rule-7-prefer-async-await`** | INFO | `rules\javascript-rules-original-backup.yml`
> Rule 7: Prefer async/await over promise chains for better readability and control flow

---

**`js-rule-7-prefer-async-await`** | INFO | `rules\javascript-rules.yml`
> Rule 7: Prefer async/await over promise chains for better readability and control flow

---

**`js-rule-8-no-console-production`** | WARNING | `rules\javascript-rules-original-backup.yml`
> Rule 8: Avoid console statements in production. Use a proper logging library (e.g., winston, pino)

---

**`js-rule-8-no-console-production`** | WARNING | `rules\javascript-rules.yml`
> Rule 8: Avoid console statements in production. Use a proper logging library (e.g., winston, pino)

---

**`js-security-command-injection`** | ERROR | `rules\javascript-rules.yml`
> Command injection vulnerability detected. Sanitize user input or use execFile with array arguments

---

**`js-security-hardcoded-secrets`** | ERROR | `rules\javascript-rules.yml`
> Hardcoded secret detected. Use environment variables or a secure secrets management system

---

**`js-security-insecure-cors`** | ERROR | `rules\javascript-rules.yml`
> Insecure CORS configuration detected. Use specific origins or implement proper origin validation

---

**`js-security-path-traversal`** | ERROR | `rules\javascript-rules.yml`
> Path traversal vulnerability detected. Validate and sanitize file paths from user input

---

**`js-security-prototype-pollution`** | ERROR | `rules\javascript-rules.yml`
> Prototype pollution vulnerability detected. Validate object keys and use Object.hasOwnProperty()

---

**`js-security-sql-injection`** | ERROR | `rules\javascript-rules.yml`
> SQL injection vulnerability detected. Use parameterized queries or prepared statements

---

**`js-security-weak-crypto`** | ERROR | `rules\javascript-rules.yml`
> Weak cryptographic algorithm detected. Use SHA-256 or stronger, and crypto.randomBytes() for random values

---

**`jwt-decode-without-verify`** | WARNING | `community-rules\javascript\jsonwebtoken\security\audit\jwt-decode-without-verify.yaml`
> Detected the decoding of a JWT token without a verify step. JWT tokens must be verified before use, otherwise the token's integrity is unknown. This means a malicious actor could forge a JWT token with any claims. Call '.verify()' before using the token.

---

**`jwt-exposed-data`** | WARNING | `community-rules\javascript\jsonwebtoken\security\audit\jwt-exposed-data.yaml`
> The object is passed strictly to jsonwebtoken.sign(...) Make sure that sensitive information is not exposed through JWT token payload.

---

**`jwt-none-alg`** | ERROR | `community-rules\javascript\jose\security\jwt-none-alg.yaml`
> Detected use of the 'none' algorithm in a JWT token. The 'none' algorithm assumes the integrity of the token has already been verified. This would allow a malicious actor to forge a JWT token that will automatically be verified. Do not explicitly use the 'none' algorithm. Instead, use an algorithm such as 'HS256'.

---

**`jwt-none-alg`** | ERROR | `community-rules\javascript\jsonwebtoken\security\jwt-none-alg.yaml`
> Detected use of the 'none' algorithm in a JWT token. The 'none' algorithm assumes the integrity of the token has already been verified. This would allow a malicious actor to forge a JWT token that will automatically be verified. Do not explicitly use the 'none' algorithm. Instead, use an algorithm such as 'HS256'.

---

**`jwt-simple-noverify`** | ERROR | `community-rules\javascript\jwt-simple\security\jwt-simple-noverify.yaml`
> Detected the decoding of a JWT token without a verify step. JWT tokens must be verified before use, otherwise the token's integrity is unknown. This means a malicious actor could forge a JWT token with any claims. Set 'verify' to `true` before using the token.

---

**`knex-sqli`** | WARNING | `community-rules\javascript\aws-lambda\security\knex-sqli.yaml`
> Detected SQL statement that is tainted by `$EVENT` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries or prepared statements instead. You can use parameterized statements like so: `knex.raw('SELECT $1 from table', [userinput])`

---

**`lazy-load-module`** | WARNING | `community-rules\javascript\lang\best-practice\lazy-load-module.yaml`
> Lazy loading can complicate code bundling if care is not taken, also `require`s are run synchronously by Node.js. If they are called from within a function, it may block other requests from being handled at a more critical time. The best practice is to `require` modules at the beginning of each file, before and outside of any functions.

---

**`md5-used-as-password`** | WARNING | `community-rules\javascript\lang\security\audit\md5-used-as-password.yaml`
> It looks like MD5 is used as a password hash. MD5 is not considered a secure password hash because it can be cracked by an attacker in a short amount of time. Use a suitable password hashing function such as bcrypt. You can use the `bcrypt` node.js package.

---

**`missing-template-string-indicator`** | INFO | `community-rules\javascript\lang\correctness\missing-template-string-indicator.yaml`
> This looks like a JavaScript template string. Are you missing a '$' in front of '{...}'?

---

**`monaco-hover-htmlsupport`** | WARNING | `community-rules\javascript\monaco-editor\security\audit\monaco-hover-htmlsupport.yaml`
> If user input reaches `HoverProvider` while `supportHml` is set to `true` it may introduce an XSS vulnerability. Do not produce HTML for hovers with dynamically generated input.

---

**`multiargs-code-execution`** | WARNING | `community-rules\javascript\thenify\security\audit\multiargs-code-execution.yaml`
> Potential arbitrary code execution, piped to eval

---

**`mysql-sqli`** | WARNING | `community-rules\javascript\aws-lambda\security\mysql-sqli.yaml`
> Detected SQL statement that is tainted by `$EVENT` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries or prepared statements instead. You can use parameterized statements like so: `connection.query('SELECT $1 from table', [userinput])`

---

**`no-replaceall`** | WARNING | `community-rules\javascript\lang\correctness\no-replaceall.yaml`
> The string method replaceAll is not supported in all versions of javascript, and is not supported by older browser versions. Consider using replace() with a regex as the first argument instead like mystring.replace(/bad/g, "good") instead of mystring.replaceAll("bad", "good") (https://discourse.threejs.org/t/replaceall-is-not-a-function/14585)

---

**`no-stringify-keys`** | WARNING | `community-rules\javascript\lang\correctness\no-stringify-keys.yaml`
> JSON stringify does not produce a stable key ordering, and should not be relied on for producing object keys. Consider using json-stable-stringify instead.

---

**`node-knex-sqli`** | WARNING | `community-rules\javascript\lang\security\audit\sqli\node-knex-sqli.yaml`
> Detected SQL statement that is tainted by `$REQ` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, it is recommended to use parameterized queries or prepared statements. An example of parameterized queries like so: `knex.raw('SELECT $1 from table', [userinput])` can help prevent SQLi.

---

**`node-mssql-sqli`** | WARNING | `community-rules\javascript\lang\security\audit\sqli\node-mssql-sqli.yaml`
> Detected string concatenation with a non-literal variable in a `mssql` JS SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries or prepared statements instead. You can use parameterized statements like so: `$REQ.input('USER_ID', mssql.Int, id);`

---

**`node-mysql-sqli`** | WARNING | `community-rules\javascript\lang\security\audit\sqli\node-mysql-sqli.yaml`
> Detected a `$IMPORT` SQL statement that comes from a function argument. This could lead to SQL injection if the variable is user-controlled and is not properly sanitized. In order to prevent SQL injection, it is recommended to use parameterized queries or prepared statements.

---

**`node-postgres-sqli`** | WARNING | `community-rules\javascript\lang\security\audit\sqli\node-postgres-sqli.yaml`
> Detected string concatenation with a non-literal variable in a node-postgres JS SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries or prepared statements instead. You can use parameterized statements like so: `client.query('SELECT $1 from table', [userinput])`

---

**`path-join-resolve-traversal`** | WARNING | `community-rules\javascript\lang\security\audit\path-traversal\path-join-resolve-traversal.yaml`
> Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in the file system. Instead, be sure to sanitize or validate user input first.

---

**`pg-sqli`** | WARNING | `community-rules\javascript\aws-lambda\security\pg-sqli.yaml`
> Detected SQL statement that is tainted by `$EVENT` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries or prepared statements instead. You can use parameterized statements like so: `connection.query('SELECT $1 from table', [userinput])`

---

**`phantom-injection`** | WARNING | `community-rules\javascript\phantom\security\audit\phantom-injection.yaml`
> If unverified user data can reach the `phantom` page methods it can result in Server-Side Request Forgery vulnerabilities

---

**`playwright-addinitscript-code-injection`** | WARNING | `community-rules\javascript\playwright\security\audit\playwright-addinitscript-code-injection.yaml`
> If unverified user data can reach the `addInitScript` method it can result in Server-Side Request Forgery vulnerabilities

---

**`playwright-evaluate-arg-injection`** | WARNING | `community-rules\javascript\playwright\security\audit\playwright-evaluate-arg-injection.yaml`
> If unverified user data can reach the `evaluate` method it can result in Server-Side Request Forgery vulnerabilities

---

**`playwright-evaluate-code-injection`** | WARNING | `community-rules\javascript\playwright\security\audit\playwright-evaluate-code-injection.yaml`
> If unverified user data can reach the `evaluate` method it can result in Server-Side Request Forgery vulnerabilities

---

**`playwright-exposed-chrome-devtools`** | WARNING | `community-rules\javascript\playwright\security\audit\playwright-exposed-chrome-devtools.yaml`
> Remote debugging protocol does not perform any authentication, so exposing it too widely can be a security risk.

---

**`playwright-goto-injection`** | WARNING | `community-rules\javascript\playwright\security\audit\playwright-goto-injection.yaml`
> If unverified user data can reach the `goto` method it can result in Server-Side Request Forgery vulnerabilities

---

**`playwright-setcontent-injection`** | WARNING | `community-rules\javascript\playwright\security\audit\playwright-setcontent-injection.yaml`
> If unverified user data can reach the `setContent` method it can result in Server-Side Request Forgery vulnerabilities

---

**`prohibit-jquery-html`** | WARNING | `community-rules\javascript\jquery\security\audit\prohibit-jquery-html.yaml`
> JQuery's `html` function is susceptible to Cross Site Scripting (XSS) attacks. If you're just passing text, consider `text` instead. Otherwise, use a function that escapes HTML such as edX's `HtmlUtils.setHtml()`.

---

**`prototype-pollution-assignment`** | WARNING | `community-rules\javascript\lang\security\audit\prototype-pollution\prototype-pollution-assignment.yaml`
> Possibility of prototype polluting assignment detected. By adding or modifying attributes of an object prototype, it is possible to create attributes that exist on every object, or replace critical attributes with malicious ones. This can be problematic if the software depends on existence or non-existence of certain attributes, or uses pre-defined attributes of object prototype (such as hasOwnProperty, toString or valueOf). Possible mitigations might be: freezing the object prototype, using an object without prototypes (via Object.create(null) ), blocking modifications of attributes that resolve to object prototype, using Map instead of object.

---

**`prototype-pollution-loop`** | WARNING | `community-rules\javascript\lang\security\audit\prototype-pollution\prototype-pollution-loop.yaml`
> Possibility of prototype polluting function detected. By adding or modifying attributes of an object prototype, it is possible to create attributes that exist on every object, or replace critical attributes with malicious ones. This can be problematic if the software depends on existence or non-existence of certain attributes, or uses pre-defined attributes of object prototype (such as hasOwnProperty, toString or valueOf). Possible mitigations might be: freezing the object prototype, using an object without prototypes (via Object.create(null) ), blocking modifications of attributes that resolve to object prototype, using Map instead of object.

---

**`puppeteer-evaluate-arg-injection`** | WARNING | `community-rules\javascript\puppeteer\security\audit\puppeteer-evaluate-arg-injection.yaml`
> If unverified user data can reach the `evaluate` method it can result in Server-Side Request Forgery vulnerabilities

---

**`puppeteer-evaluate-code-injection`** | WARNING | `community-rules\javascript\puppeteer\security\audit\puppeteer-evaluate-code-injection.yaml`
> If unverified user data can reach the `evaluate` method it can result in Server-Side Request Forgery vulnerabilities

---

**`puppeteer-exposed-chrome-devtools`** | WARNING | `community-rules\javascript\puppeteer\security\audit\puppeteer-exposed-chrome-devtools.yaml`
> Remote debugging protocol does not perform any authentication, so exposing it too widely can be a security risk.

---

**`puppeteer-goto-injection`** | WARNING | `community-rules\javascript\puppeteer\security\audit\puppeteer-goto-injection.yaml`
> If unverified user data can reach the `goto` method it can result in Server-Side Request Forgery vulnerabilities

---

**`puppeteer-setcontent-injection`** | WARNING | `community-rules\javascript\puppeteer\security\audit\puppeteer-setcontent-injection.yaml`
> If unverified user data can reach the `setContent` method it can result in Server-Side Request Forgery vulnerabilities

---

**`raw-html-concat`** | WARNING | `community-rules\javascript\browser\security\raw-html-concat.yaml`
> User controlled data in a HTML string may result in XSS

---

**`raw-html-format`** | WARNING | `community-rules\javascript\express\security\injection\raw-html-format.yaml`
> User data flows into the host portion of this manually-constructed HTML. This can introduce a Cross-Site-Scripting (XSS) vulnerability if this comes from user-provided input. Consider using a sanitization library such as DOMPurify to sanitize the HTML within.

---

**`raw-html-join`** | WARNING | `community-rules\javascript\browser\security\raw-html-join.yaml`
> User controlled data in a HTML string may result in XSS

---

**`remote-property-injection`** | ERROR | `community-rules\javascript\express\security\audit\remote-property-injection.yaml`
> Bracket object notation with user input is present, this might allow an attacker to access all properties of the object and even it's prototype. Use literal values for object properties.

---

**`require-request`** | ERROR | `community-rules\javascript\express\security\require-request.yaml`
> If an attacker controls the x in require(x) then they can cause code to load that was not intended to run on the server.

---

**`res-render-injection`** | WARNING | `community-rules\javascript\express\security\audit\res-render-injection.yaml`
> User controllable data `$REQ` enters `$RES.render(...)` this can lead to the loading of other HTML/templating pages that they may not be authorized to render. An attacker may attempt to use directory traversal techniques e.g. `../folder/index` to access other HTML pages on the file system. Where possible, do not allow users to define what should be  loaded in $RES.render or use an allow list for the existing application.

---

**`sandbox-code-injection`** | WARNING | `community-rules\javascript\sandbox\security\audit\sandbox-code-injection.yaml`
> Make sure that unverified user data can not reach `sandbox`.

---

**`sax-xxe`** | WARNING | `community-rules\javascript\sax\security\audit\sax-xxe.yaml`
> Use of 'ondoctype' in 'sax' library detected. By default, 'sax' won't do anything with custom DTD entity definitions. If you're implementing a custom DTD entity definition, be sure not to introduce XML External Entity (XXE) vulnerabilities, or be absolutely sure that external entities received from a trusted source while processing XML.

---

**`sequelize-enforce-tls`** | WARNING | `community-rules\javascript\sequelize\security\audit\sequelize-enforce-tls.yaml`
> If TLS is disabled on server side (Postgresql server), Sequelize establishes connection without TLS and no error will be thrown. To prevent MITN (Man In The Middle) attack, TLS must be enforce by Sequelize. Set "ssl: true" or define settings "ssl: {...}"

---

**`sequelize-raw-query`** | WARNING | `community-rules\javascript\sequelize\security\audit\sequelize-raw-query.yaml`
> Avoiding SQL string concatenation: untrusted input concatenated with raw SQL query can result in SQL Injection. Data replacement or data binding should be used. See https://sequelize.org/master/manual/raw-queries.html

---

**`sequelize-sqli`** | WARNING | `community-rules\javascript\aws-lambda\security\sequelize-sqli.yaml`
> Detected SQL statement that is tainted by `$EVENT` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries or prepared statements instead. You can use parameterized statements like so: `sequelize.query('SELECT * FROM projects WHERE status = ?', { replacements: ['active'], type: QueryTypes.SELECT });`

---

**`sequelize-tls-disabled-cert-validation`** | ERROR | `community-rules\javascript\sequelize\security\audit\sequelize-tls-disabled-cert-validation.yaml`
> Set "rejectUnauthorized" to false is a convenient way to resolve certificate error. But this method is unsafe because it disables the server certificate verification, making the Node app open to MITM attack. "rejectUnauthorized" option must be alway set to True (default value). With self -signed certificate or custom CA, use "ca" option to define Root Certificate. This rule checks TLS configuration only for Postgresql, MariaDB and MySQL. SQLite is not really concerned by TLS configuration. This rule could be extended for MSSQL, but the dialectOptions is specific for Tedious.

---

**`sequelize-weak-tls-version`** | WARNING | `community-rules\javascript\sequelize\security\audit\sequelize-weak-tls-version.yaml`
> TLS1.0 and TLS1.1 are deprecated and should not be used anymore. By default, NodeJS used TLSv1.2. So, TLS min version must not be downgrade to TLS1.0 or TLS1.1. Enforce TLS1.3 is highly recommended This rule checks TLS configuration only for PostgreSQL, MariaDB and MySQL. SQLite is not really concerned by TLS configuration. This rule could be extended for MSSQL, but the dialectOptions is specific for Tedious.

---

**`shelljs-exec-injection`** | ERROR | `community-rules\javascript\shelljs\security\shelljs-exec-injection.yaml`
> If unverified user data can reach the `exec` method it can result in Remote Code Execution

---

**`spawn-git-clone`** | ERROR | `community-rules\javascript\lang\security\spawn-git-clone.yaml`
> Git allows shell commands to be specified in ext URLs for remote repositories. For example, git clone 'ext::sh -c whoami% >&2' will execute the whoami command to try to connect to a remote repository. Make sure that the URL is not controlled by external input.

---

**`spawn-shell-true`** | ERROR | `community-rules\javascript\lang\security\audit\spawn-shell-true.yaml`
> Found '$SPAWN' with '{shell: $SHELL}'. This is dangerous because this call will spawn the command using a shell process. Doing so propagates current shell settings and variables, which makes it much easier for a malicious actor to execute commands. Use '{shell: false}' instead.

---

**`tainted-eval`** | WARNING | `community-rules\javascript\aws-lambda\security\tainted-eval.yaml`
> The `eval()` function evaluates JavaScript code represented as a string. Executing JavaScript from a string is an enormous security risk. It is far too easy for a bad actor to run arbitrary code when you use `eval()`. Ensure evaluated content is not definable by external sources.

---

**`tainted-html-response`** | WARNING | `community-rules\javascript\aws-lambda\security\tainted-html-response.yaml`
> Detected user input flowing into an HTML response. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross-site scripting vulnerability, which could let attackers steal sensitive user data.

---

**`tainted-html-string`** | WARNING | `community-rules\javascript\aws-lambda\security\tainted-html-string.yaml`
> Detected user input flowing into a manually constructed HTML string. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross-site scripting vulnerability, which could let attackers steal sensitive user data. To be sure this is safe, check that the HTML is rendered safely. Otherwise, use templates which will safely render HTML instead.

---

**`tainted-sql-string`** | ERROR | `community-rules\javascript\aws-lambda\security\tainted-sql-string.yaml`
> Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify contents of the database. Instead, use a parameterized query which is available by default in most database engines. Alternatively, consider using an object-relational mapper (ORM) such as Sequelize which will protect your queries.

---

**`tainted-sql-string`** | ERROR | `community-rules\javascript\express\security\injection\tainted-sql-string.yaml`
> Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify contents of the database. Instead, use a parameterized query which is available by default in most database engines. Alternatively, consider using an object-relational mapper (ORM) such as Sequelize which will protect your queries.

---

**`template-and-attributes`** | WARNING | `community-rules\javascript\express\security\audit\xss\pug\and-attributes.yaml`
> Detected a unescaped variables using '&attributes'. If external data can reach these locations, your application is exposed to a cross-site scripting (XSS) vulnerability. If you must do this, ensure no external data can reach this location.

---

**`template-explicit-unescape`** | WARNING | `community-rules\javascript\express\security\audit\xss\ejs\explicit-unescape.yaml`
> Detected an explicit unescape in an EJS template, using '<%- ... %>' If external data can reach these locations, your application is exposed to a cross-site scripting (XSS) vulnerability. Use '<%= ... %>' to escape this data. If you need escaping, ensure no external data can reach this location.

---

**`template-explicit-unescape`** | WARNING | `community-rules\javascript\express\security\audit\xss\mustache\explicit-unescape.yaml`
> Detected an explicit unescape in a Mustache template, using triple braces '{{{...}}}' or ampersand '&'. If external data can reach these locations, your application is exposed to a cross-site scripting (XSS) vulnerability. If you must do this, ensure no external data can reach this location.

---

**`template-explicit-unescape`** | WARNING | `community-rules\javascript\express\security\audit\xss\pug\explicit-unescape.yaml`
> Detected an explicit unescape in a Pug template, using either '!=' or '!{...}'. If external data can reach these locations, your application is exposed to a cross-site scripting (XSS) vulnerability. If you must do this, ensure no external data can reach this location.

---

**`tofastproperties-code-execution`** | WARNING | `community-rules\javascript\bluebird\security\audit\tofastproperties-code-execution.yaml`
> Potential arbitrary code execution, whatever is provided to `toFastProperties` is sent straight to eval()

---

**`unknown-value-in-redirect`** | WARNING | `community-rules\javascript\express\security\audit\possible-user-input-redirect.yaml`
> It looks like '$UNK' is read from user input and it is used to as a redirect. Ensure '$UNK' is not externally controlled, otherwise this is an open redirect.

---

**`unknown-value-with-script-tag`** | WARNING | `community-rules\javascript\lang\security\audit\unknown-value-with-script-tag.yaml`
> Cannot determine what '$UNK' is and it is used with a '<script>' tag. This could be susceptible to cross-site scripting (XSS). Ensure '$UNK' is not externally controlled, or sanitize this data.

---

**`unsafe-argon2-config`** | WARNING | `community-rules\javascript\argon2\security\unsafe-argon2-config.yaml`
> Prefer Argon2id where possible. Per RFC9016, section 4 IETF recommends selecting Argon2id unless you can guarantee an adversary has no direct access to the computing environment.

---

**`unsafe-dynamic-method`** | WARNING | `community-rules\javascript\lang\security\audit\unsafe-dynamic-method.yaml`
> Using non-static data to retrieve and run functions from the object is dangerous. If the data is user-controlled, it may allow executing arbitrary code.

---

**`unsafe-formatstring`** | INFO | `community-rules\javascript\lang\security\audit\unsafe-formatstring.yaml`
> Detected string concatenation with a non-literal variable in a util.format / console.log function. If an attacker injects a format specifier in the string, it will forge the log message. Try to use constant values for the format string.

---

**`unsafe-serialize-javascript`** | WARNING | `community-rules\javascript\serialize-javascript\security\audit\unsafe-serialize-javascript.yaml`
> `serialize-javascript` used with `unsafe` parameter, this could be vulnerable to XSS.

---

**`useless-assignment`** | INFO | `community-rules\javascript\lang\correctness\useless-assign.yaml`
> `$X` is assigned twice; the first assignment is useless

---

**`var-in-href`** | WARNING | `community-rules\javascript\express\security\audit\xss\ejs\var-in-href.yaml`
> Detected a template variable used in an anchor tag with the 'href' attribute. This allows a malicious actor to input the 'javascript:' URI and is subject to cross- site scripting (XSS) attacks. If using a relative URL, start with a literal forward slash and concatenate the URL, like this: href='/<%= link %>'. You may also consider setting the Content Security Policy (CSP) header.

---

**`var-in-href`** | WARNING | `community-rules\javascript\express\security\audit\xss\pug\var-in-href.yaml`
> Detected a template variable used in an anchor tag with the 'href' attribute. This allows a malicious actor to input the 'javascript:' URI and is subject to cross- site scripting (XSS) attacks. If using a relative URL, start with a literal forward slash and concatenate the URL, like this: a(href='/'+url). You may also consider setting the Content Security Policy (CSP) header.

---

**`var-in-script-src`** | WARNING | `community-rules\javascript\express\security\audit\xss\ejs\var-in-script-src.yaml`
> Detected a template variable used as the 'src' in a script tag. Although template variables are HTML escaped, HTML escaping does not always prevent malicious URLs from being injected and could results in a cross-site scripting (XSS) vulnerability. Prefer not to dynamically generate the 'src' attribute and use static URLs instead. If you must do this, carefully check URLs against an allowlist and be sure to URL-encode the result.

---

**`var-in-script-tag`** | WARNING | `community-rules\javascript\express\security\audit\xss\ejs\var-in-script-tag.yaml`
> Detected a template variable used in a script tag. Although template variables are HTML escaped, HTML escaping does not always prevent cross-site scripting (XSS) attacks when used directly in JavaScript. If you need this data on the rendered page, consider placing it in the HTML portion (outside of a script tag). Alternatively, use a JavaScript-specific encoder, such as the one available in OWASP ESAPI.

---

**`var-in-script-tag`** | WARNING | `community-rules\javascript\express\security\audit\xss\mustache\var-in-script-tag.yaml`
> Detected a template variable used in a script tag. Although template variables are HTML escaped, HTML escaping does not always prevent cross-site scripting (XSS) attacks when used directly in JavaScript. If you need this data on the rendered page, consider placing it in the HTML portion (outside of a script tag). Alternatively, use a JavaScript-specific encoder, such as the one available in OWASP ESAPI.

---

**`var-in-script-tag`** | WARNING | `community-rules\javascript\express\security\audit\xss\pug\var-in-script-tag.yaml`
> Detected a template variable used in a script tag. Although template variables are HTML escaped, HTML escaping does not always prevent cross-site scripting (XSS) attacks when used directly in JavaScript. If you need this data on the rendered page, consider placing it in the HTML portion (outside of a script tag). Alternatively, use a JavaScript-specific encoder, such as the one available in OWASP ESAPI.

---

**`vm-runincontext-injection`** | ERROR | `community-rules\javascript\aws-lambda\security\vm-runincontext-injection.yaml`
> The `vm` module enables compiling and running code within V8 Virtual Machine contexts. The `vm` module is not a security mechanism. Do not use it to run untrusted code. If code passed to `vm` functions is controlled by user input it could result in command injection. Do not let user input in `vm` functions.

---

**`vm2-code-injection`** | WARNING | `community-rules\javascript\vm2\security\audit\vm2-code-injection.yaml`
> Make sure that unverified user data can not reach `vm2`.

---

**`vm2-context-injection`** | WARNING | `community-rules\javascript\vm2\security\audit\vm2-context-injection.yaml`
> Make sure that unverified user data can not reach `vm2`.

---

**`wildcard-postmessage-configuration`** | WARNING | `community-rules\javascript\browser\security\wildcard-postmessage-configuration.yaml`
> The target origin of the window.postMessage() API is set to "*". This could allow for information disclosure due to the possibility of any origin allowed to receive the message.

---

**`wkhtmltoimage-injection`** | WARNING | `community-rules\javascript\wkhtmltoimage\security\audit\wkhtmltoimage-injection.yaml`
> If unverified user data can reach the `wkhtmltoimage` it can result in Server-Side Request Forgery vulnerabilities

---

**`wkhtmltopdf-injection`** | WARNING | `community-rules\javascript\wkhtmltopdf\security\audit\wkhtmltopdf-injection.yaml`
> If unverified user data can reach the `wkhtmltopdf` it can result in Server-Side Request Forgery vulnerabilities

---

**`x-frame-options-misconfiguration`** | WARNING | `community-rules\javascript\express\security\x-frame-options-misconfiguration.yaml`
> By letting user input control `X-Frame-Options` header, there is a risk that software does not properly verify whether or not a browser should be allowed to render a page in an `iframe`.

---

**`xml2json-xxe`** | WARNING | `community-rules\javascript\xml2json\security\audit\xml2json-xxe.yaml`
> If unverified user data can reach the XML Parser it can result in XML External or Internal Entity (XXE) Processing vulnerabilities

---

**`zlib-async-loop`** | WARNING | `community-rules\javascript\lang\best-practice\zlib-async-loop.yaml`
> Creating and using a large number of zlib objects simultaneously can cause significant memory fragmentation. It is strongly recommended that the results of compression operations be cached or made synchronous to avoid duplication of effort.

---

## Json (4 rules)

**`package-dependencies-check`** | WARNING | `community-rules\json\npm\security\package-dependencies-check.yml`
> Package dependencies with variant versions may lead to dependency hijack and confusion attacks. Better to specify an exact version or use package-lock.json for a specific version of the package.

---

**`public-s3-bucket`** | WARNING | `community-rules\json\aws\security\public-s3-bucket.yaml`
> Detected public S3 bucket. This policy allows anyone to have some kind of access to the bucket. The exact level of access and types of actions allowed will depend on the configuration of bucket policy and ACLs. Please review the bucket configuration to make sure they are set with intended values.

---

**`public-s3-policy-statement`** | WARNING | `community-rules\json\aws\security\public-s3-policy-statement.yaml`
> Detected public S3 bucket policy. This policy allows anyone to access certain properties of or items in the bucket. Do not do this unless you will never have sensitive data inside the bucket.

---

**`wildcard-assume-role`** | ERROR | `community-rules\json\aws\security\wildcard-assume-role.yaml`
> Detected wildcard access granted to sts:AssumeRole. This means anyone with your AWS account ID and the name of the role can assume the role. Instead, limit to a specific identity in your account, like this: `arn:aws:iam::<account_id>:root`.

---

## Kotlin (14 rules)

**`anonymous-ldap-bind`** | WARNING | `community-rules\kotlin\lang\security\anonymous-ldap-bind.yaml`
> Detected anonymous LDAP bind. This permits anonymous users to execute LDAP statements. Consider enforcing authentication for LDAP. See https://docs.oracle.com/javase/tutorial/jndi/ldap/auth_mechs.html for more information.

---

**`bad-hexa-conversion`** | WARNING | `community-rules\kotlin\lang\security\bad-hexa-conversion.yaml`
> 'Integer.toHexString()' strips leading zeroes from each byte if read byte-by-byte. This mistake weakens the hash value computed since it introduces more collisions. Use 'String.format("%02X", ...)' instead.

---

**`build-gradle-password-hardcoded`** | WARNING | `community-rules\kotlin\gradle\security\build-gradle-password-hardcoded.yaml`
> A secret is hard-coded in the application. Secrets stored in source code, such as credentials, identifiers, and other types of sensitive data, can be leaked and used by internal or external malicious actors. It is recommended to rotate the secret and retrieve them from a secure secret vault or Hardware Security Module (HSM), alternatively environment variables can be used if allowed by your company policy.

---

**`command-injection-formatted-runtime-call`** | ERROR | `community-rules\kotlin\lang\security\command-injection-formatted-runtime-call.yaml`
> A formatted or concatenated string was detected as input to a java.lang.Runtime call. This is dangerous if a variable is controlled by user input and could result in a command injection. Ensure your variables are not controlled by users or sufficiently sanitized.

---

**`cookie-missing-httponly`** | WARNING | `community-rules\kotlin\lang\security\cookie-missing-httponly.yaml`
> A cookie was detected without setting the 'HttpOnly' flag. The 'HttpOnly' flag for cookies instructs the browser to forbid client-side scripts from reading the cookie. Set the 'HttpOnly' flag by calling 'cookie.setHttpOnly(true);'

---

**`cookie-missing-secure-flag`** | WARNING | `community-rules\kotlin\lang\security\cookie-missing-secure-flag.yaml`
> A cookie was detected without setting the 'secure' flag. The 'secure' flag for cookies prevents the client from transmitting the cookie over insecure channels such as HTTP. Set the 'secure' flag by calling '$COOKIE.setSecure(true);'

---

**`defaulthttpclient-is-deprecated`** | WARNING | `community-rules\kotlin\lang\security\defaulthttpclient-is-deprecated.yaml`
> DefaultHttpClient is deprecated. Further, it does not support connections using TLS1.2, which makes using DefaultHttpClient a security hazard. Use SystemDefaultHttpClient instead, which supports TLS1.2.

---

**`ecb-cipher`** | WARNING | `community-rules\kotlin\lang\security\ecb-cipher.yaml`
> Cipher in ECB mode is detected. ECB mode produces the same output for the same input each time which allows an attacker to intercept and replay the data. Further, ECB mode does not provide any integrity checking. See https://find-sec-bugs.github.io/bugs.htm#CIPHER_INTEGRITY.

---

**`gcm-detection`** | INFO | `community-rules\kotlin\lang\security\gcm-detection.yaml`
> GCM detected, please check that IV/nonce is not reused, an Initialization Vector (IV) is a nonce used to randomize the encryption, so that even if multiple messages with identical plaintext are encrypted, the generated corresponding ciphertexts are different.Unlike the Key, the IV usually does not need to be secret, rather it is important that it is random and unique. Certain encryption schemes the IV is exchanged in public as part of the ciphertext. Reusing same Initialization Vector with the same Key to encrypt multiple plaintext blocks allows an attacker to compare the ciphertexts and then, with some assumptions on the content of the messages, to gain important information about the data being encrypted.

---

**`no-null-cipher`** | WARNING | `community-rules\kotlin\lang\security\no-null-cipher.yaml`
> NullCipher was detected. This will not encrypt anything; the cipher text will be the same as the plain text. Use a valid, secure cipher: Cipher.getInstance("AES/CBC/PKCS7PADDING"). See https://owasp.org/www-community/Using_the_Java_Cryptographic_Extensions for more information.

---

**`unencrypted-socket`** | WARNING | `community-rules\kotlin\lang\security\unencrypted-socket.yaml`
> This socket is not encrypted. The traffic could be read by an attacker intercepting the network traffic. Use an SSLSocket created by 'SSLSocketFactory' or 'SSLServerSocketFactory' instead

---

**`use-of-md5`** | WARNING | `community-rules\kotlin\lang\security\use-of-md5.yaml`
> Detected MD5 hash algorithm which is considered insecure. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.

---

**`use-of-sha1`** | WARNING | `community-rules\kotlin\lang\security\use-of-sha1.yaml`
> Detected SHA1 hash algorithm which is considered insecure. SHA1 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.

---

**`use-of-weak-rsa-key`** | WARNING | `community-rules\kotlin\lang\security\weak-rsa.yaml`
> RSA keys should be at least 2048 bits based on NIST recommendation.

---

## Ocaml (33 rules)

**`bad-reraise`** | WARNING | `community-rules\ocaml\lang\best-practice\exception.yaml`
> You should not re-raise exceptions using 'raise' because it loses track of where the exception was raised originally, leading to a useless and possibly confusing stack trace. Instead, you should obtain a stack backtrace as soon as the exception is caught using 'try ... with exn -> let trace = Printexc.get_raw_backtrace () in ...', and keep it around until you re-raise the exception using 'Printexc.raise_with_backtrace exn trace'. You must collect the stack backtrace before calling another function which might internally raise and catch exceptions. To avoid false positives from Semgrep, write 'raise (Foo args)' instead of 'let e = Foo args in raise e'.

---

**`broken-input-line`** | WARNING | `community-rules\ocaml\lang\portability\crlf-support.yaml`
> 'input_line' leaves a '\r' (CR) character when reading lines from a Windows text file, whose lines end in "\r\n" (CRLF). This is a problem for any Windows file that is being read either on a Unix-like platform or on Windows in binary mode. If the code already takes care of removing any trailing '\r' after reading the line, add a '(* nosemgrep *)' comment to disable this warning.

---

**`deprecated-pervasives`** | ERROR | `community-rules\ocaml\lang\compatibility\deprecated.yaml`
> Pervasives is deprecated and will not be available after 4.10. Use Stdlib.

---

**`hashtbl-find-outside-try`** | WARNING | `community-rules\ocaml\lang\best-practice\hashtbl.yaml`
> 'Hashtbl.find' raises the 'Not_found' exception. Handle the exception or use 'Hashtbl.find_opt' instead. If you have proof that the key exists in the table, use 'assert false' as the exception handler to demonstrate awareness of the issue. If your code uses the syntax 'match Hashtbl.find ... with exception Not_found -> ...', it's fine and we apologize for not detecting it. Consider using 'Hashtbl.find_opt' to please Semgrep and stay safe.

---

**`list-find-outside-try`** | WARNING | `community-rules\ocaml\lang\best-practice\list.yaml`
> You should not use List.find outside of a try, or you should use List.find_opt

---

**`not-portable-tmp-string`** | WARNING | `community-rules\ocaml\lang\portability\slash-tmp.yaml`
> You should probably use Filename.get_temp_dirname().

---

**`ocamllint-backwards-if`** | WARNING | `community-rules\ocaml\lang\best-practice\ifs.yaml`
> Backwards if. Rewrite the code as 'if not $E then $E2'.

---

**`ocamllint-bool-false`** | WARNING | `community-rules\ocaml\lang\best-practice\bool.yaml`
> Comparison to boolean. Just use `not $X`

---

**`ocamllint-bool-true`** | WARNING | `community-rules\ocaml\lang\best-practice\bool.yaml`
> Comparison to boolean. Just use `$X`

---

**`ocamllint-digest`** | WARNING | `community-rules\ocaml\lang\security\digest.yaml`
> Digest uses MD5 and should not be used for security purposes. Consider using SHA256 instead.

---

**`ocamllint-exec`** | WARNING | `community-rules\ocaml\lang\security\exec.yaml`
> Executing external programs might lead to comand or argument injection vulnerabilities.

---

**`ocamllint-filenameconcat`** | WARNING | `community-rules\ocaml\lang\security\filenameconcat.yaml`
> When attacker supplied data is passed to Filename.concat directory traversal attacks might be possible.

---

**`ocamllint-hashtable-dos`** | WARNING | `community-rules\ocaml\lang\security\hashtable-dos.yaml`
> Creating a Hashtbl without the optional random number parameter makes it prone to DoS attacks when attackers are able to fill the table with malicious content. Hashtbl.randomize or the R flag in the OCAMLRUNPARAM are other ways to randomize it.

---

**`ocamllint-length-list-zero`** | WARNING | `community-rules\ocaml\lang\performance\list.yaml`
> You probably want $X = [], which is faster.

---

**`ocamllint-length-more-than-zero`** | WARNING | `community-rules\ocaml\lang\performance\list.yaml`
> You probably want $X <> [], which is faster.

---

**`ocamllint-marshal`** | WARNING | `community-rules\ocaml\lang\security\marshal.yaml`
> Marshaling is currently not type-safe and can lead to insecure behaviour when untrusted data is marshalled. Marshalling can lead to out-of-bound reads as well.

---

**`ocamllint-ref-decr`** | WARNING | `community-rules\ocaml\lang\best-practice\ref.yaml`
> You should use `decr`

---

**`ocamllint-ref-incr`** | WARNING | `community-rules\ocaml\lang\best-practice\ref.yaml`
> You should use `incr`

---

**`ocamllint-str-first-chars`** | WARNING | `community-rules\ocaml\lang\best-practice\string.yaml`
> Use instead `Str.first_chars`

---

**`ocamllint-str-last-chars`** | WARNING | `community-rules\ocaml\lang\best-practice\string.yaml`
> Use instead `Str.last_chars`

---

**`ocamllint-str-string-after`** | WARNING | `community-rules\ocaml\lang\best-practice\string.yaml`
> Use instead `Str.string_after`

---

**`ocamllint-tempfile`** | WARNING | `community-rules\ocaml\lang\security\tempfile.yaml`
> Filename.temp_file might lead to race conditions, since the file could be altered or replaced by a symlink before being opened.

---

**`ocamllint-unsafe`** | WARNING | `community-rules\ocaml\lang\security\unsafe.yaml`
> Unsafe functions do not perform boundary checks or have other side effects, use with care.

---

**`ocamllint-useless-else`** | WARNING | `community-rules\ocaml\lang\best-practice\ifs.yaml`
> Useless else. Just remove the else branch;

---

**`ocamllint-useless-if`** | ERROR | `community-rules\ocaml\lang\correctness\useless-if.yaml`
> Useless if. Both branches are equal.

---

**`ocamllint-useless-sprintf`** | WARNING | `community-rules\ocaml\lang\best-practice\string.yaml`
> Useless sprintf

---

**`physical-equal`** | WARNING | `community-rules\ocaml\lang\correctness\physical-vs-structural.yaml`
> You probably want the structural equality operator =

---

**`physical-not-equal`** | WARNING | `community-rules\ocaml\lang\correctness\physical-vs-structural.yaml`
> You probably want the structural inequality operator <>

---

**`prefer-read-in-binary-mode`** | WARNING | `community-rules\ocaml\lang\portability\crlf-support.yaml`
> 'open_in' behaves differently on Windows and on Unix-like systems with respect to line endings. To get the same behavior everywhere, use 'open_in_bin' or 'open_in_gen [Open_binary]'. If you really want CRLF-to-LF translations to take place when running on Windows, use 'open_in_gen [Open_text]'.

---

**`prefer-write-in-binary-mode`** | WARNING | `community-rules\ocaml\lang\portability\crlf-support.yaml`
> 'open_out' behaves differently on Windows and on Unix-like systems with respect to line endings. To get the same behavior everywhere, use 'open_out_bin' or 'open_out_gen [Open_binary]'. If you really want LF-to-CRLF translations to take place when running on Windows, use 'open_out_gen [Open_text]'.

---

**`useless-compare`** | ERROR | `community-rules\ocaml\lang\correctness\useless-compare.yaml`
> This comparison is useless because the expressions being compared are identical. This is expected to always return the same result, 0, unless your code is really strange.

---

**`useless-equal`** | ERROR | `community-rules\ocaml\lang\correctness\useless-eq.yaml`
> This is always true. If testing for floating point NaN, use `Float.is_nan` instead.

---

**`useless-let`** | ERROR | `community-rules\ocaml\lang\correctness\useless-let.yaml`
> Useless let

---

## Php (64 rules)

**`assert-use`** | ERROR | `community-rules\php\lang\security\assert-use.yaml`
> Calling assert with user input is equivalent to eval'ing.

---

**`assert-use-audit`** | ERROR | `community-rules\php\lang\security\audit\assert-use-audit.yaml`
> Calling assert with user input is equivalent to eval'ing.

---

**`backticks-use`** | ERROR | `community-rules\php\lang\security\backticks-use.yaml`
> Backticks use may lead to command injection vulnerabilities.

---

**`base-convert-loses-precision`** | WARNING | `community-rules\php\lang\security\base-convert-loses-precision.yaml`
> The function base_convert uses 64-bit numbers internally, and does not correctly convert large numbers. It is not suitable for random tokens such as those used for session tokens or CSRF tokens.

---

**`curl-ssl-verifypeer-off`** | ERROR | `community-rules\php\lang\security\curl-ssl-verifypeer-off.yaml`
> SSL verification is disabled but should not be (currently CURLOPT_SSL_VERIFYPEER= $IS_VERIFIED)

---

**`doctrine-dbal-dangerous-query`** | WARNING | `community-rules\php\doctrine\security\audit\doctrine-dbal-dangerous-query.yaml`
> Detected string concatenation with a non-literal variable in a Doctrine DBAL query method. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries or prepared statements instead.

---

**`doctrine-orm-dangerous-query`** | WARNING | `community-rules\php\doctrine\security\audit\doctrine-orm-dangerous-query.yaml`
> `$QUERY` Detected string concatenation with a non-literal variable in a Doctrine QueryBuilder method. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries or prepared statements instead.

---

**`echoed-request`** | ERROR | `community-rules\php\lang\security\injection\echoed-request.yaml`
> `Echo`ing user input risks cross-site scripting vulnerability. You should use `htmlentities()` when showing data to users.

---

**`empty-with-boolean-expression`** | WARNING | `community-rules\php\lang\correctness\empty-with-boolean-expression.yaml`
> Calling `empty` on a boolean expression may be an indication that a parenthesis is misplaced.

---

**`eval-use`** | ERROR | `community-rules\php\lang\security\eval-use.yaml`
> Evaluating non-constant commands. This can lead to command injection.

---

**`exec-use`** | ERROR | `community-rules\php\lang\security\exec-use.yaml`
> Executing non-constant commands. This can lead to command injection.

---

**`extract-user-data`** | ERROR | `community-rules\php\lang\security\deserialization.yaml`
> Do not call 'extract()' on user-controllable data. If you must, then you must also provide the EXTR_SKIP flag to prevent overwriting existing variables.

---

**`file-inclusion`** | ERROR | `community-rules\php\lang\security\file-inclusion.yaml`
> Detected non-constant file inclusion. This can lead to local file inclusion (LFI) or remote file inclusion (RFI) if user input reaches this statement. LFI and RFI could lead to sensitive files being obtained by attackers. Instead, explicitly specify what to include. If that is not a viable solution, validate user input thoroughly.

---

**`ftp-use`** | ERROR | `community-rules\php\lang\security\ftp-use.yaml`
> FTP allows for unencrypted file transfers. Consider using an encrypted alternative.

---

**`laravel-active-debug-code`** | ERROR | `community-rules\php\laravel\security\laravel-active-debug-code.yaml`
> Found an instance setting the APP_DEBUG environment variable to true. In your production environment, this should always be false. Otherwise, you risk exposing sensitive configuration values to potential attackers. Instead, set this to false.

---

**`laravel-api-route-sql-injection`** | WARNING | `community-rules\php\laravel\security\laravel-api-route-sql-injection.yaml`
> HTTP method [$METHOD] to Laravel route $ROUTE_NAME is vulnerable to SQL injection via string concatenation or unsafe interpolation.

---

**`laravel-blade-form-missing-csrf`** | WARNING | `community-rules\php\laravel\security\laravel-blade-form-missing-csrf.yaml`
> Detected a form executing a state-changing HTTP method `$METHOD` to route definition `$...ROUTE` without a Laravel CSRF decorator or explicit CSRF token implementation. If this form modifies sensitive state this will open your application to Cross-Site Request Forgery (CSRF) attacks.

---

**`laravel-cookie-http-only`** | ERROR | `community-rules\php\laravel\security\laravel-cookie-http-only.yaml`
> Found a configuration file where the HttpOnly attribute is not set to true. Setting `http_only` to true makes sure that your cookies are inaccessible from Javascript, which mitigates XSS attacks. Instead, set the 'http_only' like so: `http_only` => true 

---

**`laravel-cookie-long-timeout`** | ERROR | `community-rules\php\laravel\security\laravel-cookie-long-timeout.yaml`
> Found a configuration file where the lifetime attribute is over 30 minutes.

---

**`laravel-cookie-null-domain`** | ERROR | `community-rules\php\laravel\security\laravel-cookie-null-domain.yaml`
> Found a configuration file where the domain attribute is not set to null. It is recommended (unless you are using sub-domain route registrations) to set this attribute to null so that only the same origin can set the cookie, thus protecting your cookies. 

---

**`laravel-cookie-same-site`** | ERROR | `community-rules\php\laravel\security\laravel-cookie-same-site.yaml`
> Found a configuration file where the same_site attribute is not set to 'lax' or 'strict'. Setting 'same_site' to 'lax' or 'strict' restricts cookies to a first-party or same-site context, which will protect your cookies and prevent CSRF.

---

**`laravel-cookie-secure-set`** | ERROR | `community-rules\php\laravel\security\laravel-cookie-secure-set.yaml`
> Found a configuration file where the secure attribute is not set to 'true'. Setting 'secure' to 'true' prevents the client from transmitting the cookie over unencrypted channels and therefore prevents cookies from being stolen through man in the middle attacks. 

---

**`laravel-dangerous-model-construction`** | ERROR | `community-rules\php\laravel\security\laravel-dangerous-model-construction.yaml`
> Setting `$guarded` to an empty array allows mass assignment to every property in a Laravel model. This explicitly overrides Eloquent's safe-by-default mass assignment protections.

---

**`laravel-sql-injection`** | WARNING | `community-rules\php\laravel\security\laravel-sql-injection.yaml`
> Detected a SQL query based on user input. This could lead to SQL injection, which could potentially result in sensitive data being exfiltrated by attackers. Instead, use parameterized queries and prepared statements.

---

**`laravel-unsafe-validator`** | ERROR | `community-rules\php\laravel\security\laravel-unsafe-validator.yaml`
> Found a request argument passed to an `ignore()` definition in a Rule constraint. This can lead to SQL injection.

---

**`ldap-bind-without-password`** | WARNING | `community-rules\php\lang\security\ldap-bind-without-password.yaml`
> Detected anonymous LDAP bind. This permits anonymous users to execute LDAP statements. Consider enforcing authentication for LDAP.

---

**`mb-ereg-replace-eval`** | ERROR | `community-rules\php\lang\security\mb-ereg-replace-eval.yaml`
> Calling mb_ereg_replace with user input in the options can lead to arbitrary code execution. The eval modifier (`e`) evaluates the replacement argument as code.

---

**`mcrypt-use`** | ERROR | `community-rules\php\lang\security\mcrypt-use.yaml`
> Mcrypt functionality has been deprecated and/or removed in recent PHP versions. Consider using Sodium or OpenSSL.

---

**`md5-loose-equality`** | ERROR | `community-rules\php\lang\security\md5-loose-equality.yaml`
> Make sure comparisons involving md5 values are strict (use `===` not `==`) to avoid type juggling issues

---

**`md5-used-as-password`** | WARNING | `community-rules\php\lang\security\md5-used-as-password.yaml`
> It looks like MD5 is used as a password hash. MD5 is not considered a secure password hash because it can be cracked by an attacker in a short amount of time. Use a suitable password hashing function such as bcrypt. You can use `password_hash($PASSWORD, PASSWORD_BCRYPT, $OPTIONS);`.

---

**`openssl-cbc-static-iv`** | ERROR | `community-rules\php\lang\security\openssl-cbc-static-iv.yaml`
> Static IV used with AES in CBC mode. Static IVs enable chosen-plaintext attacks against encrypted data.

---

**`openssl-decrypt-validate`** | WARNING | `community-rules\php\lang\security\audit\openssl-decrypt-validate.yaml`
> The function `openssl_decrypt` returns either a string of the decrypted data on success or `false` on failure. If the failure case is not handled, this could lead to undefined behavior in your application. Please handle the case where `openssl_decrypt` returns `false`.

---

**`php-permissive-cors`** | WARNING | `community-rules\php\lang\security\php-permissive-cors.yaml`
> Access-Control-Allow-Origin response header is set to "*". This will disable CORS Same Origin Policy restrictions.

---

**`php-ssrf`** | ERROR | `community-rules\php\lang\security\php-ssrf.yaml`
> The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination. Dangerous function $FUNCS with payload $DATA

---

**`phpinfo-use`** | ERROR | `community-rules\php\lang\security\phpinfo-use.yaml`
> The 'phpinfo' function may reveal sensitive information about your environment.

---

**`printed-request`** | ERROR | `community-rules\php\lang\security\injection\printed-request.yaml`
> `Printing user input risks cross-site scripting vulnerability. You should use `htmlentities()` when showing data to users.

---

**`redirect-to-request-uri`** | WARNING | `community-rules\php\lang\security\redirect-to-request-uri.yaml`
> Redirecting to the current request URL may redirect to another domain, if the current path starts with two slashes.  E.g. in https://www.example.com//attacker.com, the value of REQUEST_URI is //attacker.com, and redirecting to it will redirect to that domain.

---

**`sha224-hash`** | WARNING | `community-rules\php\lang\security\audit\sha224-hash.yaml`
> This code uses a 224-bit hash function, which is deprecated or disallowed in some security policies. Consider updating to a stronger hash function such as SHA-384 or higher to ensure compliance and security.

---

**`symfony-csrf-protection-disabled`** | WARNING | `community-rules\php\symfony\security\audit\symfony-csrf-protection-disabled.yaml`
> CSRF protection is disabled for this configuration. This is a security risk. Make sure that it is safe or consider setting `csrf_protection` property to `true`.

---

**`symfony-non-literal-redirect`** | WARNING | `community-rules\php\symfony\security\audit\symfony-non-literal-redirect.yaml`
> The `redirect()` method does not check its destination in any way. If you redirect to a URL provided by end-users, your application may be open to the unvalidated redirects security vulnerability. Consider using literal values or an allowlist to validate URLs.

---

**`symfony-permissive-cors`** | WARNING | `community-rules\php\symfony\security\audit\symfony-permissive-cors.yaml`
> Access-Control-Allow-Origin response header is set to "*". This will disable CORS Same Origin Policy restrictions.

---

**`tainted-callable`** | WARNING | `community-rules\php\lang\security\injection\tainted-callable.yaml`
> Callable based on user input risks remote code execution.

---

**`tainted-exec`** | ERROR | `community-rules\php\lang\security\tainted-exec.yaml`
> Executing non-constant commands. This can lead to command injection. You should use `escapeshellarg()` when using command.

---

**`tainted-exec`** | WARNING | `community-rules\php\lang\security\injection\tainted-exec.yaml`
> User input is passed to a function that executes a shell command. This can lead to remote code execution.

---

**`tainted-filename`** | WARNING | `community-rules\php\lang\security\injection\tainted-filename.yaml`
> File name based on user input risks server-side request forgery.

---

**`tainted-object-instantiation`** | WARNING | `community-rules\php\lang\security\injection\tainted-object-instantiation.yaml`
> <- A new object is created where the class name is based on user input. This could lead to remote code execution, as it allows to instantiate any class in the application.

---

**`tainted-session`** | WARNING | `community-rules\php\lang\security\injection\tainted-session.yaml`
> Session key based on user input risks session poisoning. The user can determine the key used for the session, and thus write any session variable. Session variables are typically trusted to be set only by the application, and manipulating the session can result in access control issues.

---

**`tainted-sql-string`** | ERROR | `community-rules\php\lang\security\injection\tainted-sql-string.yaml`
> User data flows into this manually-constructed SQL string. User data can be safely inserted into SQL strings using prepared statements or an object-relational mapper (ORM). Manually-constructed SQL strings is a possible indicator of SQL injection, which could let an attacker steal or manipulate data from the database. Instead, use prepared statements (`$mysqli->prepare("INSERT INTO test(id, label) VALUES (?, ?)");`) or a safe library.

---

**`tainted-url-host`** | WARNING | `community-rules\php\lang\security\injection\tainted-url-host.yaml`
> User data flows into the host portion of this manually-constructed URL. This could allow an attacker to send data to their own server, potentially exposing sensitive data such as cookies or authorization information sent with this request. They could also probe internal servers or other resources that the server running this code can access. (This is called server-side request forgery, or SSRF.) Do not allow arbitrary hosts. Instead, create an allowlist for approved hosts, or hardcode the correct host.

---

**`unlink-use`** | WARNING | `community-rules\php\lang\security\unlink-use.yaml`
> Using user input when deleting files with `unlink()` is potentially dangerous. A malicious actor could use this to modify or access files they have no right to.

---

**`unserialize-use`** | WARNING | `community-rules\php\lang\security\unserialize-use.yaml`
> Calling `unserialize()` with user input in the pattern can lead to arbitrary code execution. Consider using JSON or structured data approaches (e.g. Google Protocol Buffers).

---

**`weak-crypto`** | ERROR | `community-rules\php\lang\security\weak-crypto.yaml`
> Detected usage of weak crypto function. Consider using stronger alternatives.

---

**`wp-ajax-no-auth-and-auth-hooks-audit`** | WARNING | `community-rules\php\wordpress-plugins\security\audit\wp-ajax-no-auth-and-auth-hooks-audit.yaml`
> These hooks allow the developer to handle the custom AJAX endpoints."wp_ajax_$action" hook get fires for any authenticated user and "wp_ajax_nopriv_$action" hook get fires for non-authenticated users.

---

**`wp-authorisation-checks-audit`** | WARNING | `community-rules\php\wordpress-plugins\security\audit\wp-authorisation-checks-audit.yaml`
> These are some of the patterns used for authorisation. Look properly if the authorisation is proper or not.

---

**`wp-code-execution-audit`** | WARNING | `community-rules\php\wordpress-plugins\security\audit\wp-code-execution-audit.yaml`
> These functions can lead to code injection if the data inside them is user-controlled. Don't use the input directly or validate the data properly before passing it to these functions.

---

**`wp-command-execution-audit`** | WARNING | `community-rules\php\wordpress-plugins\security\audit\wp-command-execution-audit.yaml`
> These functions can lead to command execution if the data inside them is user-controlled. Don't use the input directly or validate the data properly before passing it to these functions.

---

**`wp-csrf-audit`** | WARNING | `community-rules\php\wordpress-plugins\security\audit\wp-csrf-audit.yaml`
> Passing false or 0 as the third argument to this function will not cause the script to die, making the check useless.

---

**`wp-file-download-audit`** | WARNING | `community-rules\php\wordpress-plugins\security\audit\wp-file-download-audit.yaml`
> These functions can be used to read to content of the files if the data inside is user-controlled. Don't use the input directly or validate the data properly before passing it to these functions.

---

**`wp-file-inclusion-audit`** | WARNING | `community-rules\php\wordpress-plugins\security\audit\wp-file-inclusion-audit.yaml`
> These functions can lead to Local File Inclusion (LFI) or Remote File Inclusion (RFI) if the data inside is user-controlled. Validate the data properly before passing it to these functions.

---

**`wp-file-manipulation-audit`** | WARNING | `community-rules\php\wordpress-plugins\security\audit\wp-file-manipulation-audit.yaml`
> These functions can be used to delete the files if the data inside the functions are user controlled. Use these functions carefully.

---

**`wp-open-redirect-audit`** | WARNING | `community-rules\php\wordpress-plugins\security\audit\wp-open-redirect-audit.yaml`
> This function can be used to redirect to user supplied URLs. If user input is not sanitised or validated, this could lead to Open Redirect vulnerabilities. Use "wp_safe_redirect()" to prevent this kind of attack.

---

**`wp-php-object-injection-audit`** | WARNING | `community-rules\php\wordpress-plugins\security\audit\wp-php-object-injection-audit.yaml`
> If the data used inside the patterns are directly used without proper sanitization, then this could lead to PHP Object Injection. Do not use these function with user-supplied input, use JSON functions instead.

---

**`wp-sql-injection-audit`** | WARNING | `community-rules\php\wordpress-plugins\security\audit\wp-sql-injection-audit.yaml`
> Detected unsafe API methods. This could lead to SQL Injection if the used variable in the functions are user controlled and not properly escaped or sanitized. In order to prevent SQL Injection, use safe api methods like "$wpdb->prepare" properly or escape/sanitize the data properly.

---

**`wp-ssrf-audit`** | WARNING | `community-rules\php\wordpress-plugins\security\audit\wp-ssrf-audit.yaml`
> Detected usage of vulnerable functions with user input, which could lead to SSRF vulnerabilities.

---

## Python (405 rules)

**`access-foreign-keys`** | WARNING | `community-rules\python\django\performance\access-foreign-keys.yaml`
> You should use ITEM.user_id rather than ITEM.user.id to prevent running an extra query.

---

**`aiopg-sqli`** | WARNING | `community-rules\python\lang\security\audit\sqli\aiopg-sqli.yaml`
> Detected string concatenation with a non-literal variable in an aiopg Python SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries instead. You can create parameterized queries like so: 'cur.execute("SELECT %s FROM table", (user_value,))'.

---

**`arbitrary-sleep`** | ERROR | `community-rules\python\lang\best-practice\sleep.yaml`
> time.sleep() call; did you mean to leave this in?

---

**`asyncpg-sqli`** | WARNING | `community-rules\python\lang\security\audit\sqli\asyncpg-sqli.yaml`
> Detected string concatenation with a non-literal variable in a asyncpg Python SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries or prepared statements instead. You can create parameterized queries like so: 'conn.fetch("SELECT $1 FROM table", value)'. You can also create prepared statements with 'Connection.prepare': 'stmt = conn.prepare("SELECT $1 FROM table"); await stmt.fetch(user_value)'

---

**`attr-mutable-initializer`** | WARNING | `community-rules\python\attr\correctness\mutable-initializer.yaml`
> Unsafe usage of mutable initializer with attr.s decorator. Multiple instances of this class will re-use the same data structure, which is likely not the desired behavior. Consider instead: replace assignment to mutable initializer (ex. dict() or {}) with attr.ib(factory=type) where type is dict, set, or list

---

**`avoid-accessing-request-in-wrong-handler`** | WARNING | `community-rules\python\flask\correctness\access-request-in-wrong-handler.yaml`
> Accessing request object inside a route handle for HTTP GET command will throw due to missing request body.

---

**`avoid-bind-to-all-interfaces`** | INFO | `community-rules\python\lang\security\audit\network\bind.yaml`
> Running `socket.bind` to 0.0.0.0, or empty string could unexpectedly expose the server publicly as it binds to all available interfaces. Consider instead getting correct address from an environment variable or configuration file.

---

**`avoid-cPickle`** | WARNING | `community-rules\python\lang\security\deserialization\pickle.yaml`
> Avoid using `cPickle`, which is known to lead to code execution vulnerabilities. When unpickling, the serialized data could be manipulated to run arbitrary code. Instead, consider serializing the relevant data as JSON or a similar text-based serialization format.

---

**`avoid-dill`** | WARNING | `community-rules\python\lang\security\deserialization\pickle.yaml`
> Avoid using `dill`, which uses `pickle`, which is known to lead to code execution vulnerabilities. When unpickling, the serialized data could be manipulated to run arbitrary code. Instead, consider serializing the relevant data as JSON or a similar text-based serialization format.

---

**`avoid-insecure-deserialization`** | ERROR | `community-rules\python\django\security\audit\avoid-insecure-deserialization.yaml`
> Avoid using insecure deserialization library, backed by `pickle`, `_pickle`, `cpickle`, `dill`, `shelve`, or `yaml`, which are known to lead to remote code execution vulnerabilities.

---

**`avoid-jsonpickle`** | WARNING | `community-rules\python\lang\security\deserialization\avoid-jsonpickle.yaml`
> Avoid using `jsonpickle`, which is known to lead to code execution vulnerabilities. When unpickling, the serialized data could be manipulated to run arbitrary code. Instead, consider serializing the relevant data using `json` module.

---

**`avoid-mark-safe`** | WARNING | `community-rules\python\django\security\audit\avoid-mark-safe.yaml`
> 'mark_safe()' is used to mark a string as "safe" for HTML output. This disables escaping and could therefore subject the content to XSS attacks. Use 'django.utils.html.format_html()' to build HTML for rendering instead.

---

**`avoid-pickle`** | WARNING | `community-rules\python\lang\security\deserialization\pickle.yaml`
> Avoid using `pickle`, which is known to lead to code execution vulnerabilities. When unpickling, the serialized data could be manipulated to run arbitrary code. Instead, consider serializing the relevant data as JSON or a similar text-based serialization format.

---

**`avoid-pyyaml-load`** | ERROR | `community-rules\python\lang\security\deserialization\avoid-pyyaml-load.yaml`
> Detected a possible YAML deserialization vulnerability. `yaml.unsafe_load`, `yaml.Loader`, `yaml.CLoader`, and `yaml.UnsafeLoader` are all known to be unsafe methods of deserializing YAML. An attacker with control over the YAML input could create special YAML input that allows the attacker to run arbitrary Python code. This would allow the attacker to steal files, download and install malware, or otherwise take over the machine. Use `yaml.safe_load` or `yaml.SafeLoader` instead.

---

**`avoid-query-set-extra`** | WARNING | `community-rules\python\django\security\audit\query-set-extra.yaml`
> QuerySet.extra' does not provide safeguards against SQL injection and requires very careful use. SQL injection can lead to critical data being stolen by attackers. Instead of using '.extra', use the Django ORM and parameterized queries such as `People.objects.get(name='Bob')`.

---

**`avoid-raw-sql`** | WARNING | `community-rules\python\django\security\audit\raw-query.yaml`
> Detected the use of 'RawSQL' or 'raw' indicating the execution of a non-parameterized SQL query. This could lead to a SQL injection and therefore protected information could be leaked. Instead, use Django ORM and parameterized queries before raw SQL. An example of using the Django ORM is: `People.objects.get(name='Bob')`

---

**`avoid-shelve`** | WARNING | `community-rules\python\lang\security\deserialization\pickle.yaml`
> Avoid using `shelve`, which uses `pickle`, which is known to lead to code execution vulnerabilities. When unpickling, the serialized data could be manipulated to run arbitrary code. Instead, consider serializing the relevant data as JSON or a similar text-based serialization format.

---

**`avoid-sqlalchemy-text`** | ERROR | `community-rules\python\sqlalchemy\security\audit\avoid-sqlalchemy-text.yaml`
> sqlalchemy.text passes the constructed SQL statement to the database mostly unchanged. This means that the usual SQL injection protections are not applied and this function is vulnerable to SQL injection if user input can reach here. Use normal SQLAlchemy operators (such as `or_()`, `and_()`, etc.) to construct SQL.

---

**`avoid-unsafe-ruamel`** | ERROR | `community-rules\python\lang\security\deserialization\avoid-unsafe-ruamel.yaml`
> Avoid using unsafe `ruamel.yaml.YAML()`. `ruamel.yaml.YAML` can create arbitrary Python objects. A malicious actor could exploit this to run arbitrary code. Use `YAML(typ='rt')` or `YAML(typ='safe')` instead.

---

**`avoid_app_run_with_bad_host`** | WARNING | `community-rules\python\flask\security\audit\app-run-param-config.yaml`
> Running flask app with host 0.0.0.0 could expose the server publicly.

---

**`avoid_hardcoded_config_DEBUG`** | WARNING | `community-rules\python\flask\security\audit\hardcoded-config.yaml`
> Hardcoded variable `DEBUG` detected. Set this by using FLASK_DEBUG environment variable

---

**`avoid_hardcoded_config_ENV`** | WARNING | `community-rules\python\flask\security\audit\hardcoded-config.yaml`
> Hardcoded variable `ENV` detected. Set this by using FLASK_ENV environment variable

---

**`avoid_hardcoded_config_SECRET_KEY`** | ERROR | `community-rules\python\flask\security\audit\hardcoded-config.yaml`
> Hardcoded variable `SECRET_KEY` detected. Use environment variables or config files instead

---

**`avoid_hardcoded_config_TESTING`** | WARNING | `community-rules\python\flask\security\audit\hardcoded-config.yaml`
> Hardcoded variable `TESTING` detected. Use environment variables or config files instead

---

**`avoid_send_file_without_path_sanitization`** | WARNING | `community-rules\python\flask\security\secure-static-file-serve.yaml`
> Detected a user-controlled `filename` that could flow to `flask.send_file()` function. This could lead to an attacker reading arbitrary file from the system, leaking private information. Make sure to properly sanitize filename or use `flask.send_from_directory`

---

**`avoid_using_app_run_directly`** | WARNING | `community-rules\python\flask\security\audit\app-run-security-config.yaml`
> top-level app.run(...) is ignored by flask. Consider putting app.run(...) behind a guard, like inside a function

---

**`bad-operator-in-filter`** | WARNING | `community-rules\python\sqlalchemy\correctness\bad-operator-in-filter.yaml`
> Only comparison operators should be used inside SQLAlchemy filter expressions. Use `==` instead of `is`, `!=` instead of `is not`, `sqlalchemy.and_` instead of `and`, `sqlalchemy.or_` instead of `or`, `sqlalchemy.not_` instead of `not`, and `sqlalchemy.in_` instead of `in_`.

---

**`baseclass-attribute-override`** | WARNING | `community-rules\python\lang\correctness\baseclass-attribute-override.yaml`
> Class $C inherits from both `$A` and `$B` which both have a method named `$F`; one of these methods will be overwritten.

---

**`batch-import`** | WARNING | `community-rules\python\sqlalchemy\performance\performance-improvements.yaml`
> Rather than adding one element at a time, consider batch loading to improve performance.

---

**`bokeh-deprecated-apis`** | WARNING | `community-rules\python\bokeh\maintainability\deprecated\deprecated_apis.yaml`
> These APIs are deprecated in Bokeh see https://docs.bokeh.org/en/latest/docs/releases.html#api-deprecations

---

**`cannot-cache-generators`** | WARNING | `community-rules\python\lang\correctness\cannot-cache-generators.yaml`
> Generators can only be consumed once, so in most cases, caching them will cause an error when the already-consumed generator is retrieved from cache.

---

**`check-is-none-explicitly`** | WARNING | `community-rules\python\correctness\check-is-none-explicitly.yaml`
> This expression will always return False because 0 is a false-y value. So if $X is 0, then the first part of this expression will return False but if it is not, the second part will return False. Perhaps you meant to check if $X was None explicitly.

---

**`class-extends-safestring`** | WARNING | `community-rules\python\django\security\audit\xss\class-extends-safestring.yaml`
> Found a class extending 'SafeString', 'SafeText' or 'SafeData'. These classes are for bypassing the escaping engine built in to Django and should not be used directly. Improper use of this class exposes your application to cross-site scripting (XSS) vulnerabilities. If you need this functionality, use 'mark_safe' instead and ensure no user data can reach it.

---

**`code-after-unconditional-return`** | WARNING | `community-rules\python\lang\maintainability\return.yaml`
> code after return statement will not be executed

---

**`command-injection-os-system`** | ERROR | `community-rules\python\django\security\injection\command\command-injection-os-system.yaml`
> Request data detected in os.system. This could be vulnerable to a command injection and should be avoided. If this must be done, use the 'subprocess' module instead and pass the arguments as a list. See https://owasp.org/www-community/attacks/Command_Injection for more information.

---

**`conflicting-path-assignment`** | ERROR | `community-rules\python\django\maintainability\duplicate-path-assignment.yaml`
> The path for `$URL` is assigned once to view `$VIEW` and once to `$DIFFERENT_VIEW`, which can lead to unexpected behavior. Verify what the intended target view is and delete the other route.

---

**`context-autoescape-off`** | WARNING | `community-rules\python\django\security\audit\xss\context-autoescape-off.yaml`
> Detected a Context with autoescape disabled. If you are rendering any web pages, this exposes your application to cross-site scripting (XSS) vulnerabilities. Remove 'autoescape: False' or set it to 'True'.

---

**`crypto-mode-without-authentication`** | ERROR | `community-rules\python\cryptography\security\mode-without-authentication.yaml`
> An encryption mode of operation is being used without proper message authentication. This can potentially result in the encrypted content to be decrypted by an attacker. Consider instead use an AEAD mode of operation like GCM. 

---

**`crypto-mode-without-authentication`** | ERROR | `community-rules\python\pycryptodome\security\mode-without-authentication.yaml`
> An encryption mode of operation is being used without proper message authentication. This can potentially result in the encrypted content to be decrypted by an attacker. Consider instead use an AEAD mode of operation like GCM. 

---

**`csv-writer-injection`** | ERROR | `community-rules\python\django\security\injection\csv-writer-injection.yaml`
> Detected user input into a generated CSV file using the built-in `csv` module. If user data is used to generate the data in this file, it is possible that an attacker could inject a formula when the CSV is imported into a spreadsheet application that runs an attacker script, which could steal data from the importing user or, at worst, install malware on the user's computer. `defusedcsv` is a drop-in replacement with the same API that will attempt to mitigate formula injection attempts. You can use `defusedcsv` instead of `csv` to safely generate CSVs.

---

**`csv-writer-injection`** | ERROR | `community-rules\python\flask\security\injection\csv-writer-injection.yaml`
> Detected user input into a generated CSV file using the built-in `csv` module. If user data is used to generate the data in this file, it is possible that an attacker could inject a formula when the CSV is imported into a spreadsheet application that runs an attacker script, which could steal data from the importing user or, at worst, install malware on the user's computer. `defusedcsv` is a drop-in replacement with the same API that will attempt to mitigate formula injection attempts. You can use `defusedcsv` instead of `csv` to safely generate CSVs.

---

**`custom-expression-as-sql`** | WARNING | `community-rules\python\django\security\audit\custom-expression-as-sql.yaml`
> Detected a Custom Expression ''$EXPRESSION'' calling ''as_sql(...).'' This could lead to SQL injection, which can result in attackers exfiltrating sensitive data. Instead, ensure no user input enters this function or that user input is properly sanitized.

---

**`dangerous-annotations-usage`** | INFO | `community-rules\python\lang\security\audit\dangerous-annotations-usage.yaml`
> Annotations passed to `typing.get_type_hints` are evaluated in `globals` and `locals` namespaces. Make sure that no arbitrary value can be written as the annotation and passed to `typing.get_type_hints` function.

---

**`dangerous-asyncio-create-exec`** | ERROR | `community-rules\python\aws-lambda\security\dangerous-asyncio-create-exec.yaml`
> Detected 'create_subprocess_exec' function with argument tainted by `event` object. If this data can be controlled by a malicious actor, it may be an instance of command injection. Audit the use of this call to ensure it is not controllable by an external resource. You may consider using 'shlex.escape()'.

---

**`dangerous-asyncio-create-exec-audit`** | ERROR | `community-rules\python\lang\security\audit\dangerous-asyncio-create-exec-audit.yaml`
> Detected 'create_subprocess_exec' function without a static string. If this data can be controlled by a malicious actor, it may be an instance of command injection. Audit the use of this call to ensure it is not controllable by an external resource. You may consider using 'shlex.escape()'.

---

**`dangerous-asyncio-create-exec-tainted-env-args`** | ERROR | `community-rules\python\lang\security\audit\dangerous-asyncio-create-exec-tainted-env-args.yaml`
> Detected 'create_subprocess_exec' function with user controlled data. You may consider using 'shlex.escape()'.

---

**`dangerous-asyncio-exec`** | ERROR | `community-rules\python\aws-lambda\security\dangerous-asyncio-exec.yaml`
> Detected subprocess function '$LOOP.subprocess_exec' with argument tainted by `event` object. If this data can be controlled by a malicious actor, it may be an instance of command injection. Audit the use of this call to ensure it is not controllable by an external resource. You may consider using 'shlex.escape()'.

---

**`dangerous-asyncio-exec-audit`** | ERROR | `community-rules\python\lang\security\audit\dangerous-asyncio-exec-audit.yaml`
> Detected subprocess function '$LOOP.subprocess_exec' without a static string. If this data can be controlled by a malicious actor, it may be an instance of command injection. Audit the use of this call to ensure it is not controllable by an external resource. You may consider using 'shlex.escape()'.

---

**`dangerous-asyncio-exec-tainted-env-args`** | ERROR | `community-rules\python\lang\security\audit\dangerous-asyncio-exec-tainted-env-args.yaml`
> Detected subprocess function '$LOOP.subprocess_exec' with user controlled data. You may consider using 'shlex.escape()'.

---

**`dangerous-asyncio-shell`** | ERROR | `community-rules\python\aws-lambda\security\dangerous-asyncio-shell.yaml`
> Detected asyncio subprocess function with argument tainted by `event` object. If this data can be controlled by a malicious actor, it may be an instance of command injection. Audit the use of this call to ensure it is not controllable by an external resource. You may consider using 'shlex.escape()'.

---

**`dangerous-asyncio-shell-audit`** | ERROR | `community-rules\python\lang\security\audit\dangerous-asyncio-shell-audit.yaml`
> Detected asyncio subprocess function without a static string. If this data can be controlled by a malicious actor, it may be an instance of command injection. Audit the use of this call to ensure it is not controllable by an external resource. You may consider using 'shlex.escape()'.

---

**`dangerous-asyncio-shell-tainted-env-args`** | ERROR | `community-rules\python\lang\security\audit\dangerous-asyncio-shell-tainted-env-args.yaml`
> Detected asyncio subprocess function with user controlled data. You may consider using 'shlex.escape()'.

---

**`dangerous-globals-use`** | WARNING | `community-rules\python\lang\security\dangerous-globals-use.yaml`
> Found non static data as an index to 'globals()'. This is extremely dangerous because it allows an attacker to execute arbitrary code on the system. Refactor your code not to use 'globals()'.

---

**`dangerous-interactive-code-run`** | WARNING | `community-rules\python\lang\security\dangerous-code-run.yaml`
> Found user controlled data inside InteractiveConsole/InteractiveInterpreter method. This is dangerous if external data can reach this function call because it allows a malicious actor to run arbitrary Python code.

---

**`dangerous-interactive-code-run-audit`** | WARNING | `community-rules\python\lang\security\audit\dangerous-code-run-audit.yaml`
> Found dynamic content inside InteractiveConsole/InteractiveInterpreter method. This is dangerous if external data can reach this function call because it allows a malicious actor to run arbitrary Python code. Ensure no external data reaches here.

---

**`dangerous-interactive-code-run-tainted-env-args`** | WARNING | `community-rules\python\lang\security\audit\dangerous-code-run-tainted-env-args.yaml`
> Found user controlled data inside InteractiveConsole/InteractiveInterpreter method. This is dangerous if external data can reach this function call because it allows a malicious actor to run arbitrary Python code.

---

**`dangerous-os-exec`** | ERROR | `community-rules\python\lang\security\dangerous-os-exec.yaml`
> Found user controlled content when spawning a process. This is dangerous because it allows a malicious actor to execute commands.

---

**`dangerous-os-exec-audit`** | ERROR | `community-rules\python\lang\security\audit\dangerous-os-exec-audit.yaml`
> Found dynamic content when spawning a process. This is dangerous if external data can reach this function call because it allows a malicious actor to execute commands. Ensure no external data reaches here.

---

**`dangerous-os-exec-tainted-env-args`** | ERROR | `community-rules\python\lang\security\audit\dangerous-os-exec-tainted-env-args.yaml`
> Found user controlled content when spawning a process. This is dangerous because it allows a malicious actor to execute commands.

---

**`dangerous-spawn-process`** | ERROR | `community-rules\python\aws-lambda\security\dangerous-spawn-process.yaml`
> Detected `os` function with argument tainted by `event` object. This is dangerous if external data can reach this function call because it allows a malicious actor to execute commands. Ensure no external data reaches here.

---

**`dangerous-spawn-process`** | ERROR | `community-rules\python\lang\security\dangerous-spawn-process.yaml`
> Found user controlled content when spawning a process. This is dangerous because it allows a malicious actor to execute commands.

---

**`dangerous-spawn-process-audit`** | ERROR | `community-rules\python\lang\security\audit\dangerous-spawn-process-audit.yaml`
> Found dynamic content when spawning a process. This is dangerous if external data can reach this function call because it allows a malicious actor to execute commands. Ensure no external data reaches here.

---

**`dangerous-spawn-process-tainted-env-args`** | ERROR | `community-rules\python\lang\security\audit\dangerous-spawn-process-tainted-env-args.yaml`
> Found user controlled content when spawning a process. This is dangerous because it allows a malicious actor to execute commands.

---

**`dangerous-subinterpreters-run-string`** | WARNING | `community-rules\python\lang\security\dangerous-subinterpreters-run-string.yaml`
> Found user controlled content in `run_string`. This is dangerous because it allows a malicious actor to run arbitrary Python code.

---

**`dangerous-subinterpreters-run-string-audit`** | WARNING | `community-rules\python\lang\security\audit\dangerous-subinterpreters-run-string-audit.yaml`
> Found dynamic content in `run_string`. This is dangerous if external data can reach this function call because it allows a malicious actor to run arbitrary Python code. Ensure no external data reaches here.

---

**`dangerous-subinterpreters-run-string-tainted-env-args`** | WARNING | `community-rules\python\lang\security\audit\dangerous-subinterpreters-run-string-tainted-env-args.yaml`
> Found user controlled content in `run_string`. This is dangerous because it allows a malicious actor to run arbitrary Python code.

---

**`dangerous-subprocess-use`** | ERROR | `community-rules\python\aws-lambda\security\dangerous-subprocess-use.yaml`
> Detected subprocess function with argument tainted by an `event` object.  If this data can be controlled by a malicious actor, it may be an instance of command injection. The default option for `shell` is False, and this is secure by default. Consider removing the `shell=True` or setting it to False explicitely. Using `shell=False` means you have to split the command string into an array of strings for the command and its arguments. You may consider using 'shlex.split()' for this purpose.

---

**`dangerous-subprocess-use`** | ERROR | `community-rules\python\lang\security\dangerous-subprocess-use.yaml`
> Detected subprocess function '$FUNC' with user controlled data. A malicious actor could leverage this to perform command injection. You may consider using 'shlex.escape()'.

---

**`dangerous-subprocess-use-audit`** | ERROR | `community-rules\python\lang\security\audit\dangerous-subprocess-use-audit.yaml`
> Detected subprocess function '$FUNC' without a static string. If this data can be controlled by a malicious actor, it may be an instance of command injection. Audit the use of this call to ensure it is not controllable by an external resource. You may consider using 'shlex.escape()'.

---

**`dangerous-subprocess-use-tainted-env-args`** | ERROR | `community-rules\python\lang\security\audit\dangerous-subprocess-use-tainted-env-args.yaml`
> Detected subprocess function '$FUNC' with user controlled data. A malicious actor could leverage this to perform command injection. You may consider using 'shlex.quote()'.

---

**`dangerous-system-call`** | ERROR | `community-rules\python\aws-lambda\security\dangerous-system-call.yaml`
> Detected `os` function with argument tainted by `event` object. This is dangerous if external data can reach this function call because it allows a malicious actor to execute commands. Use the 'subprocess' module instead, which is easier to use without accidentally exposing a command injection vulnerability.

---

**`dangerous-system-call`** | ERROR | `community-rules\python\lang\security\dangerous-system-call.yaml`
> Found user-controlled data used in a system call. This could allow a malicious actor to execute commands. Use the 'subprocess' module instead, which is easier to use without accidentally exposing a command injection vulnerability.

---

**`dangerous-system-call-audit`** | ERROR | `community-rules\python\lang\security\audit\dangerous-system-call-audit.yaml`
> Found dynamic content used in a system call. This is dangerous if external data can reach this function call because it allows a malicious actor to execute commands. Use the 'subprocess' module instead, which is easier to use without accidentally exposing a command injection vulnerability.

---

**`dangerous-system-call-tainted-env-args`** | ERROR | `community-rules\python\lang\security\audit\dangerous-system-call-tainted-env-args.yaml`
> Found user-controlled data used in a system call. This could allow a malicious actor to execute commands. Use the 'subprocess' module instead, which is easier to use without accidentally exposing a command injection vulnerability.

---

**`dangerous-template-string`** | ERROR | `community-rules\python\flask\security\dangerous-template-string.yaml`
> Found a template created with string formatting. This is susceptible to server-side template injection and cross-site scripting attacks.

---

**`dangerous-testcapi-run-in-subinterp`** | WARNING | `community-rules\python\lang\security\dangerous-testcapi-run-in-subinterp.yaml`
> Found user controlled content in `run_in_subinterp`. This is dangerous because it allows a malicious actor to run arbitrary Python code.

---

**`dangerous-testcapi-run-in-subinterp-audit`** | WARNING | `community-rules\python\lang\security\audit\dangerous-testcapi-run-in-subinterp-audit.yaml`
> Found dynamic content in `run_in_subinterp`. This is dangerous if external data can reach this function call because it allows a malicious actor to run arbitrary Python code. Ensure no external data reaches here.

---

**`dangerous-testcapi-run-in-subinterp-tainted-env-args`** | WARNING | `community-rules\python\lang\security\audit\dangerous-testcapi-run-in-subinterp-tainted-env-args.yaml`
> Found user controlled content in `run_in_subinterp`. This is dangerous because it allows a malicious actor to run arbitrary Python code.

---

**`debug-enabled`** | WARNING | `community-rules\python\flask\security\audit\debug-enabled.yaml`
> Detected Flask app with debug=True. Do not deploy to production with this flag enabled as it will leak sensitive information. Instead, consider using Flask configuration variables or setting 'debug' using system environment variables.

---

**`debug-template-tag`** | WARNING | `community-rules\python\django\security\audit\templates\debug-template-tag.yaml`
> Detected a debug template tag in a Django template. This dumps debugging information to the page when debug mode is enabled. Showing debug information to users is dangerous because it may reveal information about your environment that malicious actors can use to gain access to the system. Remove the debug tag.

---

**`default-mutable-dict`** | ERROR | `community-rules\python\lang\correctness\common-mistakes\default-mutable-dict.yaml`
> Function $F mutates default dict $D. Python only instantiates default function arguments once and shares the instance across the function calls. If the default function argument is mutated, that will modify the instance used by all future function calls. This can cause unexpected results, or lead to security vulnerabilities whereby one function consumer can view or modify the data of another function consumer. Instead, use a default argument (like None) to indicate that no argument was provided and instantiate a new dictionary at that time. For example: `if $D is None: $D = {}`.

---

**`default-mutable-list`** | ERROR | `community-rules\python\lang\correctness\common-mistakes\default-mutable-list.yaml`
> Function $F mutates default list $D. Python only instantiates default function arguments once and shares the instance across the function calls. If the default function argument is mutated, that will modify the instance used by all future function calls. This can cause unexpected results, or lead to security vulnerabilities whereby one function consumer can view or modify the data of another function consumer. Instead, use a default argument (like None) to indicate that no argument was provided and instantiate a new list at that time. For example: `if $D is None: $D = []`.

---

**`delete-where-no-execute`** | ERROR | `community-rules\python\sqlalchemy\correctness\delete-where.yaml`
> .delete().where(...) results in a no-op in SQLAlchemy unless the command is executed, use .filter(...).delete() instead.

---

**`dict-del-while-iterate`** | WARNING | `community-rules\python\lang\correctness\dict-modify-iterating.yaml`
> It appears that `$DICT[$KEY]` is a dict with items being deleted while in a for loop. This is usually a bad idea and will likely lead to a RuntimeError: dictionary changed size during iteration

---

**`direct-use-of-httpresponse`** | WARNING | `community-rules\python\django\security\audit\xss\direct-use-of-httpresponse.yaml`
> Detected data rendered directly to the end user via 'HttpResponse' or a similar object. This bypasses Django's built-in cross-site scripting (XSS) defenses and could result in an XSS vulnerability. Use Django's template engine to safely render HTML.

---

**`direct-use-of-jinja2`** | WARNING | `community-rules\python\flask\security\xss\audit\direct-use-of-jinja2.yaml`
> Detected direct use of jinja2. If not done properly, this may bypass HTML escaping which opens up the application to cross-site scripting (XSS) vulnerabilities. Prefer using the Flask method 'render_template()' and templates with a '.html' extension in order to prevent XSS.

---

**`directly-returned-format-string`** | WARNING | `community-rules\python\flask\security\audit\directly-returned-format-string.yaml`
> Detected Flask route directly returning a formatted string. This is subject to cross-site scripting if user input can reach the string. Consider using the template engine instead and rendering pages with 'render_template()'.

---

**`disabled-cert-validation`** | ERROR | `community-rules\python\lang\security\audit\network\disabled-cert-validation.yaml`
> certificate verification explicitly disabled, insecure connections possible

---

**`disabled-cert-validation`** | ERROR | `community-rules\python\requests\security\disabled-cert-validation.yaml`
> Certificate verification has been explicitly disabled. This permits insecure connections to insecure servers. Re-enable certification validation.

---

**`django-compat-2_0-assert-redirects-helper`** | WARNING | `community-rules\python\django\compatibility\django-2_0-compat.yaml`
> The host argument to assertRedirects is removed in Django 2.0.

---

**`django-compat-2_0-assignment-tag`** | WARNING | `community-rules\python\django\compatibility\django-2_0-compat.yaml`
> The assignment_tag helper is removed in Django 2.0.

---

**`django-compat-2_0-check-aggregate-support`** | WARNING | `community-rules\python\django\compatibility\django-2_0-compat.yaml`
> django.db.backends.base.BaseDatabaseOperations.check_aggregate_support() is removed in Django 2.0.

---

**`django-compat-2_0-extra-forms`** | WARNING | `community-rules\python\django\compatibility\django-2_0-compat.yaml`
> The django.forms.extras package is removed in Django 2.0.

---

**`django-compat-2_0-signals-weak`** | WARNING | `community-rules\python\django\compatibility\django-2_0-compat.yaml`
> The weak argument to django.dispatch.signals.Signal.disconnect() is removed in Django 2.0.

---

**`django-db-model-save-super`** | WARNING | `community-rules\python\django\correctness\model-save.yaml`
> Detected a django model `$MODEL` is not calling super().save() inside of the save method.

---

**`django-no-csrf-token`** | WARNING | `community-rules\python\django\security\django-no-csrf-token.yaml`
> Manually-created forms in django templates should specify a csrf_token to prevent CSRF attacks.

---

**`django-secure-set-cookie`** | WARNING | `community-rules\python\django\security\audit\secure-cookies.yaml`
> Django cookies should be handled securely by setting secure=True, httponly=True, and samesite='Lax' in response.set_cookie(...). If your situation calls for different settings, explicitly disable the setting. If you want to send the cookie over http, set secure=False. If you want to let client-side JavaScript read the cookie, set httponly=False. If you want to attach cookies to requests for external sites, set samesite=None.

---

**`django-using-request-post-after-is-valid`** | WARNING | `community-rules\python\django\security\django-using-request-post-after-is-valid.yaml`
> Use $FORM.cleaned_data[] instead of request.POST[] after form.is_valid() has been executed to only access sanitized data

---

**`docker-arbitrary-container-run`** | WARNING | `community-rules\python\docker\security\audit\docker-arbitrary-container-run.yaml`
> If unverified user data can reach the `run` or `create` method it can result in running arbitrary container.

---

**`duplicate-name-assignment`** | ERROR | `community-rules\python\django\maintainability\duplicate-path-assignment.yaml`
> The name `$NAME` is used for both `$URL` and `$OTHER_URL`, which can lead to unexpected behavior when using URL reversing. Pick a unique name for each path.

---

**`duplicate-path-assignment`** | WARNING | `community-rules\python\django\maintainability\duplicate-path-assignment.yaml`
> path for `$URL` is uselessly assigned twice

---

**`duplicate-path-assignment-different-names`** | WARNING | `community-rules\python\django\maintainability\duplicate-path-assignment.yaml`
> path for `$URL` is assigned twice with different names

---

**`dynamic-urllib-use-detected`** | WARNING | `community-rules\python\lang\security\audit\dynamic-urllib-use-detected.yaml`
> Detected a dynamic value being used with urllib. urllib supports 'file://' schemes, so a dynamic value controlled by a malicious actor may allow them to read arbitrary files. Audit uses of urllib calls to ensure user data cannot control the URLs, or consider using the 'requests' library instead.

---

**`dynamodb-filter-injection`** | ERROR | `community-rules\python\aws-lambda\security\dynamodb-filter-injection.yaml`
> Detected DynamoDB query filter that is tainted by `$EVENT` object. This could lead to NoSQL injection if the variable is user-controlled and not properly sanitized. Explicitly assign query params instead of passing data from `$EVENT` directly to DynamoDB client.

---

**`empty-aes-key`** | WARNING | `community-rules\python\cryptography\security\empty-aes-key.yaml`
> Potential empty AES encryption key. Using an empty key in AES encryption can result in weak encryption and may allow attackers to easily decrypt sensitive data. Ensure that a strong, non-empty key is used for AES encryption.

---

**`eval-detected`** | WARNING | `community-rules\python\lang\security\audit\eval-detected.yaml`
> Detected the use of eval(). eval() can be dangerous if used to evaluate dynamic content. If this content can be input from outside the program, this may be a code injection vulnerability. Ensure evaluated content is not definable by external sources.

---

**`eval-injection`** | ERROR | `community-rules\python\flask\security\injection\user-eval.yaml`
> Detected user data flowing into eval. This is code injection and should be avoided.

---

**`exec-detected`** | WARNING | `community-rules\python\lang\security\audit\exec-detected.yaml`
> Detected the use of exec(). exec() can be dangerous if used to evaluate dynamic content. If this content can be input from outside the program, this may be a code injection vulnerability. Ensure evaluated content is not definable by external sources.

---

**`exec-injection`** | ERROR | `community-rules\python\flask\security\injection\user-exec.yaml`
> Detected user data flowing into exec. This is code injection and should be avoided.

---

**`explicit-unescape-with-markup`** | WARNING | `community-rules\python\flask\security\xss\audit\explicit-unescape-with-markup.yaml`
> Detected explicitly unescaped content using 'Markup()'. This permits the unescaped data to include unescaped HTML which could result in cross-site scripting. Ensure this data is not externally controlled, or consider rewriting to not use 'Markup()'.

---

**`extends-custom-expression`** | WARNING | `community-rules\python\django\security\audit\extends-custom-expression.yaml`
> Found extension of custom expression: $CLASS. Extending expressions in this way could inadvertently lead to a SQL injection vulnerability, which can result in attackers exfiltrating sensitive data. Instead, ensure no user input enters this function or that user input is properly sanitized.

---

**`file-object-redefined-before-close`** | WARNING | `community-rules\python\lang\correctness\file-object-redefined-before-close.yaml`
> Detected a file object that is redefined and never closed. This could leak file descriptors and unnecessarily consume system resources.

---

**`filter-with-is-safe`** | WARNING | `community-rules\python\django\security\audit\xss\filter-with-is-safe.yaml`
> Detected Django filters flagged with 'is_safe'. 'is_safe' tells Django not to apply escaping on the value returned by this filter (although the input is escaped). Used improperly, 'is_safe' could expose your application to cross-site scripting (XSS) vulnerabilities. Ensure this filter does not 1) add HTML characters, 2) remove characters, or 3) use external data in any way. Consider instead removing 'is_safe' and explicitly marking safe content with 'mark_safe()'.

---

**`flask-api-method-string-format`** | ERROR | `community-rules\python\flask\security\flask-api-method-string-format.yaml`
> Method $METHOD in API controller $CLASS provides user arg $ARG to requests method $REQMETHOD

---

**`flask-cache-query-string`** | WARNING | `community-rules\python\flask\caching\query-string.yaml`
> Flask-caching doesn't cache query strings by default. You have to use `query_string=True`. Also you shouldn't cache verbs that can mutate state.

---

**`flask-class-method-get-side-effects`** | WARNING | `community-rules\python\flask\best-practice\get-class-method-with-side-effects.yaml`
> Flask class method GET with side effects

---

**`flask-cors-misconfiguration`** | WARNING | `community-rules\python\flask\security\audit\flask-cors-misconfiguration.yaml`
> Setting 'support_credentials=True' together with 'origin="*"' is a CORS misconfiguration that can allow third party origins to read sensitive data. Using this configuration, flask_cors will dynamically reflects the Origin of each request in the Access-Control-Allow-Origin header, allowing all origins and allowing cookies and credentials to be sent along with request. It is recommended to specify allowed origins instead of using "*" when setting 'support_credentials=True'.

---

**`flask-deprecated-apis`** | WARNING | `community-rules\python\flask\maintainability\deprecated\deprecated-apis.yaml`
> deprecated Flask API

---

**`flask-duplicate-handler-name`** | WARNING | `community-rules\python\flask\correctness\same-handler-name.yaml`
> Looks like `$R` is a flask function handler that registered to two different routes. This will cause a runtime error

---

**`flask-url-for-external-true`** | WARNING | `community-rules\python\flask\security\audit\flask-url-for-external-true.yaml`
> Function `flask.url_for` with `_external=True` argument will generate URLs using the `Host` header of the HTTP request, which may lead to security risks such as Host header injection

---

**`flask-wtf-csrf-disabled`** | WARNING | `community-rules\python\flask\security\audit\wtf-csrf-disabled.yaml`
> Setting 'WTF_CSRF_ENABLED' to 'False' explicitly disables CSRF protection.

---

**`formathtml-fstring-parameter`** | WARNING | `community-rules\python\django\security\audit\xss\formathtml-fstring-parameter.yaml`
> Passing a formatted string as first parameter to `format_html` disables the proper encoding of variables. Any HTML in the first parameter is not encoded. Using a formatted string as first parameter obscures which parameters are encoded. Correct use of `format_html` is passing a static format string as first parameter, and the variables to substitute as subsequent parameters.

---

**`formatted-sql-query`** | WARNING | `community-rules\python\lang\security\audit\formatted-sql-query.yaml`
> Detected possible formatted SQL query. Use parameterized queries instead.

---

**`formatted-string-bashoperator`** | ERROR | `community-rules\python\airflow\security\audit\formatted-string-bashoperator.yaml`
> Found a formatted string in BashOperator: $CMD. This could be vulnerable to injection. Be extra sure your variables are not controllable by external sources.

---

**`global-autoescape-off`** | WARNING | `community-rules\python\django\security\audit\xss\global-autoescape-off.yaml`
> Autoescape is globally disbaled for this Django application. If you are rendering any web pages, this exposes your application to cross-site scripting (XSS) vulnerabilities. Remove 'autoescape: False' or set it to 'True'.

---

**`globals-as-template-context`** | ERROR | `community-rules\python\django\security\globals-as-template-context.yaml`
> Using 'globals()' as a context to 'render(...)' is extremely dangerous. This exposes Python functions to the template that were not meant to be exposed. An attacker could use these functions to execute code that was not intended to run and could compromise the application. (This is server-side template injection (SSTI)). Do not use 'globals()'. Instead, specify each variable in a dictionary or 'django.template.Context' object, like '{"var1": "hello"}' and use that instead.

---

**`globals-misuse-code-execution`** | WARNING | `community-rules\python\django\security\injection\code\globals-misuse-code-execution.yaml`
> Found request data as an index to 'globals()'. This is extremely dangerous because it allows an attacker to execute arbitrary code on the system. Refactor your code not to use 'globals()'.

---

**`hardcoded-password-default-argument`** | WARNING | `community-rules\python\lang\security\audit\hardcoded-password-default-argument.yaml`
> Hardcoded password is used as a default argument to '$FUNC'. This could be dangerous if a real password is not supplied.

---

**`hardcoded-tmp-path`** | WARNING | `community-rules\python\lang\best-practice\hardcoded-tmp-path.yaml`
> Detected hardcoded temp directory. Consider using 'tempfile.TemporaryFile' instead.

---

**`hardcoded-token`** | WARNING | `community-rules\python\boto3\security\hardcoded-token.yaml`
> A hard-coded credential was detected. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`hashids-with-django-secret`** | ERROR | `community-rules\python\django\security\hashids-with-django-secret.yaml`
> The Django secret key is used as salt in HashIDs. The HashID mechanism is not secure. By observing sufficient HashIDs, the salt used to construct them can be recovered. This means the Django secret key can be obtained by attackers, through the HashIDs.

---

**`hashids-with-flask-secret`** | ERROR | `community-rules\python\flask\security\hashids-with-flask-secret.yaml`
> The Flask secret key is used as salt in HashIDs. The HashID mechanism is not secure. By observing sufficient HashIDs, the salt used to construct them can be recovered. This means the Flask secret key can be obtained by attackers, through the HashIDs.

---

**`host-header-injection-python`** | INFO | `community-rules\python\flask\security\audit\host-header-injection-python.yaml`
> The `flask.request.host` is used to construct an HTTP request.  This can lead to host header injection issues. Vulnerabilities  that generally occur due to this issue are authentication bypasses,  password reset issues, Server-Side-Request-Forgery (SSRF), and many more.  It is recommended to validate the URL before passing it to a  request library, or using application logic such as authentication  or password resets.

---

**`html-magic-method`** | WARNING | `community-rules\python\django\security\audit\xss\html-magic-method.yaml`
> The `__html__` method indicates to the Django template engine that the value is 'safe' for rendering. This means that normal HTML escaping will not be applied to the return value. This exposes your application to cross-site scripting (XSS) vulnerabilities. If you need to render raw HTML, consider instead using `mark_safe()` which more clearly marks the intent to render raw HTML than a class with a magic method.

---

**`html-safe`** | WARNING | `community-rules\python\django\security\audit\xss\html-safe.yaml`
> `html_safe()` add the `__html__` magic method to the provided class. The `__html__` method indicates to the Django template engine that the value is 'safe' for rendering. This means that normal HTML escaping will not be applied to the return value. This exposes your application to cross-site scripting (XSS) vulnerabilities. If you need to render raw HTML, consider instead using `mark_safe()` which more clearly marks the intent to render raw HTML than a class with a magic method.

---

**`http-not-https-connection`** | ERROR | `community-rules\python\lang\security\audit\network\http-not-https-connection.yaml`
> Detected HTTPConnectionPool. This will transmit data in cleartext. It is recommended to use HTTPSConnectionPool instead for to encrypt communications.

---

**`httpsconnection-detected`** | WARNING | `community-rules\python\lang\security\audit\httpsconnection-detected.yaml`
> The HTTPSConnection API has changed frequently with minor releases of Python. Ensure you are using the API for your version of Python securely. For example, Python 3 versions prior to 3.4.3 will not verify SSL certificates by default. See https://docs.python.org/3/library/http.client.html#http.client.HTTPSConnection for more information.

---

**`identical-is-comparison`** | ERROR | `community-rules\python\lang\correctness\common-mistakes\is-comparison-string.yaml`
> Found identical comparison using is. Ensure this is what you intended.

---

**`improper-list-concat`** | INFO | `community-rules\python\lang\maintainability\improper-list-concat.yaml`
> This expression will evaluate to be ONLY value the of the `else` clause if the condition `$EXPRESSION` is false. If you meant to do list concatenation, put parentheses around the entire concatenation expression, like this: `['a', 'b', 'c'] + (['d'] if x else ['e'])`. If this is the intended behavior, the expression may be confusing to others, and you may wish to add parentheses for readability.

---

**`incorrect-autoescape-disabled`** | WARNING | `community-rules\python\jinja2\security\audit\autoescape-disabled-false.yaml`
> Detected a Jinja2 environment with 'autoescaping' disabled. This is dangerous if you are rendering to a browser because this allows for cross-site scripting (XSS) attacks. If you are in a web context, enable 'autoescaping' by setting 'autoescape=True.' You may also consider using 'jinja2.select_autoescape()' to only enable automatic escaping for certain file extensions.

---

**`insecure-cipher-algorithm-arc4`** | WARNING | `community-rules\python\cryptography\security\insecure-cipher-algorithms-arc4.yaml`
> ARC4 (Alleged RC4) is a stream cipher with serious weaknesses in its initial stream output.  Its use is strongly discouraged. ARC4 does not use mode constructions. Use a strong symmetric cipher such as EAS instead. With the `cryptography` package it is recommended to use the `Fernet` which is a secure implementation of AES in CBC mode with a 128-bit key.  Alternatively, keep using the `Cipher` class from the hazmat primitives but use the AES algorithm instead.

---

**`insecure-cipher-algorithm-blowfish`** | WARNING | `community-rules\python\cryptography\security\insecure-cipher-algorithms-blowfish.yaml`
> Blowfish is a block cipher developed by Bruce Schneier. It is known to be susceptible to attacks when using weak keys.  The author has recommended that users of Blowfish move to newer algorithms such as AES. With the `cryptography` package it is recommended to use `Fernet` which is a secure implementation of AES in CBC mode with a 128-bit key.  Alternatively, keep using the `Cipher` class from the hazmat primitives but use the AES algorithm instead.

---

**`insecure-cipher-algorithm-blowfish`** | WARNING | `community-rules\python\pycryptodome\security\insecure-cipher-algorithm-blowfish.yaml`
> Detected Blowfish cipher algorithm which is considered insecure. This algorithm is not cryptographically secure and can be reversed easily. Use secure stream ciphers such as ChaCha20, XChaCha20 and Salsa20, or a block cipher such as AES with a block size of 128 bits. When using a block cipher, use a modern mode of operation that also provides authentication, such as GCM.

---

**`insecure-cipher-algorithm-des`** | WARNING | `community-rules\python\pycryptodome\security\insecure-cipher-algorithm-des.yaml`
> Detected DES cipher or Triple DES algorithm which is considered insecure. This algorithm is not cryptographically secure and can be reversed easily. Use a secure symmetric cipher from the cryptodome package instead. Use secure stream ciphers such as ChaCha20, XChaCha20 and Salsa20, or a block cipher such as AES with a block size of 128 bits. When using a block cipher, use a modern mode of operation that also provides authentication, such as GCM.

---

**`insecure-cipher-algorithm-idea`** | WARNING | `community-rules\python\cryptography\security\insecure-cipher-algorithms.yaml`
> IDEA (International Data Encryption Algorithm) is a block cipher created in 1991.  It is an optional component of the OpenPGP standard. This cipher is susceptible to attacks when using weak keys.  It is recommended that you do not use this cipher for new applications. Use a strong symmetric cipher such as EAS instead. With the `cryptography` package it is recommended to use `Fernet` which is a secure implementation of AES in CBC mode with a 128-bit key.  Alternatively, keep using the `Cipher` class from the hazmat primitives but use the AES algorithm instead.

---

**`insecure-cipher-algorithm-rc2`** | WARNING | `community-rules\python\pycryptodome\security\insecure-cipher-algorithm-rc2.yaml`
> Detected RC2 cipher algorithm which is considered insecure. This algorithm is not cryptographically secure and can be reversed easily. Use secure stream ciphers such as ChaCha20, XChaCha20 and Salsa20, or a block cipher such as AES with a block size of 128 bits. When using a block cipher, use a modern mode of operation that also provides authentication, such as GCM.

---

**`insecure-cipher-algorithm-rc4`** | WARNING | `community-rules\python\pycryptodome\security\insecure-cipher-algorithm-rc4.yaml`
> Detected ARC4 cipher algorithm which is considered insecure. This algorithm is not cryptographically secure and can be reversed easily. Use secure stream ciphers such as ChaCha20, XChaCha20 and Salsa20, or a block cipher such as AES with a block size of 128 bits. When using a block cipher, use a modern mode of operation that also provides authentication, such as GCM.

---

**`insecure-cipher-algorithm-xor`** | WARNING | `community-rules\python\pycryptodome\security\insecure-cipher-algorithm.yaml`
> Detected XOR cipher algorithm which is considered insecure. This algorithm is not cryptographically secure and can be reversed easily. Use AES instead.

---

**`insecure-cipher-mode-ecb`** | WARNING | `community-rules\python\cryptography\security\insecure-cipher-mode-ecb.yaml`
> ECB (Electronic Code Book) is the simplest mode of operation for block ciphers.  Each block of data is encrypted in the same way.  This means identical plaintext blocks will always result in identical ciphertext blocks, which can leave significant patterns in the output. Use a different, cryptographically strong mode instead, such as GCM.

---

**`insecure-deserialization`** | ERROR | `community-rules\python\flask\security\insecure-deserialization.yaml`
> Detected the use of an insecure deserialization library in a Flask route. These libraries are prone to code execution vulnerabilities. Ensure user data does not enter this function. To fix this, try to avoid serializing whole objects. Consider instead using a serializer such as JSON.

---

**`insecure-file-permissions`** | WARNING | `community-rules\python\lang\security\audit\insecure-file-permissions.yaml`
> These permissions `$BITS` are widely permissive and grant access to more people than may be necessary. A good default is `0o644` which gives read and write access to yourself and read access to everyone else.

---

**`insecure-hash-algorithm-md2`** | WARNING | `community-rules\python\pycryptodome\security\insecure-hash-algorithm-md2.yaml`
> Detected MD2 hash algorithm which is considered insecure. MD2 is not collision resistant and is therefore not suitable as a cryptographic signature.  Use a modern hash algorithm from the SHA-2, SHA-3, or BLAKE2 family instead.

---

**`insecure-hash-algorithm-md4`** | WARNING | `community-rules\python\pycryptodome\security\insecure-hash-algorithm-md4.yaml`
> Detected MD4 hash algorithm which is considered insecure. MD4 is not collision resistant and is therefore not suitable as a cryptographic signature. Use a modern hash algorithm from the SHA-2, SHA-3, or BLAKE2 family instead.

---

**`insecure-hash-algorithm-md5`** | WARNING | `community-rules\python\cryptography\security\insecure-hash-algorithms-md5.yaml`
> Detected MD5 hash algorithm which is considered insecure. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.

---

**`insecure-hash-algorithm-md5`** | WARNING | `community-rules\python\lang\security\insecure-hash-algorithms-md5.yaml`
> Detected MD5 hash algorithm which is considered insecure. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.

---

**`insecure-hash-algorithm-md5`** | WARNING | `community-rules\python\pycryptodome\security\insecure-hash-algorithm-md5.yaml`
> Detected MD5 hash algorithm which is considered insecure. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature.  Use a modern hash algorithm from the SHA-2, SHA-3, or BLAKE2 family instead.

---

**`insecure-hash-algorithm-sha1`** | WARNING | `community-rules\python\cryptography\security\insecure-hash-algorithms.yaml`
> Detected SHA1 hash algorithm which is considered insecure. SHA1 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.

---

**`insecure-hash-algorithm-sha1`** | WARNING | `community-rules\python\lang\security\insecure-hash-algorithms.yaml`
> Detected SHA1 hash algorithm which is considered insecure. SHA1 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.

---

**`insecure-hash-algorithm-sha1`** | WARNING | `community-rules\python\pycryptodome\security\insecure-hash-algorithm.yaml`
> Detected SHA1 hash algorithm which is considered insecure. SHA1 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.

---

**`insecure-hash-function`** | WARNING | `community-rules\python\lang\security\insecure-hash-function.yaml`
> Detected use of an insecure MD4 or MD5 hash function. These functions have known vulnerabilities and are considered deprecated. Consider using 'SHA256' or a similar function instead.

---

**`insecure-openerdirector-open`** | WARNING | `community-rules\python\lang\security\audit\insecure-transport\urllib\insecure-openerdirector-open.yaml`
> Detected an unsecured transmission channel. 'OpenerDirector.open(...)' is being used with 'http://'. Use 'https://' instead to secure the channel.

---

**`insecure-openerdirector-open-ftp`** | WARNING | `community-rules\python\lang\security\audit\insecure-transport\urllib\insecure-openerdirector-open-ftp.yaml`
> Detected an unsecured transmission channel. 'OpenerDirector.open(...)' is being used with 'ftp://'. Information sent over this connection will be unencrypted. Consider using SFTP instead. urllib does not support SFTP, so consider a library which supports SFTP.

---

**`insecure-request-object`** | WARNING | `community-rules\python\lang\security\audit\insecure-transport\urllib\insecure-request-object.yaml`
> Detected a 'urllib.request.Request()' object using an insecure transport protocol, 'http://'. This connection will not be encrypted. Use 'https://' instead.

---

**`insecure-request-object-ftp`** | WARNING | `community-rules\python\lang\security\audit\insecure-transport\urllib\insecure-request-object-ftp.yaml`
> Detected a 'urllib.request.Request()' object using an insecure transport protocol, 'ftp://'. This connection will not be encrypted. Consider using SFTP instead. urllib does not support SFTP natively, so consider using a library which supports SFTP.

---

**`insecure-urlopen`** | WARNING | `community-rules\python\lang\security\audit\insecure-transport\urllib\insecure-urlopen.yaml`
> Detected 'urllib.urlopen()' using 'http://'. This request will not be encrypted. Use 'https://' instead.

---

**`insecure-urlopen-ftp`** | WARNING | `community-rules\python\lang\security\audit\insecure-transport\urllib\insecure-urlopen-ftp.yaml`
> Detected 'urllib.urlopen()' using 'ftp://'. This request will not be encrypted. Consider using SFTP instead. urllib does not support SFTP, so consider switching to a library which supports SFTP.

---

**`insecure-urlopener-open`** | WARNING | `community-rules\python\lang\security\audit\insecure-transport\urllib\insecure-urlopener-open.yaml`
> Detected an unsecured transmission channel. 'URLopener.open(...)' is being used with 'http://'. Use 'https://' instead to secure the channel.

---

**`insecure-urlopener-open-ftp`** | WARNING | `community-rules\python\lang\security\audit\insecure-transport\urllib\insecure-urlopener-open-ftp.yaml`
> Detected an insecure transmission channel. 'URLopener.open(...)' is being used with 'ftp://'. Use SFTP instead. urllib does not support SFTP, so consider using a library which supports SFTP.

---

**`insecure-urlopener-retrieve`** | WARNING | `community-rules\python\lang\security\audit\insecure-transport\urllib\insecure-urlopener-retrieve.yaml`
> Detected an unsecured transmission channel. 'URLopener.retrieve(...)' is being used with 'http://'. Use 'https://' instead to secure the channel.

---

**`insecure-urlopener-retrieve-ftp`** | WARNING | `community-rules\python\lang\security\audit\insecure-transport\urllib\insecure-urlopener-retrieve-ftp.yaml`
> Detected an insecure transmission channel. 'URLopener.retrieve(...)' is being used with 'ftp://'. Use SFTP instead. urllib does not support SFTP, so consider using a library which supports SFTP.

---

**`insecure-urlretrieve`** | WARNING | `community-rules\python\lang\security\audit\insecure-transport\urllib\insecure-urlretrieve.yaml`
> Detected 'urllib.urlretrieve()' using 'http://'. This request will not be encrypted. Use 'https://' instead.

---

**`insecure-urlretrieve-ftp`** | WARNING | `community-rules\python\lang\security\audit\insecure-transport\urllib\insecure-urlretrieve-ftp.yaml`
> Detected 'urllib.urlretrieve()' using 'ftp://'. This request will not be encrypted. Use SFTP instead. urllib does not support SFTP, so consider switching to a library which supports SFTP.

---

**`insecure-uuid-version`** | WARNING | `community-rules\python\lang\security\insecure-uuid-version.yaml`
> Using UUID version 1 for UUID generation can lead to predictable UUIDs based on system information (e.g., MAC address, timestamp). This may lead to security risks such as the sandwich attack. Consider using `uuid.uuid4()` instead for better randomness and security.

---

**`insufficient-dsa-key-size`** | WARNING | `community-rules\python\cryptography\security\insufficient-dsa-key-size.yaml`
> Detected an insufficient key size for DSA. NIST recommends a key size of 2048 or higher.

---

**`insufficient-dsa-key-size`** | WARNING | `community-rules\python\pycryptodome\security\insufficient-dsa-key-size.yaml`
> Detected an insufficient key size for DSA. NIST recommends a key size of 2048 or higher.

---

**`insufficient-ec-key-size`** | WARNING | `community-rules\python\cryptography\security\insufficient-ec-key-size.yaml`
> Detected an insufficient curve size for EC. NIST recommends a key size of 224 or higher. For example, use 'ec.SECP256R1'.

---

**`insufficient-rsa-key-size`** | WARNING | `community-rules\python\cryptography\security\insufficient-rsa-key-size.yaml`
> Detected an insufficient key size for RSA. NIST recommends a key size of 2048 or higher.

---

**`insufficient-rsa-key-size`** | WARNING | `community-rules\python\pycryptodome\security\insufficient-rsa-key-size.yaml`
> Detected an insufficient key size for RSA. NIST recommends a key size of 3072 or higher.

---

**`is-function-without-parentheses`** | WARNING | `community-rules\python\lang\maintainability\is-function-without-parentheses.yaml`
> Is "$FUNC" a function or an attribute? If it is a function, you may have meant $X.$FUNC() because $X.$FUNC is always true.

---

**`is-not-is-not`** | ERROR | `community-rules\python\lang\correctness\common-mistakes\is-not-is-not.yaml`
> In Python 'X is not ...' is different from 'X is (not ...)'. In the latter the 'not' converts the '...' directly to boolean.

---

**`jwt-python-exposed-credentials`** | ERROR | `community-rules\python\jwt\security\jwt-exposed-credentials.yaml`
> Password is exposed through JWT token payload. This is not encrypted and the password could be compromised. Do not store passwords in JWT tokens.

---

**`jwt-python-exposed-data`** | WARNING | `community-rules\python\jwt\security\audit\jwt-exposed-data.yaml`
> The object is passed strictly to jwt.encode(...) Make sure that sensitive information is not exposed through JWT token payload.

---

**`jwt-python-hardcoded-secret`** | ERROR | `community-rules\python\jwt\security\jwt-hardcode.yaml`
> Hardcoded JWT secret or private key is used. This is a Insufficiently Protected Credentials weakness: https://cwe.mitre.org/data/definitions/522.html Consider using an appropriate security mechanism to protect the credentials (e.g. keeping secrets in environment variables)

---

**`jwt-python-none-alg`** | ERROR | `community-rules\python\jwt\security\jwt-none-alg.yaml`
> Detected use of the 'none' algorithm in a JWT token. The 'none' algorithm assumes the integrity of the token has already been verified. This would allow a malicious actor to forge a JWT token that will automatically be verified. Do not explicitly use the 'none' algorithm. Instead, use an algorithm such as 'HS256'.

---

**`len-all-count`** | WARNING | `community-rules\python\sqlalchemy\performance\performance-improvements.yaml`
> Using QUERY.count() instead of len(QUERY.all()) sends less data to the client since the SQLAlchemy method is performed server-side.

---

**`list-modify-while-iterate`** | ERROR | `community-rules\python\lang\correctness\list-modify-iterating.yaml`
> It appears that `$LIST` is a list that is being modified while in a for loop. This will likely cause a runtime error or an infinite loop.

---

**`listen-eval`** | WARNING | `community-rules\python\lang\security\audit\logging\listeneval.yaml`
> Because portions of the logging configuration are passed through eval(), use of this function may open its users to a security risk. While the function only binds to a socket on localhost, and so does not accept connections from remote machines, there are scenarios where untrusted code could be run under the account of the process which calls listen(). To avoid this happening, use the `verify()` argument to `listen()` to prevent unrecognized configurations.

---

**`locals-as-template-context`** | ERROR | `community-rules\python\django\security\locals-as-template-context.yaml`
> Using 'locals()' as a context to 'render(...)' is extremely dangerous. This exposes Python functions to the template that were not meant to be exposed. An attacker could use these functions to execute code that was not intended to run and could compromise the application. (This is server-side template injection (SSTI)). Do not use 'locals()'. Instead, specify each variable in a dictionary or 'django.template.Context' object, like '{"var1": "hello"}' and use that instead.

---

**`logging-error-without-handling`** | WARNING | `community-rules\python\lang\best-practice\logging-error-without-handling.yaml`
> Errors should only be logged when handled. The code logs the error and propogates the exception, consider reducing the level to warning or info.

---

**`make-response-with-unknown-content`** | WARNING | `community-rules\python\flask\security\audit\xss\make-response-with-unknown-content.yaml`
> Be careful with `flask.make_response()`. If this response is rendered onto a webpage, this could create a cross-site scripting (XSS) vulnerability. `flask.make_response()` will not autoescape HTML. If you are rendering HTML, write your HTML in a template file and use `flask.render_template()` which will take care of escaping. If you are returning data from an API, consider using `flask.jsonify()`.

---

**`mako-templates-detected`** | INFO | `community-rules\python\lang\security\audit\mako-templates-detected.yaml`
> Mako templates do not provide a global HTML escaping mechanism. This means you must escape all sensitive data in your templates using '| u' for URL escaping or '| h' for HTML escaping. If you are using Mako to serve web content, consider using a system such as Jinja2 which enables global escaping.

---

**`manual-counter-create`** | WARNING | `community-rules\python\lang\best-practice\manual-collections-create.yaml`
> manually creating a counter - use collections.Counter

---

**`manual-defaultdict-dict-create`** | WARNING | `community-rules\python\lang\best-practice\manual-collections-create.yaml`
> manually creating a defaultdict - use collections.defaultdict(dict)

---

**`manual-defaultdict-list-create`** | WARNING | `community-rules\python\lang\best-practice\manual-collections-create.yaml`
> manually creating a defaultdict - use collections.defaultdict(list)

---

**`manual-defaultdict-set-create`** | WARNING | `community-rules\python\lang\best-practice\manual-collections-create.yaml`
> manually creating a defaultdict - use collections.defaultdict(set)

---

**`marshal-usage`** | WARNING | `community-rules\python\lang\security\audit\marshal.yaml`
> The marshal module is not intended to be secure against erroneous or maliciously constructed data. Never unmarshal data received from an untrusted or unauthenticated source. See more details: https://docs.python.org/3/library/marshal.html?highlight=security

---

**`mass-assignment`** | WARNING | `community-rules\python\django\security\injection\mass-assignment.yaml`
> Mass assignment detected. This can result in assignment to model fields that are unintended and can be exploited by an attacker. Instead of using '**request.$W', assign each field you want to edit individually to prevent mass assignment. You can read more about mass assignment at https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html.

---

**`md5-used-as-password`** | WARNING | `community-rules\python\lang\security\audit\md5-used-as-password.yaml`
> It looks like MD5 is used as a password hash. MD5 is not considered a secure password hash because it can be cracked by an attacker in a short amount of time. Use a suitable password hashing function such as scrypt. You can use `hashlib.scrypt`.

---

**`missing-autoescape-disabled`** | WARNING | `community-rules\python\jinja2\security\audit\missing-autoescape-disabled.yaml`
> Detected a Jinja2 environment without autoescaping. Jinja2 does not autoescape by default. This is dangerous if you are rendering to a browser because this allows for cross-site scripting (XSS) attacks. If you are in a web context, enable autoescaping by setting 'autoescape=True.' You may also consider using 'jinja2.select_autoescape()' to only enable automatic escaping for certain file extensions.

---

**`missing-hash-with-eq`** | WARNING | `community-rules\python\lang\best-practice\missing-hash-with-eq.yaml`
> Class `$A` has defined `__eq__` which means it should also have defined `__hash__`; 

---

**`missing-throttle-config`** | WARNING | `community-rules\python\django\security\audit\django-rest-framework\missing-throttle-config.yaml`
> Django REST framework configuration is missing default rate- limiting options. This could inadvertently allow resource starvation or Denial of Service (DoS) attacks. Add 'DEFAULT_THROTTLE_CLASSES' and 'DEFAULT_THROTTLE_RATES' to add rate-limiting to your application.

---

**`mongo-client-bad-auth`** | WARNING | `community-rules\python\pymongo\security\mongodb.yaml`
> Warning MONGODB-CR was deprecated with the release of MongoDB 3.6 and is no longer supported by MongoDB 4.0 (see https://api.mongodb.com/python/current/examples/authentication.html for details).

---

**`multiprocessing-recv`** | WARNING | `community-rules\python\lang\security\audit\conn_recv.yaml`
> The Connection.recv() method automatically unpickles the data it receives, which can be a security risk unless you can trust the process which sent the message. Therefore, unless the connection object was produced using Pipe() you should only use the recv() and send() methods after performing some sort of authentication. See more dettails: https://docs.python.org/3/library/multiprocessing.html?highlight=security#multiprocessing.connection.Connection

---

**`mysql-sqli`** | WARNING | `community-rules\python\aws-lambda\security\mysql-sqli.yaml`
> Detected SQL statement that is tainted by `event` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries or prepared statements instead. You can use parameterized statements like so: `cursor.execute('SELECT * FROM projects WHERE status = %s', ('active'))`

---

**`nan-injection`** | ERROR | `community-rules\python\django\security\nan-injection.yaml`
> Found user input going directly into typecast for bool(), float(), or complex(). This allows an attacker to inject Python's not-a-number (NaN) into the typecast. This results in undefind behavior, particularly when doing comparisons. Either cast to a different type, or add a guard checking for all capitalizations of the string 'nan'.

---

**`nan-injection`** | ERROR | `community-rules\python\flask\security\injection\nan-injection.yaml`
> Found user input going directly into typecast for bool(), float(), or complex(). This allows an attacker to inject Python's not-a-number (NaN) into the typecast. This results in undefind behavior, particularly when doing comparisons. Either cast to a different type, or add a guard checking for all capitalizations of the string 'nan'.

---

**`no-auth-over-http`** | ERROR | `community-rules\python\requests\security\no-auth-over-http.yaml`
> Authentication detected over HTTP. HTTP does not provide any encryption or protection for these authentication credentials. This may expose these credentials to unauthorized parties. Use 'https://' instead.

---

**`no-csrf-exempt`** | WARNING | `community-rules\python\django\security\audit\csrf-exempt.yaml`
> Detected usage of @csrf_exempt, which indicates that there is no CSRF token set for this route. This could lead to an attacker manipulating the user's account and exfiltration of private data. Instead, create a function without this decorator.

---

**`no-null-string-field`** | WARNING | `community-rules\python\django\correctness\string-field-null-checks.yaml`
> Avoid using null on string-based fields such as CharField and TextField. If a string-based field has null=True, that means it has two possible values for "no data": NULL, and the empty string. In most cases, it's redundant to have two possible values for "no data;" the Django convention is to use the empty string, not NULL.

---

**`no-set-ciphers`** | WARNING | `community-rules\python\lang\security\audit\insecure-transport\ssl\no-set-ciphers.yaml`
> The 'ssl' module disables insecure cipher suites by default. Therefore, use of 'set_ciphers()' should only be used when you have very specialized requirements. Otherwise, you risk lowering the security of the SSL channel.

---

**`no-strings-as-booleans`** | ERROR | `community-rules\python\lang\correctness\useless-comparison.yaml`
> Using strings as booleans in Python has unexpected results. `"one" and "two"` will return "two". `"one" or "two"` will return "one". In Python, strings are truthy, and strings with a non-zero length evaluate to True.

---

**`non-literal-import`** | WARNING | `community-rules\python\lang\security\audit\non-literal-import.yaml`
> Untrusted user input in `importlib.import_module()` function allows an attacker to load arbitrary code. Avoid dynamic values in `importlib.import_module()` or use a whitelist to prevent running untrusted code.

---

**`nontext-field-must-set-null-true`** | ERROR | `community-rules\python\django\correctness\nontext-field-must-set-null-true.yaml`
> null=True should be set if blank=True is set on non-text fields.

---

**`open-never-closed`** | ERROR | `community-rules\python\lang\best-practice\open-never-closed.yaml`
> file object opened without corresponding close

---

**`open-redirect`** | WARNING | `community-rules\python\django\security\injection\open-redirect.yaml`
> Data from request ($DATA) is passed to redirect(). This is an open redirect and could be exploited. Ensure you are redirecting to safe URLs by using django.utils.http.is_safe_url(). See https://cwe.mitre.org/data/definitions/601.html for more information.

---

**`open-redirect`** | ERROR | `community-rules\python\flask\security\open-redirect.yaml`
> Data from request is passed to redirect(). This is an open redirect and could be exploited. Consider using 'url_for()' to generate links to known locations. If you must use a URL to unknown pages, consider using 'urlparse()' or similar and checking if the 'netloc' property is the same as your site's host name. See the references for more information.

---

**`os-system-injection`** | ERROR | `community-rules\python\flask\security\injection\os-system-injection.yaml`
> User data detected in os.system. This could be vulnerable to a command injection and should be avoided. If this must be done, use the 'subprocess' module instead and pass the arguments as a list.

---

**`paramiko-exec-command`** | ERROR | `community-rules\python\lang\security\audit\paramiko\paramiko-exec-command.yaml`
> Unverified SSL context detected. This will permit insecure connections without verifying SSL certificates. Use 'ssl.create_default_context()' instead.

---

**`paramiko-implicit-trust-host-key`** | WARNING | `community-rules\python\lang\security\audit\paramiko-implicit-trust-host-key.yaml`
> Detected a paramiko host key policy that implicitly trusts a server's host key. Host keys should be verified to ensure the connection is not to a malicious server. Use RejectPolicy or a custom subclass instead.

---

**`pass-body-fn`** | WARNING | `community-rules\python\lang\best-practice\pass-body.yaml`
> `pass` is the body of function $X. Consider removing this or raise NotImplementedError() if this is a TODO

---

**`pass-body-range`** | WARNING | `community-rules\python\lang\best-practice\pass-body.yaml`
> `pass` is the body of for $X in $Y. Consider removing this or raise NotImplementedError() if this is a TODO

---

**`password-empty-string`** | ERROR | `community-rules\python\django\security\passwords\password-empty-string.yaml`
> '$VAR' is the empty string and is being used to set the password on '$MODEL'. If you meant to set an unusable password, set the password to None or call 'set_unusable_password()'.

---

**`path-traversal-file-name`** | WARNING | `community-rules\python\django\security\injection\path-traversal\path-traversal-file-name.yaml`
> Data from request is passed to a file name `$FILE`. This is a path traversal vulnerability, which can lead to sensitive data being leaked. To mitigate, consider using os.path.abspath or os.path.realpath or the pathlib library.

---

**`path-traversal-join`** | WARNING | `community-rules\python\django\security\injection\path-traversal\path-traversal-join.yaml`
> Data from request is passed to os.path.join() and to open(). This is a path traversal vulnerability, which can lead to sensitive data being leaked. To mitigate, consider using os.path.abspath or os.path.realpath or Path library.

---

**`path-traversal-open`** | WARNING | `community-rules\python\django\security\injection\path-traversal\path-traversal-open.yaml`
> Found request data in a call to 'open'. Ensure the request data is validated or sanitized, otherwise it could result in path traversal attacks and therefore sensitive data being leaked. To mitigate, consider using os.path.abspath or os.path.realpath or the pathlib library.

---

**`path-traversal-open`** | ERROR | `community-rules\python\flask\security\injection\path-traversal-open.yaml`
> Found request data in a call to 'open'. Ensure the request data is validated or sanitized, otherwise it could result in path traversal attacks.

---

**`pdb-remove`** | WARNING | `community-rules\python\lang\correctness\pdb.yaml`
> pdb is an interactive debugging tool and you may have forgotten to remove it before committing your code

---

**`pg8000-sqli`** | WARNING | `community-rules\python\lang\security\audit\sqli\pg8000-sqli.yaml`
> Detected string concatenation with a non-literal variable in a pg8000 Python SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries or prepared statements instead. You can create parameterized queries like so: 'conn.run("SELECT :value FROM table", value=myvalue)'. You can also create prepared statements with 'conn.prepare': 'conn.prepare("SELECT (:v) FROM table")'

---

**`psycopg-sqli`** | WARNING | `community-rules\python\aws-lambda\security\psycopg-sqli.yaml`
> Detected SQL statement that is tainted by `event` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries or prepared statements instead. You can use parameterized statements like so: `cursor.execute('SELECT * FROM projects WHERE status = %s', 'active')`

---

**`psycopg-sqli`** | WARNING | `community-rules\python\lang\security\audit\sqli\psycopg-sqli.yaml`
> Detected string concatenation with a non-literal variable in a psycopg2 Python SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries or prepared statements instead. You can use prepared statements by creating a 'sql.SQL' string. You can also use the pyformat binding style to create parameterized queries. For example: 'cur.execute(SELECT * FROM table WHERE name=%s, user_input)'

---

**`py-rule-1-class-naming-pascalcase`** | WARNING | `rules\python-rules.yml`
> PY Rule 1: Class names must use PascalCase (e.g., UserProfile, not userprofile or user_profile)

---

**`py-rule-10-single-responsibility`** | WARNING | `rules\python-rules.yml`
> PY Rule 10: One function should do one thing. Break down large functions following Single Responsibility Principle

---

**`py-rule-11-no-param-mutation`** | WARNING | `rules\python-rules.yml`
> PY Rule 11: Do not reassign function parameters. Create new variables to avoid confusion

---

**`py-rule-12-default-params`** | INFO | `rules\python-rules.yml`
> PY Rule 12: Use default parameters instead of manual checks (e.g., def log(level='info'))

---

**`py-rule-13-weak-hash`** | ERROR | `rules\python-rules.yml`
> PY Rule 13: MD5 and SHA1 are cryptographically broken. Use SHA-256 or stronger (hashlib.sha256)

---

**`py-rule-14-pickle-unsafe`** | ERROR | `rules\python-rules.yml`
> PY Rule 14: pickle.loads() can execute arbitrary code. Never unpickle untrusted data

---

**`py-rule-15-shell-injection`** | ERROR | `rules\python-rules.yml`
> PY Rule 15: os.system() is vulnerable to shell injection. Use subprocess with shell=False

---

**`py-rule-16-hardcoded-temp`** | WARNING | `rules\python-rules.yml`
> PY Rule 16: Hardcoded temp paths are insecure. Use tempfile module (tempfile.NamedTemporaryFile)

---

**`py-rule-17-requests-no-timeout`** | WARNING | `rules\python-rules.yml`
> PY Rule 17: HTTP requests should have timeout to prevent hanging (e.g., requests.get(url, timeout=5))

---

**`py-rule-18-sql-injection`** | ERROR | `rules\python-rules.yml`
> PY Rule 18: SQL injection vulnerability. Use parameterized queries (cursor.execute(query, params))

---

**`py-rule-19-yaml-unsafe`** | ERROR | `rules\python-rules.yml`
> PY Rule 19: yaml.load() can execute arbitrary code. Use yaml.safe_load() instead

---

**`py-rule-2-function-naming-snakecase`** | WARNING | `rules\python-rules.yml`
> PY Rule 2: Function names should use snake_case (e.g., calculate_total, not CalculateTotal or Calculate_Total)

---

**`py-rule-20-assert-usage`** | WARNING | `rules\python-rules.yml`
> PY Rule 20: Don't use assert for validation. Assertions can be disabled with -O flag. Use explicit if statements

---

**`py-rule-21-string-concat-loop`** | INFO | `rules\python-rules.yml`
> PY Rule 21: Avoid string concatenation in loops. Use list and ''.join() for better performance

---

**`py-rule-22-use-list-comprehension`** | INFO | `rules\python-rules.yml`
> PY Rule 22: Use list comprehension for cleaner code (e.g., result = [x * 2 for x in arr])

---

**`py-rule-23-method-naming-snakecase`** | WARNING | `rules\python-rules.yml`
> PY Rule 23: Method names should use snake_case (e.g., print_data, not PrintData)

---

**`py-rule-24-variable-naming-snakecase`** | INFO | `rules\python-rules.yml`
> PY Rule 24: Variable names should use snake_case (e.g., user_name, not userName or User_Name)

---

**`py-rule-25-avoid-type-comparison`** | WARNING | `rules\python-rules.yml`
> PY Rule 25: Use isinstance() instead of type() for type checking (e.g., isinstance(x, int))

---

**`py-rule-3-constant-naming-uppercase`** | INFO | `rules\python-rules.yml`
> PY Rule 3: Module-level constants should use UPPER_CASE (e.g., API_KEY, not apiKey or api_key for constants)

---

**`py-rule-4-no-print-production`** | WARNING | `rules\python-rules.yml`
> PY Rule 4: Avoid print statements in production. Use logging module (logging.info, logging.debug, etc.)

---

**`py-rule-5-empty-except`** | ERROR | `rules\python-rules.yml`
> PY Rule 5: Always handle errors. Never leave except blocks empty - log errors or handle them properly

---

**`py-rule-6-bare-except`** | WARNING | `rules\python-rules.yml`
> PY Rule 6: Avoid bare except clauses. Catch specific exceptions (e.g., except ValueError, except Exception)

---

**`py-rule-7-no-eval`** | ERROR | `rules\python-rules.yml`
> PY Rule 7: Never use eval(). It executes arbitrary code and is a major security risk

---

**`py-rule-8-mutable-default`** | ERROR | `rules\python-rules.yml`
> PY Rule 8: Mutable default arguments are dangerous. Use None and initialize inside function

---

**`py-rule-9-reduce-nesting`** | WARNING | `rules\python-rules.yml`
> PY Rule 9: Reduce nested code. Use early returns or guard clauses to improve readability

---

**`pymssql-sqli`** | WARNING | `community-rules\python\aws-lambda\security\pymssql-sqli.yaml`
> Detected SQL statement that is tainted by `event` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries or prepared statements instead. You can use parameterized statements like so: `cursor.execute('SELECT * FROM projects WHERE status = %s', 'active')`

---

**`pymysql-sqli`** | WARNING | `community-rules\python\aws-lambda\security\pymysql-sqli.yaml`
> Detected SQL statement that is tainted by `event` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries or prepared statements instead. You can use parameterized statements like so: `cursor.execute('SELECT * FROM projects WHERE status = %s', ('active'))`

---

**`pyramid-authtkt-cookie-httponly-unsafe-default`** | WARNING | `community-rules\python\pyramid\audit\authtkt-cookie-httponly-unsafe-default.yaml`
> Found a Pyramid Authentication Ticket cookie without the httponly option correctly set. Pyramid cookies should be handled securely by setting httponly=True. If this parameter is not properly set, your cookies are not properly protected and are at risk of being stolen by an attacker.

---

**`pyramid-authtkt-cookie-httponly-unsafe-value`** | WARNING | `community-rules\python\pyramid\audit\authtkt-cookie-httponly-unsafe-value.yaml`
> Found a Pyramid Authentication Ticket cookie without the httponly option correctly set. Pyramid cookies should be handled securely by setting httponly=True. If this parameter is not properly set, your cookies are not properly protected and are at risk of being stolen by an attacker.

---

**`pyramid-authtkt-cookie-samesite`** | WARNING | `community-rules\python\pyramid\audit\authtkt-cookie-samesite.yaml`
> Found a Pyramid Authentication Ticket without the samesite option correctly set. Pyramid cookies should be handled securely by setting samesite='Lax'. If this parameter is not properly set, your cookies are not properly protected and are at risk of being stolen by an attacker.

---

**`pyramid-authtkt-cookie-secure-unsafe-default`** | WARNING | `community-rules\python\pyramid\audit\authtkt-cookie-secure-unsafe-default.yaml`
> Found a Pyramid Authentication Ticket cookie using an unsafe default for the secure option. Pyramid cookies should be handled securely by setting secure=True. If this parameter is not properly set, your cookies are not properly protected and are at risk of being stolen by an attacker.

---

**`pyramid-authtkt-cookie-secure-unsafe-value`** | WARNING | `community-rules\python\pyramid\audit\authtkt-cookie-secure-unsafe-value.yaml`
> Found a Pyramid Authentication Ticket cookie without the secure option correctly set. Pyramid cookies should be handled securely by setting secure=True. If this parameter is not properly set, your cookies are not properly protected and are at risk of being stolen by an attacker.

---

**`pyramid-csrf-check-disabled`** | WARNING | `community-rules\python\pyramid\audit\csrf-check-disabled.yaml`
> CSRF protection is disabled for this view. This is a security risk.

---

**`pyramid-csrf-check-disabled-globally`** | ERROR | `community-rules\python\pyramid\security\csrf-check-disabled-globally.yaml`
> Automatic check of cross-site request forgery tokens has been explicitly disabled globally, which might leave views unprotected. Use 'pyramid.config.Configurator.set_default_csrf_options(require_csrf=True)' to turn the automatic check for all unsafe methods (per RFC2616).

---

**`pyramid-csrf-origin-check-disabled`** | WARNING | `community-rules\python\pyramid\audit\csrf-origin-check-disabled.yaml`
> Origin check for the CSRF token is disabled for this view. This might represent a security risk if the CSRF storage policy is not known to be secure.

---

**`pyramid-csrf-origin-check-disabled-globally`** | ERROR | `community-rules\python\pyramid\audit\csrf-origin-check-disabled-globally.yaml`
> Automatic check of the referrer for cross-site request forgery tokens has been explicitly disabled globally, which might leave views unprotected when an unsafe CSRF storage policy is used. Use 'pyramid.config.Configurator.set_default_csrf_options(check_origin=True)' to turn the automatic check for all unsafe methods (per RFC2616).

---

**`pyramid-direct-use-of-response`** | ERROR | `community-rules\python\pyramid\security\direct-use-of-response.yaml`
> Detected data rendered directly to the end user via 'Response'. This bypasses Pyramid's built-in cross-site scripting (XSS) defenses and could result in an XSS vulnerability. Use Pyramid's template engines to safely render HTML.

---

**`pyramid-set-cookie-httponly-unsafe-default`** | WARNING | `community-rules\python\pyramid\audit\set-cookie-httponly-unsafe-default.yaml`
> Found a Pyramid cookie using an unsafe default for the httponly option. Pyramid cookies should be handled securely by setting httponly=True in response.set_cookie(...). If this parameter is not properly set, your cookies are not properly protected and are at risk of being stolen by an attacker.

---

**`pyramid-set-cookie-httponly-unsafe-value`** | WARNING | `community-rules\python\pyramid\audit\set-cookie-httponly-unsafe-value.yaml`
> Found a Pyramid cookie without the httponly option correctly set. Pyramid cookies should be handled securely by setting httponly=True in response.set_cookie(...). If this parameter is not properly set, your cookies are not properly protected and are at risk of being stolen by an attacker.

---

**`pyramid-set-cookie-samesite-unsafe-default`** | WARNING | `community-rules\python\pyramid\audit\set-cookie-samesite-unsafe-default.yaml`
> Found a Pyramid cookie using an unsafe value for the samesite option. Pyramid cookies should be handled securely by setting samesite='Lax' in response.set_cookie(...). If this parameter is not properly set, your cookies are not properly protected and are at risk of being stolen by an attacker.

---

**`pyramid-set-cookie-samesite-unsafe-value`** | WARNING | `community-rules\python\pyramid\audit\set-cookie-samesite-unsafe-value.yaml`
> Found a Pyramid cookie without the samesite option correctly set. Pyramid cookies should be handled securely by setting samesite='Lax' in response.set_cookie(...). If this parameter is not properly set, your cookies are not properly protected and are at risk of being stolen by an attacker.

---

**`pyramid-set-cookie-secure-unsafe-default`** | WARNING | `community-rules\python\pyramid\audit\set-cookie-secure-unsafe-default.yaml`
> Found a Pyramid cookie using an unsafe default for the secure option. Pyramid cookies should be handled securely by setting secure=True in response.set_cookie(...). If this parameter is not properly set, your cookies are not properly protected and are at risk of being stolen by an attacker.

---

**`pyramid-set-cookie-secure-unsafe-value`** | WARNING | `community-rules\python\pyramid\audit\set-cookie-secure-unsafe-value.yaml`
> Found a Pyramid cookie without the secure option correctly set. Pyramid cookies should be handled securely by setting secure=True in response.set_cookie(...). If this parameter is not properly set, your cookies are not properly protected and are at risk of being stolen by an attacker.

---

**`pyramid-sqlalchemy-sql-injection`** | ERROR | `community-rules\python\pyramid\security\sqlalchemy-sql-injection.yaml`
> Distinct, Having, Group_by, Order_by, and Filter in SQLAlchemy can cause sql injections if the developer inputs raw SQL into the before-mentioned clauses. This pattern captures relevant cases in which the developer inputs raw SQL into the distinct, having, group_by, order_by or filter clauses and injects user-input into the raw SQL with any function besides "bindparams". Use bindParams to securely bind user-input to SQL statements.

---

**`pytest-assert_match-after-path-patch`** | WARNING | `community-rules\python\lang\correctness\pytest-assert_match-after-path-patch.yaml`
> snapshot.assert_match makes use of pathlib to create files. Patching $METHOD may result in unexpected snapshot behavior

---

**`python-debugger-found`** | WARNING | `community-rules\python\lang\best-practice\pdb.yaml`
> Importing the python debugger; did you mean to leave this in?

---

**`python-hardcoded-api`** | WARNING | `rules\python-rules.yml`
> Hardcoded API URL detected. Consider using environment variables or a configuration file to store API URLs

---

**`python-logger-credential-disclosure`** | WARNING | `community-rules\python\lang\security\audit\logging\logger-credential-leak.yaml`
> Detected a python logger call with a potential hardcoded secret $FORMAT_STRING being logged. This may lead to secret credentials being exposed. Make sure that the logger is not logging  sensitive information.

---

**`python-reverse-shell`** | WARNING | `community-rules\python\lang\security\audit\python-reverse-shell.yaml`
> Semgrep found a Python reverse shell using $BINPATH to $IP at $PORT

---

**`python-rule-1-eval-injection`** | WARNING | `rules\python-rules.yml`
> Rule 1: eval statement can pose a security risk, consider using safer alternatives like ast.literal_eval or json.loads

---

**`python.requests.best-practice.use-request-json-shortcut`** | WARNING | `community-rules\python\requests\best-practice\use-request-json-shortcut.yaml`
> The requests library has a convenient shortcut for sending JSON requests, which lets you stop worrying about serializing the body yourself. To use it, replace `body=json.dumps(...)` with `json=...`.

---

**`python.requests.best-practice.use-response-json-shortcut`** | WARNING | `community-rules\python\requests\best-practice\use-response-json-shortcut.yaml`
> The requests library has a convenient shortcut for reading JSON responses, which lets you stop worrying about deserializing the response yourself.

---

**`python36-compatibility-Popen1`** | ERROR | `community-rules\python\lang\compatibility\python36.yaml`
> the `errors` argument to Popen is only available on Python 3.6+

---

**`python36-compatibility-Popen2`** | ERROR | `community-rules\python\lang\compatibility\python36.yaml`
> the `encoding` argument to Popen is only available on Python 3.6+

---

**`python36-compatibility-ssl`** | ERROR | `community-rules\python\lang\compatibility\python36.yaml`
> this function is only available on Python 3.6+

---

**`python37-compatibility-httpconn`** | ERROR | `community-rules\python\lang\compatibility\python37.yaml`
> Found usage of the 'blocksize' argument in a HTTPConnection call. This is only available on Python 3.7+ and is therefore not backwards compatible. Remove this in order for this code to work in Python 3.6 and below.

---

**`python37-compatibility-httpsconn`** | ERROR | `community-rules\python\lang\compatibility\python37.yaml`
> Found usage of the 'blocksize' argument in a HTTPSConnection call. This is only available on Python 3.7+ and is therefore not backwards compatible. Remove this in order for this code to work in Python 3.6 and below.

---

**`python37-compatibility-importlib`** | ERROR | `community-rules\python\lang\compatibility\python37.yaml`
> source_hash' is only available on Python 3.7+. This does not work in lower versions, and therefore is not backwards compatible. Instead, use another hash function.

---

**`python37-compatibility-importlib2`** | ERROR | `community-rules\python\lang\compatibility\python37.yaml`
> Found 'importlib.resources', which is a module only available on Python 3.7+. This does not work in lower versions, and therefore is not backwards compatible. Use importlib_resources instead for older Python versions.

---

**`python37-compatibility-importlib3`** | ERROR | `community-rules\python\lang\compatibility\python37.yaml`
> Found usage of 'importlib.abc.ResourceReader'. This module is only available on Python 3.7+ and is therefore not backwards compatible. Instead, use another loader.

---

**`python37-compatibility-ipv4network1`** | ERROR | `community-rules\python\lang\compatibility\python37.yaml`
> IPv4Network.subnet_of is only available on Python 3.7+ and is therefore not backwards compatible. Instead, check if the subnet is in 'subnets'.

---

**`python37-compatibility-ipv4network2`** | ERROR | `community-rules\python\lang\compatibility\python37.yaml`
> IPv4Network.supernet_of is only available on Python 3.7+ and is therefore not backwards compatible. Instead, check if the supernet is in 'supernet'.

---

**`python37-compatibility-ipv6network1`** | ERROR | `community-rules\python\lang\compatibility\python37.yaml`
> IPv6Network.subnet_of is only available on Python 3.7+ and is therefore not backwards compatible. Instead, check if the subnet is in 'subnets'.

---

**`python37-compatibility-ipv6network2`** | ERROR | `community-rules\python\lang\compatibility\python37.yaml`
> IPv6Network.supernet_of is only available on Python 3.7+ and is therefore not backwards compatible. Instead, check if the supernet is in 'supernet'.

---

**`python37-compatibility-locale1`** | ERROR | `community-rules\python\lang\compatibility\python37.yaml`
> Found usage of the 'monetary' argument in a function call of 'locale.format_string'. This is only available on Python 3.7+ and is therefore not backwards compatible. Instead, remove the 'monetary' argument.

---

**`python37-compatibility-math1`** | ERROR | `community-rules\python\lang\compatibility\python37.yaml`
> math.remainder is only available on Python 3.7+ and is therefore not backwards compatible. Instead, use math.fmod() or calculate $X - n* $Y.

---

**`python37-compatibility-multiprocess1`** | ERROR | `community-rules\python\lang\compatibility\python37.yaml`
> multiprocessing.Process.close() is only available on Python 3.7+ and is therefore not backwards compatible. Instead, use join().

---

**`python37-compatibility-multiprocess2`** | ERROR | `community-rules\python\lang\compatibility\python37.yaml`
> multiprocessing.Process.kill() is only available on Python 3.7+ and is therefore not backwards compatible. Instead, use terminate().

---

**`python37-compatibility-os1`** | ERROR | `community-rules\python\lang\compatibility\python37.yaml`
> os.preadv() is only available on Python 3.7+ and is therefore not backwards compatible. Instead, use a combination of os.readv() and os.pread().

---

**`python37-compatibility-os2-ok2`** | ERROR | `community-rules\python\lang\compatibility\python37.yaml`
> os.pwritev() is only available on Python 3.3+ and is therefore not backwards compatible. Instead, use a combination of pwrite() and writev().

---

**`python37-compatibility-pdb`** | ERROR | `community-rules\python\lang\compatibility\python37.yaml`
> pdb.set_trace() with the header argument is only available on Python 3.7+ and is therefore not backwards compatible. Instead, use set_trace() without the header argument.

---

**`python37-compatibility-textiowrapper`** | ERROR | `community-rules\python\lang\compatibility\python37.yaml`
> Found usage of 'importlib.abc.ResourceReader'. This module is only available on Python 3.7+ and is therefore not backwards compatible. Instead, use another loader.

---

**`raise-not-base-exception`** | ERROR | `community-rules\python\lang\correctness\exceptions\exceptions.yaml`
> In Python3, a runtime `TypeError` will be thrown if you attempt to raise an object or class which does not inherit from `BaseException`

---

**`raw-html-format`** | WARNING | `community-rules\python\django\security\injection\raw-html-format.yaml`
> Detected user input flowing into a manually constructed HTML string. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross-site scripting vulnerability, which could let attackers steal sensitive user data. To be sure this is safe, check that the HTML is rendered safely. Otherwise, use templates (`django.shortcuts.render`) which will safely render HTML instead.

---

**`raw-html-format`** | WARNING | `community-rules\python\flask\security\injection\raw-html-concat.yaml`
> Detected user input flowing into a manually constructed HTML string. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross-site scripting vulnerability, which could let attackers steal sensitive user data. To be sure this is safe, check that the HTML is rendered safely. Otherwise, use templates (`flask.render_template`) which will safely render HTML instead.

---

**`reflected-data-httpresponse`** | WARNING | `community-rules\python\django\security\injection\reflected-data-httpresponse.yaml`
> Found user-controlled request data passed into HttpResponse. This could be vulnerable to XSS, leading to attackers gaining access to user cookies and protected information. Ensure that the request data is properly escaped or sanitzed.

---

**`reflected-data-httpresponsebadrequest`** | WARNING | `community-rules\python\django\security\injection\reflected-data-httpresponsebadrequest.yaml`
> Found user-controlled request data passed into a HttpResponseBadRequest. This could be vulnerable to XSS, leading to attackers gaining access to user cookies and protected information. Ensure that the request data is properly escaped or sanitzed.

---

**`regex_dos`** | WARNING | `community-rules\python\lang\security\audit\regex-dos.yaml`
> Detected usage of re.compile with an inefficient regular expression. This can lead to regular expression denial of service, which can result in service down time. Instead, check all regexes or use safer alternatives such as pyre2.

---

**`render-template-string`** | WARNING | `community-rules\python\flask\security\audit\render-template-string.yaml`
> Found a template created with string formatting. This is susceptible to server-side template injection and cross-site scripting attacks.

---

**`request-data-fileresponse`** | WARNING | `community-rules\python\django\security\injection\request-data-fileresponse.yaml`
> Found user-controlled request data being passed into a file open, which is them passed as an argument into the FileResponse. This is dangerous because an attacker could specify an arbitrary file to read, which could result in leaking important data. Be sure to validate or sanitize the user-inputted filename in the request data before using it in FileResponse.

---

**`request-data-write`** | WARNING | `community-rules\python\django\security\injection\request-data-write.yaml`
> Found user-controlled request data passed into '.write(...)'. This could be dangerous if a malicious actor is able to control data into sensitive files. For example, a malicious actor could force rolling of critical log files, or cause a denial-of-service by using up available disk space. Instead, ensure that request data is properly escaped or sanitized.

---

**`request-session-http-in-with-context`** | INFO | `community-rules\python\lang\security\audit\insecure-transport\requests\request-session-http-in-with-context.yaml`
> Detected a request using 'http://'. This request will be unencrypted. Use 'https://' instead.

---

**`request-session-with-http`** | INFO | `community-rules\python\lang\security\audit\insecure-transport\requests\request-session-with-http.yaml`
> Detected a request using 'http://'. This request will be unencrypted. Use 'https://' instead.

---

**`request-with-http`** | INFO | `community-rules\python\lang\security\audit\insecure-transport\requests\request-with-http.yaml`
> Detected a request using 'http://'. This request will be unencrypted, and attackers could listen into traffic on the network and be able to obtain sensitive information. Use 'https://' instead.

---

**`require-encryption`** | WARNING | `community-rules\python\distributed\security.yaml`
> Initializing a security context for Dask (`distributed`) without "require_encryption" keyword argument may silently fail to provide security.

---

**`response-contains-unsanitized-input`** | WARNING | `community-rules\python\flask\security\unsanitized-input.yaml`
> Flask response reflects unsanitized user input. This could lead to a cross-site scripting vulnerability (https://owasp.org/www-community/attacks/xss/) in which an attacker causes arbitrary code to be executed in the user's browser. To prevent, please sanitize the user input, e.g. by rendering the response in a Jinja2 template (see considerations in https://flask.palletsprojects.com/en/1.0.x/security/).

---

**`return-in-init`** | ERROR | `community-rules\python\lang\correctness\return-in-init.yaml`
> `return` should never appear inside a class __init__ function. This will cause a runtime error.

---

**`return-not-in-function`** | WARNING | `community-rules\python\lang\maintainability\return.yaml`
> `return` only makes sense inside a function

---

**`secure-set-cookie`** | WARNING | `community-rules\python\flask\security\audit\secure-set-cookie.yaml`
> Found a Flask cookie with insecurely configured properties.  By default the secure, httponly and samesite ar configured insecurely. cookies should be handled securely by setting `secure=True`, `httponly=True`, and `samesite='Lax'` in response.set_cookie(...). If these parameters are not properly set, your cookies are not properly protected and are at risk of being stolen by an attacker. Include the `secure=True`, `httponly=True`, `samesite='Lax'` arguments or set these to be true in the Flask configuration.

---

**`sha224-hash`** | WARNING | `community-rules\python\lang\security\audit\sha224-hash.yaml`
> This code uses a 224-bit hash function, which is deprecated or disallowed in some security policies. Consider updating to a stronger hash function such as SHA-384 or higher to ensure compliance and security.

---

**`socket-shutdown-close`** | WARNING | `community-rules\python\correctness\socket-shutdown-close.yaml`
> Socket is not closed if shutdown fails. When socket.shutdown fails on an OSError, socket.close is not called and the code fails to clean up the socket and allow garbage collection to release the memory used for it. The OSError on shutdown can occur when the remote side of the connection closes the connection first.

---

**`sql-injection-db-cursor-execute`** | WARNING | `community-rules\python\django\security\injection\sql\sql-injection-using-db-cursor-execute.yaml`
> User-controlled data from a request is passed to 'execute()'. This could lead to a SQL injection and therefore protected information could be leaked. Instead, use django's QuerySets, which are built with query parameterization and therefore not vulnerable to sql injection. For example, you could use `Entry.objects.filter(date=2006)`.

---

**`sql-injection-using-extra-where`** | WARNING | `community-rules\python\django\security\injection\sql\sql-injection-extra.yaml`
> User-controlled data from a request is passed to 'extra()'. This could lead to a SQL injection and therefore protected information could be leaked. Instead, use parameterized queries or escape the user-controlled data by using `params` and not using quote placeholders in the SQL string.

---

**`sql-injection-using-raw`** | WARNING | `community-rules\python\django\security\injection\sql\sql-injection-using-raw.yaml`
> Data that is possible user-controlled from a python request is passed to `raw()`. This could lead to SQL injection and attackers gaining access to protected information. Instead, use django's QuerySets, which are built with query parameterization and therefore not vulnerable to sql injection. For example, you could use `Entry.objects.filter(date=2006)`.

---

**`sql-injection-using-rawsql`** | WARNING | `community-rules\python\django\security\injection\sql\sql-injection-rawsql.yaml`
> User-controlled data from request is passed to 'RawSQL()'. This could lead to a SQL injection and therefore protected information could be leaked. Instead, use parameterized queries or escape the user-controlled data by using `params` and not using quote placeholders in the SQL string.

---

**`sqlalchemy-execute-raw-query`** | ERROR | `community-rules\python\sqlalchemy\security\sqlalchemy-execute-raw-query.yaml`
> Avoiding SQL string concatenation: untrusted input concatenated with raw SQL query can result in SQL Injection. In order to execute raw query safely, prepared statement should be used. SQLAlchemy provides TextualSQL to easily used prepared statement with named parameters. For complex SQL composition, use SQL Expression Language or Schema Definition Language. In most cases, SQLAlchemy ORM will be a better option.

---

**`sqlalchemy-sql-injection`** | WARNING | `community-rules\python\sqlalchemy\security\sqlalchemy-sql-injection.yaml`
> Distinct, Having, Group_by, Order_by, and Filter in SQLAlchemy can cause sql injections if the developer inputs raw SQL into the before-mentioned clauses. This pattern captures relevant cases in which the developer inputs raw SQL into the distinct, having, group_by, order_by or filter clauses and injects user-input into the raw SQL with any function besides "bindparams". Use bindParams to securely bind user-input to SQL statements.

---

**`sqlalchemy-sqli`** | WARNING | `community-rules\python\aws-lambda\security\sqlalchemy-sqli.yaml`
> Detected SQL statement that is tainted by `event` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries or prepared statements instead. You can use parameterized statements like so: `cursor.execute('SELECT * FROM projects WHERE status = ?', 'active')`

---

**`ssl-wrap-socket-is-deprecated`** | WARNING | `community-rules\python\lang\security\audit\ssl-wrap-socket-is-deprecated.yaml`
> 'ssl.wrap_socket()' is deprecated. This function creates an insecure socket without server name indication or hostname matching. Instead, create an SSL context using 'ssl.SSLContext()' and use that to wrap a socket.

---

**`ssrf-injection-requests`** | ERROR | `community-rules\python\django\security\injection\ssrf\ssrf-injection-requests.yaml`
> Data from request object is passed to a new server-side request. This could lead to a server-side request forgery (SSRF). To mitigate, ensure that schemes and hosts are validated against an allowlist, do not forward the response to the user, and ensure proper authentication and transport-layer security in the proxied request. See https://owasp.org/www-community/attacks/Server_Side_Request_Forgery to learn more about SSRF vulnerabilities.

---

**`ssrf-injection-urllib`** | ERROR | `community-rules\python\django\security\injection\ssrf\ssrf-injection-urllib.yaml`
> Data from request object is passed to a new server-side request. This could lead to a server-side request forgery (SSRF), which could result in attackers gaining access to private organization data. To mitigate, ensure that schemes and hosts are validated against an allowlist, do not forward the response to the user, and ensure proper authentication and transport-layer security in the proxied request.

---

**`ssrf-requests`** | ERROR | `community-rules\python\flask\security\injection\ssrf-requests.yaml`
> Data from request object is passed to a new server-side request. This could lead to a server-side request forgery (SSRF). To mitigate, ensure that schemes and hosts are validated against an allowlist, do not forward the response to the user, and ensure proper authentication and transport-layer security in the proxied request.

---

**`string-concat`** | ERROR | `community-rules\python\sh\security\string-concat.yaml`
> Detected string concatenation or formatting in a call to a command via 'sh'. This could be a command injection vulnerability if the data is user-controlled. Instead, use a list and append the argument.

---

**`string-concat-in-list`** | WARNING | `community-rules\python\lang\correctness\common-mistakes\string-concat-in-list.yaml`
> Detected strings that are implicitly concatenated inside a list. Python will implicitly concatenate strings when not explicitly delimited. Was this supposed to be individual elements of the list?

---

**`string-field-must-set-null-true`** | ERROR | `community-rules\python\django\correctness\string-field-null-checks.yaml`
> If a text field declares unique=True and blank=True, null=True must also be set to avoid unique constraint violations when saving multiple objects with blank values.

---

**`string-is-comparison`** | ERROR | `community-rules\python\lang\correctness\common-mistakes\is-comparison-string.yaml`
> Found string comparison using 'is' operator. The 'is' operator is for reference equality, not value equality, and therefore should not be used to compare strings. For more information, see https://github.com/satwikkansal/wtfpython#-how-not-to-use-is-operator"

---

**`subprocess-injection`** | ERROR | `community-rules\python\django\security\injection\command\subprocess-injection.yaml`
> Detected user input entering a `subprocess` call unsafely. This could result in a command injection vulnerability. An attacker could use this vulnerability to execute arbitrary commands on the host, which allows them to download malware, scan sensitive data, or run any command they wish on the server. Do not let users choose the command to run. In general, prefer to use Python API versions of system commands. If you must use subprocess, use a dictionary to allowlist a set of commands.

---

**`subprocess-injection`** | ERROR | `community-rules\python\flask\security\injection\subprocess-injection.yaml`
> Detected user input entering a `subprocess` call unsafely. This could result in a command injection vulnerability. An attacker could use this vulnerability to execute arbitrary commands on the host, which allows them to download malware, scan sensitive data, or run any command they wish on the server. Do not let users choose the command to run. In general, prefer to use Python API versions of system commands. If you must use subprocess, use a dictionary to allowlist a set of commands.

---

**`subprocess-list-passed-as-string`** | WARNING | `community-rules\python\lang\security\audit\subprocess-list-passed-as-string.yaml`
> Detected `" ".join(...)` being passed to `subprocess.run`. This can lead to argument splitting issues and potential security vulnerabilities. Instead, pass the list directly to `subprocess.run` to preserve argument separation.

---

**`subprocess-shell-true`** | ERROR | `community-rules\python\lang\security\audit\subprocess-shell-true.yaml`
> Found 'subprocess' function '$FUNC' with 'shell=True'. This is dangerous because this call will spawn the command using a shell process. Doing so propagates current shell settings and variables, which makes it much easier for a malicious actor to execute commands. Use 'shell=False' instead.

---

**`suppressed-exception-handling-finally-break`** | WARNING | `community-rules\python\correctness\suppressed-exception-handling-finally-break.yaml`
> Having a `break`, `continue`, or `return` in a `finally` block will cause strange behaviors, like exceptions not being caught.

---

**`sync-sleep-in-async-code`** | WARNING | `community-rules\python\lang\correctness\sync-sleep-in-async-code.yaml`
> Synchronous time.sleep in async code will block the event loop and not allow other tasks to execute. Use asyncio.sleep() instead.

---

**`system-wildcard-detected`** | WARNING | `community-rules\python\lang\security\audit\system-wildcard-detected.yaml`
> Detected use of the wildcard character in a system call that spawns a shell. This subjects the wildcard to normal shell expansion, which can have unintended consequences if there exist any non-standard file names. Consider a file named '-e sh script.sh' -- this will execute a script when 'rsync' is called. See https://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt for more information.

---

**`tainted-code-exec`** | WARNING | `community-rules\python\aws-lambda\security\tainted-code-exec.yaml`
> Detected the use of `exec/eval`.This can be dangerous if used to evaluate dynamic content. If this content can be input from outside the program, this may be a code injection vulnerability. Ensure evaluated content is not definable by external sources.

---

**`tainted-html-response`** | WARNING | `community-rules\python\aws-lambda\security\tainted-html-response.yaml`
> Detected user input flowing into an HTML response. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross-site scripting vulnerability, which could let attackers steal sensitive user data.

---

**`tainted-html-string`** | WARNING | `community-rules\python\aws-lambda\security\tainted-html-string.yaml`
> Detected user input flowing into a manually constructed HTML string. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross-site scripting vulnerability, which could let attackers steal sensitive user data. To be sure this is safe, check that the HTML is rendered safely. Otherwise, use templates which will safely render HTML instead.

---

**`tainted-pickle-deserialization`** | WARNING | `community-rules\python\aws-lambda\security\tainted-pickle-deserialization.yaml`
> Avoid using `pickle`, which is known to lead to code execution vulnerabilities. When unpickling, the serialized data could be manipulated to run arbitrary code. Instead, consider serializing the relevant data as JSON or a similar text-based serialization format.

---

**`tainted-sql-string`** | ERROR | `community-rules\python\aws-lambda\security\tainted-sql-string.yaml`
> Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify contents of the database. Instead, use a parameterized query which is available by default in most database engines. Alternatively, consider using an object-relational mapper (ORM) such as Sequelize which will protect your queries.

---

**`tainted-sql-string`** | ERROR | `community-rules\python\django\security\injection\tainted-sql-string.yaml`
> Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify contents of the database. Instead, use a parameterized query which is available by default in most database engines. Alternatively, consider using the Django object-relational mappers (ORM) instead of raw SQL queries.

---

**`tainted-sql-string`** | ERROR | `community-rules\python\flask\security\injection\tainted-sql-string.yaml`
> Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify contents of the database. Instead, use a parameterized query which is available by default in most database engines. Alternatively, consider using an object-relational mapper (ORM) such as SQLAlchemy which will protect your queries.

---

**`tainted-url-host`** | WARNING | `community-rules\python\django\security\injection\tainted-url-host.yaml`
> User data flows into the host portion of this manually-constructed URL. This could allow an attacker to send data to their own server, potentially exposing sensitive data such as cookies or authorization information sent with this request. They could also probe internal servers or other resources that the server running this code can access. (This is called server-side request forgery, or SSRF.) Do not allow arbitrary hosts. Instead, create an allowlist for approved hosts, or hardcode the correct host.

---

**`tainted-url-host`** | WARNING | `community-rules\python\flask\security\injection\tainted-url-host.yaml`
> User data flows into the host portion of this manually-constructed URL. This could allow an attacker to send data to their own server, potentially exposing sensitive data such as cookies or authorization information sent with this request. They could also probe internal servers or other resources that the server running this code can access. (This is called server-side request forgery, or SSRF.) Do not allow arbitrary hosts. Instead, create an allowlist for approved hosts, or hardcode the correct host.

---

**`telnetlib`** | WARNING | `community-rules\python\lang\security\audit\telnetlib.yaml`
> Telnet does not encrypt communications. Use SSH instead.

---

**`tempfile-insecure`** | ERROR | `community-rules\python\lang\correctness\tempfile\mktemp.yaml`
> Use tempfile.NamedTemporaryFile instead. From the official Python documentation: THIS FUNCTION IS UNSAFE AND SHOULD NOT BE USED. The file name may refer to a file that did not exist at some point, but by the time you get around to creating it, someone else may have beaten you to the punch.

---

**`tempfile-without-flush`** | ERROR | `community-rules\python\lang\correctness\tempfile\flush.yaml`
> Using '$F.name' without '.flush()' or '.close()' may cause an error because the file may not exist when '$F.name' is used. Use '.flush()' or close the file before using '$F.name'.

---

**`template-autoescape-off`** | WARNING | `community-rules\python\django\security\audit\xss\template-autoescape-off.yaml`
> Detected a template block where autoescaping is explicitly disabled with '{% autoescape off %}'. This allows rendering of raw HTML in this segment. Turn autoescaping on to prevent cross-site scripting (XSS). If you must do this, consider instead, using `mark_safe` in Python code.

---

**`template-autoescape-off`** | WARNING | `community-rules\python\flask\security\xss\audit\template-autoescape-off.yaml`
> Detected a segment of a Flask template where autoescaping is explicitly disabled with '{% autoescape off %}'. This allows rendering of raw HTML in this segment. Ensure no user data is rendered here, otherwise this is a cross-site scripting (XSS) vulnerability, or turn autoescape on.

---

**`template-blocktranslate-no-escape`** | INFO | `community-rules\python\django\security\audit\xss\template-blocktranslate-no-escape.yaml`
> Translated strings will not be escaped when rendered in a template. This leads to a vulnerability where translators could include malicious script tags in their translations. Consider using `force_escape` to explicitly escape a translated text.

---

**`template-translate-as-no-escape`** | INFO | `community-rules\python\django\security\audit\xss\template-translate-as-no-escape.yaml`
> Translated strings will not be escaped when rendered in a template. This leads to a vulnerability where translators could include malicious script tags in their translations. Consider using `force_escape` to explicitly escape a translated text.

---

**`template-unescaped-with-safe`** | WARNING | `community-rules\python\flask\security\xss\audit\template-unescaped-with-safe.yaml`
> Detected a segment of a Flask template where autoescaping is explicitly disabled with '| safe' filter. This allows rendering of raw HTML in this segment. Ensure no user data is rendered here, otherwise this is a cross-site scripting (XSS) vulnerability.

---

**`template-unquoted-attribute-var`** | WARNING | `community-rules\python\flask\security\xss\audit\template-unquoted-attribute-var.yaml`
> Detected a unquoted template variable as an attribute. If unquoted, a malicious actor could inject custom JavaScript handlers. To fix this, add quotes around the template expression, like this: "{{ $...VAR }}".

---

**`template-var-unescaped-with-safeseq`** | WARNING | `community-rules\python\django\security\audit\xss\template-var-unescaped-with-safeseq.yaml`
> Detected a template variable where autoescaping is explicitly disabled with '| safeseq' filter. This allows rendering of raw HTML in this segment. Ensure no user data is rendered here, otherwise this is a cross-site scripting (XSS) vulnerability. If you must do this, use `mark_safe` in your Python code.

---

**`test-is-missing-assert`** | WARNING | `community-rules\python\lang\correctness\test-is-missing-assert.yaml`
> Comparison without assertion. The result of this comparison is not used. Perhaps this expression is missing an `assert` keyword.

---

**`twiml-injection`** | WARNING | `community-rules\python\twilio\security\twiml-injection.yaml`
> Using non-constant TwiML (Twilio Markup Language) argument when creating a Twilio conversation could allow the injection of additional TwiML commands

---

**`uncaught-executor-exceptions`** | WARNING | `community-rules\python\lang\correctness\concurrent.yaml`
> Values returned by thread pool map must be read in order to raise exceptions. Consider using `for _ in $EXECUTOR.map(...): pass`.

---

**`unchecked-subprocess-call`** | WARNING | `community-rules\python\lang\correctness\unchecked-returns.yaml`
> This is not checking the return value of this subprocess call; if it fails no exception will be raised. Consider subprocess.check_call() instead

---

**`unescaped-template-extension`** | WARNING | `community-rules\python\flask\security\unescaped-template-extension.yaml`
> Flask does not automatically escape Jinja templates unless they have .html, .htm, .xml, or .xhtml extensions. This could lead to XSS attacks. Use .html, .htm, .xml, or .xhtml for your template extensions. See https://flask.palletsprojects.com/en/1.1.x/templating/#jinja-setup for more information.

---

**`unspecified-open-encoding`** | WARNING | `community-rules\python\lang\best-practice\unspecified-open-encoding.yaml`
> Missing 'encoding' parameter. 'open()' uses device locale encodings by default, corrupting files with special characters. Specify the encoding to ensure cross-platform support when opening files in text mode (e.g. encoding="utf-8").

---

**`unvalidated-password`** | WARNING | `community-rules\python\django\security\audit\unvalidated-password.yaml`
> The password on '$MODEL' is being set without validating the password. Call django.contrib.auth.password_validation.validate_password() with validation functions before setting the password. See https://docs.djangoproject.com/en/3.0/topics/auth/passwords/ for more information.

---

**`unverified-jwt-decode`** | ERROR | `community-rules\python\jwt\security\unverified-jwt-decode.yaml`
> Detected JWT token decoded with 'verify=False'. This bypasses any integrity checks for the token which means the token could be tampered with by malicious actors. Ensure that the JWT token is verified.

---

**`unverified-ssl-context`** | ERROR | `community-rules\python\lang\security\unverified-ssl-context.yaml`
> Unverified SSL context detected. This will permit insecure connections without verifying SSL certificates. Use 'ssl.create_default_context' instead.

---

**`use-click-secho`** | ERROR | `community-rules\python\click\best-practice\echo-style.yaml`
> Use `click.secho($X)` instead. It combines click.echo() and click.style().

---

**`use-count-method`** | ERROR | `community-rules\python\django\performance\upsell-count.yaml`
> Looks like you need to determine the number of records. Django provides the count() method which is more efficient than .len(). See https://docs.djangoproject.com/en/3.0/ref/models/querysets/

---

**`use-decimalfield-for-money`** | ERROR | `community-rules\python\django\correctness\use-decimalfield-for-money.yaml`
> Found a FloatField used for variable $F. Use DecimalField for currency fields to avoid float-rounding errors.

---

**`use-defused-xml`** | ERROR | `community-rules\python\lang\security\use-defused-xml.yaml`
> The Python documentation recommends using `defusedxml` instead of `xml` because the native Python `xml` library is vulnerable to XML External Entity (XXE) attacks. These attacks can leak confidential data and "XML bombs" can cause denial of service.

---

**`use-defused-xml-parse`** | ERROR | `community-rules\python\lang\security\use-defused-xml-parse.yaml`
> The native Python `xml` library is vulnerable to XML External Entity (XXE) attacks.  These attacks can leak confidential data and "XML bombs" can cause denial of service. Do not use this library to parse untrusted input. Instead  the Python documentation recommends using `defusedxml`.

---

**`use-defused-xmlrpc`** | ERROR | `community-rules\python\lang\security\use-defused-xmlrpc.yaml`
> Detected use of xmlrpc. xmlrpc is not inherently safe from vulnerabilities. Use defusedxml.xmlrpc instead.

---

**`use-defusedcsv`** | INFO | `community-rules\python\lang\security\use-defusedcsv.yaml`
> Detected the generation of a CSV file using the built-in `csv` module. If user data is used to generate the data in this file, it is possible that an attacker could inject a formula when the CSV is imported into a spreadsheet application that runs an attacker script, which could steal data from the importing user or, at worst, install malware on the user's computer. `defusedcsv` is a drop-in replacement with the same API that will attempt to mitigate formula injection attempts. You can use `defusedcsv` instead of `csv` to safely generate CSVs.

---

**`use-django-environ`** | ERROR | `community-rules\python\django\best-practice\upsell_django_environ.yaml`
> You are using environment variables inside django app. Use `django-environ` as it a better alternative for deployment.

---

**`use-earliest-or-latest`** | ERROR | `community-rules\python\django\performance\upsell_earliest_latest.yaml`
> Looks like you are only accessing first element of an ordered QuerySet. Use `latest()` or `earliest()` instead. See https://docs.djangoproject.com/en/3.0/ref/models/querysets/#django.db.models.query.QuerySet.latest

---

**`use-ftp-tls`** | INFO | `community-rules\python\lang\security\audit\insecure-transport\ftplib\use-ftp-tls.yaml`
> The 'FTP' class sends information unencrypted. Consider using the 'FTP_TLS' class instead.

---

**`use-json-response`** | ERROR | `community-rules\python\django\best-practice\json_response.yaml`
> Use JsonResponse instead

---

**`use-jsonify`** | ERROR | `community-rules\python\flask\best-practice\use-jsonify.yaml`
> flask.jsonify() is a Flask helper method which handles the correct  settings for returning JSON from Flask routes

---

**`use-none-for-password-default`** | ERROR | `community-rules\python\django\security\passwords\use-none-for-password-default.yaml`
> '$VAR' is using the empty string as its default and is being used to set the password on '$MODEL'. If you meant to set an unusable password, set the default value to 'None' or call 'set_unusable_password()'.

---

**`use-onetoonefield`** | WARNING | `community-rules\python\django\best-practice\use-onetoonefield.yaml`
> Use 'django.db.models.OneToOneField' instead of 'ForeignKey' with unique=True. 'OneToOneField' is used to create one-to-one relationships.

---

**`use-raise-for-status`** | WARNING | `community-rules\python\requests\best-practice\use-raise-for-status.yaml`
> There's an HTTP request made with requests, but the raise_for_status() utility method isn't used. This can result in request errors going unnoticed and your code behaving in unexpected ways, such as if your authorization API returns a 500 error while you're only checking for a 401.

---

**`use-sys-exit`** | WARNING | `community-rules\python\lang\correctness\exit.yaml`
> Detected use of `exit`. Use `sys.exit` over the python shell `exit` built-in. `exit` is a helper for the interactive shell and may not be available on all Python implementations.

---

**`use-timeout`** | WARNING | `community-rules\python\requests\best-practice\use-timeout.yaml`
> Detected a 'requests' call without a timeout set. By default, 'requests' calls wait until the connection is closed. This means a 'requests' call without a timeout will hang the program if a response is never received. Consider setting a timeout for all 'requests'.

---

**`useless-assignment-keyed`** | INFO | `community-rules\python\lang\maintainability\useless-assign-keyed.yaml`
> key `$Y` in `$X` is assigned twice; the first assignment is useless

---

**`useless-eqeq`** | INFO | `community-rules\python\lang\correctness\useless-eqeq.yaml`
> This expression is always True: `$X == $X` or `$X != $X`. If testing for floating point NaN, use `math.isnan($X)`, or `cmath.isnan($X)` if the number is complex.

---

**`useless-if-body`** | WARNING | `community-rules\python\lang\maintainability\useless-ifelse.yaml`
> Useless if statement; both blocks have the same body

---

**`useless-if-conditional`** | WARNING | `community-rules\python\lang\maintainability\useless-ifelse.yaml`
> if block checks for the same condition on both branches (`$X`)

---

**`useless-inner-function`** | ERROR | `community-rules\python\lang\maintainability\useless-innerfunction.yaml`
> function `$FF` is defined inside a function but never used

---

**`useless-literal`** | WARNING | `community-rules\python\lang\maintainability\useless-literal.yaml`
> key `$X` is uselessly assigned twice

---

**`useless-literal-set`** | ERROR | `community-rules\python\lang\maintainability\useless-literal-set.yaml`
> `$X` is uselessly assigned twice inside the creation of the set

---

**`user-eval`** | WARNING | `community-rules\python\django\security\injection\code\user-eval.yaml`
> Found user data in a call to 'eval'. This is extremely dangerous because it can enable an attacker to execute arbitrary remote code on the system. Instead, refactor your code to not use 'eval' and instead use a safe library for the specific functionality you need.

---

**`user-eval-format-string`** | WARNING | `community-rules\python\django\security\injection\code\user-eval-format-string.yaml`
> Found user data in a call to 'eval'. This is extremely dangerous because it can enable an attacker to execute remote code. See https://owasp.org/www-community/attacks/Code_Injection for more information.

---

**`user-exec`** | WARNING | `community-rules\python\django\security\injection\code\user-exec.yaml`
> Found user data in a call to 'exec'. This is extremely dangerous because it can enable an attacker to execute arbitrary remote code on the system. Instead, refactor your code to not use 'eval' and instead use a safe library for the specific functionality you need.

---

**`user-exec-format-string`** | WARNING | `community-rules\python\django\security\injection\code\user-exec-format-string.yaml`
> Found user data in a call to 'exec'. This is extremely dangerous because it can enable an attacker to execute arbitrary remote code on the system. Instead, refactor your code to not use 'eval' and instead use a safe library for the specific functionality you need.

---

**`weak-ssl-version`** | WARNING | `community-rules\python\lang\security\audit\weak-ssl-version.yaml`
> An insecure SSL version was detected. TLS versions 1.0, 1.1, and all SSL versions are considered weak encryption and are deprecated. Use 'ssl.PROTOCOL_TLSv1_2' or higher.

---

**`wildcard-cors`** | WARNING | `community-rules\python\fastapi\security\wildcard-cors.yaml`
> CORS policy allows any origin (using wildcard '*'). This is insecure and should be avoided.

---

**`writing-to-file-in-read-mode`** | ERROR | `community-rules\python\lang\correctness\writing-to-file-in-read-mode.yaml`
> The file object '$FD' was opened in read mode, but is being written to. This will cause a runtime error.

---

**`xss-html-email-body`** | WARNING | `community-rules\python\django\security\injection\email\xss-html-email-body.yaml`
> Found request data in an EmailMessage that is set to use HTML. This is dangerous because HTML emails are susceptible to XSS. An attacker could inject data into this HTML email, causing XSS.

---

**`xss-send-mail-html-message`** | WARNING | `community-rules\python\django\security\injection\email\xss-send-mail-html-message.yaml`
> Found request data in 'send_mail(...)' that uses 'html_message'. This is dangerous because HTML emails are susceptible to XSS. An attacker could inject data into this HTML email, causing XSS.

---

**`yield-in-init`** | ERROR | `community-rules\python\lang\correctness\return-in-init.yaml`
> `yield` should never appear inside a class __init__ function. This will cause a runtime error.

---

## Ruby (94 rules)

**`activerecord-sqli`** | WARNING | `community-rules\ruby\aws-lambda\security\activerecord-sqli.yaml`
> Detected SQL statement that is tainted by `event` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries or prepared statements instead. You can use parameterized statements like so: `Example.find_by_sql ["SELECT title FROM posts WHERE author = ? AND created > ?", author_id, start_date]`

---

**`alias-for-html-safe`** | WARNING | `community-rules\ruby\rails\security\audit\xss\templates\alias-for-html-safe.yaml`
> The syntax `<%== ... %>` is an alias for `html_safe`. This means the content inside these tags will be rendered as raw HTML. This may expose your application to cross-site scripting. If you need raw HTML, prefer using the more explicit `html_safe` and be sure to correctly sanitize variables using a library such as DOMPurify.

---

**`avoid-content-tag`** | WARNING | `community-rules\ruby\rails\security\audit\xss\avoid-content-tag.yaml`
> 'content_tag()' bypasses HTML escaping for some portion of the content. If external data can reach here, this exposes your application to cross-site scripting (XSS) attacks. Ensure no external data reaches here. If you must do this, create your HTML manually and use 'html_safe'. Ensure no external data enters the HTML-safe string!

---

**`avoid-content-tag`** | WARNING | `community-rules\ruby\rails\security\audit\xss\templates\avoid-content-tag.yaml`
> 'content_tag' exhibits unintuitive escaping behavior and may accidentally expose your application to cross-site scripting. If using Rails 2, only attribute values are escaped. If using Rails 3, content and attribute values are escaped. Tag and attribute names are never escaped. Because of this, it is recommended to use 'html_safe' if you must render raw HTML data.

---

**`avoid-default-routes`** | WARNING | `community-rules\ruby\rails\security\audit\xss\avoid-default-routes.yaml`
> Default routes are enabled in this routes file. This means any public method on a controller can be called as an action. It is very easy to accidentally expose a method you didn't mean to. Instead, remove this line and explicitly include all routes you intend external users to follow.

---

**`avoid-html-safe`** | WARNING | `community-rules\ruby\rails\security\audit\xss\avoid-html-safe.yaml`
> 'html_safe()' does not make the supplied string safe. 'html_safe()' bypasses HTML escaping. If external data can reach here, this exposes your application to cross-site scripting (XSS) attacks. Ensure no external data reaches here.

---

**`avoid-html-safe`** | WARNING | `community-rules\ruby\rails\security\audit\xss\templates\avoid-html-safe.yaml`
> 'html_safe' renders raw HTML. This means that normal HTML escaping is bypassed. If user data can be controlled here, this exposes your application to cross-site scripting (XSS). If you need to do this, be sure to correctly sanitize the data using a library such as DOMPurify.

---

**`avoid-link-to`** | WARNING | `community-rules\ruby\rails\security\audit\xss\avoid-link-to.yaml`
> This code includes user input in `link_to`. In Rails 2.x, the body of `link_to` is not escaped. This means that user input which reaches the body will be executed when the HTML is rendered. Even in other versions, values starting with `javascript:` or `data:` are not escaped. It is better to create and use a safer function which checks the body argument.

---

**`avoid-logging-everything`** | ERROR | `community-rules\ruby\rails\security\audit\avoid-logging-everything.yaml`
> Avoid logging `params` and `params.inspect` as this bypasses Rails filter_parameters and may inadvertently log sensitive data. Instead, reference specific fields to ensure only expected data is logged.

---

**`avoid-raw`** | WARNING | `community-rules\ruby\rails\security\audit\xss\avoid-raw.yaml`
> 'raw()' bypasses HTML escaping. If external data can reach here, this exposes your application to cross-site scripting (XSS) attacks. If you must do this, construct individual strings and mark them as safe for HTML rendering with `html_safe()`.

---

**`avoid-raw`** | WARNING | `community-rules\ruby\rails\security\audit\xss\templates\avoid-raw.yaml`
> 'raw' renders raw HTML, as the name implies. This means that normal HTML escaping is bypassed. If user data can be controlled here, this exposes your application to cross-site scripting (XSS). If you need to do this, be sure to correctly sanitize the data using a library such as DOMPurify.

---

**`avoid-redirect`** | WARNING | `community-rules\ruby\rails\security\audit\xss\avoid-redirect.yaml`
> When a redirect uses user input, a malicious user can spoof a website under a trusted URL or access restricted parts of a site. When using user-supplied values, sanitize the value before using it for the redirect.

---

**`avoid-render-dynamic-path`** | WARNING | `community-rules\ruby\rails\security\audit\xss\avoid-render-dynamic-path.yaml`
> Avoid rendering user input. It may be possible for a malicious user to input a path that lets them access a template they shouldn't. To prevent this, check dynamic template paths against a predefined allowlist to make sure it's an allowed template.

---

**`avoid-render-inline`** | WARNING | `community-rules\ruby\rails\security\audit\xss\avoid-render-inline.yaml`
> 'render inline: ...' renders an entire ERB template inline and is dangerous. If external data can reach here, this exposes your application to server-side template injection (SSTI) or cross-site scripting (XSS) attacks. Instead, consider using a partial or another safe rendering method.

---

**`avoid-render-text`** | WARNING | `community-rules\ruby\rails\security\audit\xss\avoid-render-text.yaml`
> 'render text: ...' actually sets the content-type to 'text/html'. If external data can reach here, this exposes your application to cross-site scripting (XSS) attacks. Instead, use 'render plain: ...' to render non-HTML text.

---

**`avoid-session-manipulation`** | WARNING | `community-rules\ruby\rails\security\audit\avoid-session-manipulation.yaml`
> This gets data from session using user inputs. A malicious user may be able to retrieve information from your session that you didn't intend them to. Do not use user input as a session key.

---

**`avoid-tainted-file-access`** | WARNING | `community-rules\ruby\rails\security\audit\avoid-tainted-file-access.yaml`
> Using user input when accessing files is potentially dangerous. A malicious actor could use this to modify or access files they have no right to.

---

**`avoid-tainted-ftp-call`** | WARNING | `community-rules\ruby\rails\security\audit\avoid-tainted-ftp-call.yaml`
> Using user input when accessing files is potentially dangerous. A malicious actor could use this to modify or access files they have no right to.

---

**`avoid-tainted-http-request`** | WARNING | `community-rules\ruby\rails\security\audit\avoid-tainted-http-request.yaml`
> Using user input when accessing files is potentially dangerous. A malicious actor could use this to modify or access files they have no right to.

---

**`avoid-tainted-shell-call`** | ERROR | `community-rules\ruby\rails\security\audit\avoid-tainted-shell-call.yaml`
> Using user input when accessing files is potentially dangerous. A malicious actor could use this to modify or access files they have no right to.

---

**`bad-deserialization`** | ERROR | `community-rules\ruby\lang\security\bad-deserialization.yaml`
> Checks for unsafe deserialization. Objects in Ruby can be serialized into strings, then later loaded from strings. However, uses of load and object_load can cause remote code execution. Loading user input with MARSHAL or CSV can potentially be dangerous. Use JSON in a secure fashion instead.

---

**`bad-deserialization-env`** | ERROR | `community-rules\ruby\lang\security\bad-deserialization-env.yaml`
> Checks for unsafe deserialization. Objects in Ruby can be serialized into strings, then later loaded from strings. However, uses of load and object_load can cause remote code execution. Loading user input with MARSHAL or CSV can potentially be dangerous. Use JSON in a secure fashion instead.

---

**`bad-deserialization-yaml`** | ERROR | `community-rules\ruby\lang\security\bad-deserialization-yaml.yaml`
> Unsafe deserialization from YAML. Objects in Ruby can be serialized into strings, then later loaded from strings. However, uses of load and object_load can cause remote code execution. Loading user input with YAML can potentially be dangerous. Use JSON in a secure fashion instead. However, loading YAML from a static file is not dangerous and should not be flagged.

---

**`bad-send`** | ERROR | `community-rules\ruby\lang\security\no-send.yaml`
> Checks for unsafe use of Object#send, try, __send__, and public_send. These only account for unsafe use of a method, not target. This can lead to arbitrary calling of exit, along with arbitrary code execution. Please be sure to sanitize input in order to avoid this.

---

**`check-before-filter`** | ERROR | `community-rules\ruby\rails\security\brakeman\check-before-filter.yaml`
> Disabled-by-default Rails controller checks make it much easier to introduce access control mistakes. Prefer an allowlist approach with `:only => [...]` rather than `except: => [...]`

---

**`check-cookie-store-session-security-attributes`** | WARNING | `community-rules\ruby\rails\security\brakeman\check-cookie-store-session-security-attributes.yaml`
> Found a Rails `cookie_store` session configuration setting the `$KEY` attribute to `false`. If using a cookie-based session store, the HttpOnly and Secure flags should be set.

---

**`check-dynamic-render-local-file-include`** | WARNING | `community-rules\ruby\rails\security\brakeman\check-dynamic-render-local-file-include.yaml`
> Found request parameters in a call to `render` in a dynamic context. This can allow end users to request arbitrary local files which may result in leaking sensitive information persisted on disk.

---

**`check-http-verb-confusion`** | ERROR | `community-rules\ruby\rails\security\brakeman\check-http-verb-confusion.yaml`
> Found an improperly constructed control flow block with `request.get?`. Rails will route HEAD requests as GET requests but they will fail the `request.get?` check, potentially causing unexpected behavior unless an `elif` condition is used.

---

**`check-permit-attributes-high`** | ERROR | `community-rules\ruby\rails\security\brakeman\check-permit-attributes-high.yaml`
> Calling `permit` on security-critical properties like `$ATTRIBUTE` may leave your application vulnerable to mass assignment.

---

**`check-permit-attributes-medium`** | WARNING | `community-rules\ruby\rails\security\brakeman\check-permit-attributes-medium.yaml`
> Calling `permit` on security-critical properties like `$ATTRIBUTE` may leave your application vulnerable to mass assignment.

---

**`check-rails-secret-yaml`** | WARNING | `community-rules\ruby\rails\security\brakeman\check-rails-secret-yaml.yaml`
> $VALUE Found a string literal assignment to a production Rails session secret in `secrets.yaml`. Do not commit secret values to source control! Any user in possession of this value may falsify arbitrary session data in your application. Read this value from an environment variable, KMS, or file on disk outside of source control.

---

**`check-rails-session-secret-handling`** | WARNING | `community-rules\ruby\rails\security\brakeman\check-rails-session-secret-handling.yaml`
> Found a string literal assignment to a Rails session secret `$KEY`. Do not commit secret values to source control! Any user in possession of this value may falsify arbitrary session data in your application. Read this value from an environment variable, KMS, or file on disk outside of source control.

---

**`check-redirect-to`** | WARNING | `community-rules\ruby\rails\security\brakeman\check-redirect-to.yaml`
> Found potentially unsafe handling of redirect behavior $X. Do not pass `params` to `redirect_to` without the `:only_path => true` hash value.

---

**`check-regex-dos`** | ERROR | `community-rules\ruby\rails\security\brakeman\check-regex-dos.yaml`
> Found a potentially user-controllable argument in the construction of a regular expressions. This may result in excessive resource consumption when applied to certain inputs, or when the user is allowed to control the match target. Avoid allowing users to specify regular expressions processed by the server. If you must support user-controllable input in a regular expression, use an allow-list to restrict the expressions users may supply to limit catastrophic backtracking.

---

**`check-render-local-file-include`** | WARNING | `community-rules\ruby\rails\security\brakeman\check-render-local-file-include.yaml`
> Found request parameters in a call to `render`. This can allow end users to request arbitrary local files which may result in leaking sensitive information persisted on disk. Where possible, avoid letting users specify template paths for `render`. If you must allow user input, use an allow-list of known templates or normalize the user-supplied value with `File.basename(...)`.

---

**`check-reverse-tabnabbing`** | WARNING | `community-rules\ruby\rails\security\brakeman\check-reverse-tabnabbing.yaml`
> Setting an anchor target of `_blank` without the `noopener` or `noreferrer` attribute allows reverse tabnabbing on Internet Explorer, Opera, and Android Webview.

---

**`check-secrets`** | WARNING | `community-rules\ruby\rails\security\brakeman\check-secrets.yaml`
> Found a Brakeman-style secret - a variable with the name password/secret/api_key/rest_auth_site_key and a non-empty string literal value.

---

**`check-send-file`** | ERROR | `community-rules\ruby\rails\security\brakeman\check-send-file.yaml`
> Allowing user input to `send_file` allows a malicious user to potentially read arbitrary files from the server. Avoid accepting user input in `send_file` or normalize with `File.basename(...)`

---

**`check-sql`** | ERROR | `community-rules\ruby\rails\security\brakeman\check-sql.yaml`
> Found potential SQL injection due to unsafe SQL query construction via $X. Where possible, prefer parameterized queries.

---

**`check-unsafe-reflection`** | ERROR | `community-rules\ruby\rails\security\brakeman\check-unsafe-reflection.yaml`
> Found user-controllable input to Ruby reflection functionality. This allows a remote user to influence runtime behavior, up to and including arbitrary remote code execution. Do not provide user-controllable input to reflection functionality. Do not call symbol conversion on user-controllable input.

---

**`check-unsafe-reflection-methods`** | ERROR | `community-rules\ruby\rails\security\brakeman\check-unsafe-reflection-methods.yaml`
> Found user-controllable input to a reflection method. This may allow a user to alter program behavior and potentially execute arbitrary instructions in the context of the process. Do not provide arbitrary user input to `tap`, `method`, or `to_proc`

---

**`check-unscoped-find`** | WARNING | `community-rules\ruby\rails\security\brakeman\check-unscoped-find.yaml`
> Found an unscoped `find(...)` with user-controllable input. If the ActiveRecord model being searched against is sensitive, this may lead to Insecure Direct Object Reference (IDOR) behavior and allow users to read arbitrary records. Scope the find to the current user, e.g. `current_user.accounts.find(params[:id])`.

---

**`check-validation-regex`** | ERROR | `community-rules\ruby\rails\security\brakeman\check-validation-regex.yaml`
> $V Found an incorrectly-bounded regex passed to `validates_format_of` or `validate ... format => ...`. Ruby regex behavior is multiline by default and lines should be terminated by `\A` for beginning of line and `\Z` for end of line, respectively.

---

**`cookie-serialization`** | ERROR | `community-rules\ruby\lang\security\cookie-serialization.yaml`
> Checks if code allows cookies to be deserialized using Marshal. If the attacker can craft a valid cookie, this could lead to remote code execution. The hybrid check is just to warn users to migrate to :json for best practice.

---

**`create-with`** | ERROR | `community-rules\ruby\lang\security\create-with.yaml`
> Checks for strong parameter bypass through usage of create_with. Create_with bypasses strong parameter protection, which could allow attackers to set arbitrary attributes on models. To fix this vulnerability, either remove all create_with calls or use the permit function to specify tags that are allowed to be set.

---

**`dangerous-exec`** | WARNING | `community-rules\ruby\lang\security\dangerous-exec.yaml`
> Detected non-static command inside $EXEC. Audit the input to '$EXEC'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code.

---

**`dangerous-link-to`** | WARNING | `community-rules\ruby\rails\security\audit\xss\templates\dangerous-link-to.yaml`
> Detected a template variable used in 'link_to'. This will generate dynamic data in the 'href' attribute. This allows a malicious actor to input the 'javascript:' URI and is subject to cross- site scripting (XSS) attacks. If using a relative URL, start with a literal forward slash and concatenate the URL, like this: 'link_to "Here", "/"+@link'. You may also consider setting the Content Security Policy (CSP) header.

---

**`dangerous-open`** | WARNING | `community-rules\ruby\lang\security\dangerous-open.yaml`
> Detected non-static command inside 'open'. Audit the input to 'open'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code.

---

**`dangerous-open3-pipeline`** | WARNING | `community-rules\ruby\lang\security\dangerous-open3-pipeline.yaml`
> Detected non-static command inside $PIPE. Audit the input to '$PIPE'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code.

---

**`dangerous-subshell`** | WARNING | `community-rules\ruby\lang\security\dangerous-subshell.yaml`
> Detected non-static command inside `...`. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary code.

---

**`dangerous-syscall`** | WARNING | `community-rules\ruby\lang\security\dangerous-syscall.yaml`
> 'syscall' is essentially unsafe and unportable. The DL (https://apidock.com/ruby/Fiddle) library is preferred for safer and a bit more portable programming.

---

**`detailed-exceptions`** | WARNING | `community-rules\ruby\rails\security\audit\detailed-exceptions.yaml`
> Found that the setting for providing detailed exception reports in Rails is set to true. This can lead to information exposure, where sensitive system or internal information is displayed to the end user. Instead, turn this setting off.

---

**`divide-by-zero`** | WARNING | `community-rules\ruby\lang\security\divide-by-zero.yaml`
> Detected a possible ZeroDivisionError.

---

**`file-disclosure`** | ERROR | `community-rules\ruby\lang\security\file-disclosure.yaml`
> Special requests can determine whether a file exists on a filesystem that's outside the Rails app's root directory. To fix this, set config.serve_static_assets = false.

---

**`filter-skipping`** | ERROR | `community-rules\ruby\lang\security\filter-skipping.yaml`
> Checks for use of action in Ruby routes. This can cause Rails to render an arbitrary view if an attacker creates an URL accurately. Affects 3.0 applications. Can avoid the vulnerability by providing additional constraints.

---

**`force-ssl-false`** | WARNING | `community-rules\ruby\lang\security\force-ssl-false.yaml`
> Checks for configuration setting of force_ssl to false. Force_ssl forces usage of HTTPS, which could lead to network interception of unencrypted application traffic. To fix, set config.force_ssl = true.

---

**`hardcoded-http-auth-in-controller`** | WARNING | `community-rules\ruby\lang\security\hardcoded-http-auth-in-controller.yaml`
> Detected hardcoded password used in basic authentication in a controller class. Including this password in version control could expose this credential. Consider refactoring to use environment variables or configuration files.

---

**`hardcoded-secret-rsa-passphrase`** | WARNING | `community-rules\ruby\lang\security\hardcoded-secret-rsa-passphrase.yaml`
> Found the use of an hardcoded passphrase for RSA. The passphrase can be easily discovered, and therefore should not be stored in source-code. It is recommended to remove the passphrase from source-code, and use system environment variables or a restricted configuration file.

---

**`insufficient-rsa-key-size`** | WARNING | `community-rules\ruby\lang\security\insufficient-rsa-key-size.yaml`
> The RSA key size $SIZE is insufficent by NIST standards. It is recommended to use a key length of 2048 or higher.

---

**`json-entity-escape`** | WARNING | `community-rules\ruby\lang\security\json-entity-escape.yaml`
> Checks if HTML escaping is globally disabled for JSON output. This could lead to XSS.

---

**`libxml-backend`** | WARNING | `community-rules\ruby\rails\security\audit\xxe\libxml-backend.yaml`
> This application is using LibXML as the XML backend. LibXML can be vulnerable to XML External Entities (XXE) vulnerabilities. Use the built-in Rails XML parser, REXML, instead.

---

**`manual-template-creation`** | WARNING | `community-rules\ruby\rails\security\audit\xss\manual-template-creation.yaml`
> Detected manual creation of an ERB template. Manual creation of templates may expose your application to server-side template injection (SSTI) or cross-site scripting (XSS) attacks if user input is used to create the template. Instead, create a '.erb' template file and use 'render'.

---

**`mass-assignment-protection-disabled`** | WARNING | `community-rules\ruby\lang\security\mass-assignment-protection-disabled.yaml`
> Mass assignment protection disabled for '$MODEL'. This could permit assignment to sensitive model fields without intention. Instead, use 'attr_accessible' for the model or disable mass assigment using 'config.active_record.whitelist_attributes = true'. ':without_protection => true' must be removed for this to take effect.

---

**`mass-assignment-vuln`** | WARNING | `community-rules\ruby\lang\security\unprotected-mass-assign.yaml`
> Checks for calls to without_protection during mass assignment (which allows record creation from hash values). This can lead to users bypassing permissions protections. For Rails 4 and higher, mass protection is on by default. Fix: Don't use :without_protection => true. Instead, configure attr_accessible to control attribute access.

---

**`md5-used-as-password`** | WARNING | `community-rules\ruby\lang\security\md5-used-as-password.yaml`
> It looks like MD5 is used as a password hash. MD5 is not considered a secure password hash because it can be cracked by an attacker in a short amount of time. Instead, use a suitable password hashing function such as bcrypt. You can use the `bcrypt` gem.

---

**`missing-csrf-protection`** | ERROR | `community-rules\ruby\lang\security\missing-csrf-protection.yaml`
> Detected controller which does not enable cross-site request forgery protections using 'protect_from_forgery'. Add 'protect_from_forgery :with => :exception' to your controller class.

---

**`model-attr-accessible`** | ERROR | `community-rules\ruby\lang\security\model-attr-accessible.yaml`
> Checks for dangerous permitted attributes that can lead to mass assignment vulnerabilities. Query parameters allowed using permit and attr_accessible are checked for allowance of dangerous attributes admin, banned, role, and account_id. Also checks for usages of params.permit!, which allows everything. Fix: don't allow admin, banned, role, and account_id using permit or attr_accessible.

---

**`model-attributes-attr-accessible`** | ERROR | `community-rules\ruby\lang\security\model-attributes-attr-accessible.yaml`
> Checks for models that do not use attr_accessible. This means there is no limiting of which variables can be manipulated through mass assignment. For newer Rails applications, parameters should be allowlisted using strong parameters. For older Rails versions, they should be allowlisted using strong_attributes.

---

**`mysql2-sqli`** | WARNING | `community-rules\ruby\aws-lambda\security\mysql2-sqli.yaml`
> Detected SQL statement that is tainted by `event` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries or prepared statements instead. You can use sanitize statements like so: `escaped = client.escape(user_input)`

---

**`pg-sqli`** | WARNING | `community-rules\ruby\aws-lambda\security\pg-sqli.yaml`
> Detected SQL statement that is tainted by `event` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries or prepared statements instead. You can use parameterized statements like so: `conn.exec_params('SELECT $1 AS a, $2 AS b, $3 AS c', [1, 2, nil])`

---

**`rails-no-render-after-save`** | WARNING | `community-rules\ruby\rails\correctness\rails-no-render-after-save.yaml`
> Found a call to `render $T` after calling `$T.save`. Do not call `render` after calling `save` on an ActiveRecord object. Reloading the page will cause the state-changing operation to be repeated which may cause undesirable side effects. Use `redirect_to` instead.

---

**`rails-skip-forgery-protection`** | WARNING | `community-rules\ruby\rails\security\audit\rails-skip-forgery-protection.yaml`
> This call turns off CSRF protection allowing CSRF attacks against the application

---

**`raw-html-format`** | WARNING | `community-rules\ruby\rails\security\injection\raw-html-format.yaml`
> Detected user input flowing into a manually constructed HTML string. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross-site scripting vulnerability, which could let attackers steal sensitive user data. Use the `render template` and make template files which will safely render HTML instead, or inspect that the HTML is absolutely rendered safely with a function like `sanitize`.

---

**`ruby-eval`** | WARNING | `community-rules\ruby\lang\security\no-eval.yaml`
> Use of eval with user-controllable input detected. This can lead  to attackers running arbitrary code. Ensure external data does not  reach here, otherwise this is a security vulnerability. Consider  other ways to do this without eval.

---

**`ruby-jwt-decode-without-verify`** | WARNING | `community-rules\ruby\jwt\security\audit\jwt-decode-without-verify.yaml`
> Detected the decoding of a JWT token without a verify step. JWT tokens must be verified before use, otherwise the token's integrity is unknown. This means a malicious actor could forge a JWT token with any claims.

---

**`ruby-jwt-exposed-credentials`** | ERROR | `community-rules\ruby\jwt\security\jwt-exposed-credentials.yaml`
> Password is exposed through JWT token payload. This is not encrypted and the password could be compromised. Do not store passwords in JWT tokens.

---

**`ruby-jwt-exposed-data`** | WARNING | `community-rules\ruby\jwt\security\audit\jwt-exposed-data.yaml`
> The object is passed strictly to jsonwebtoken.sign(...) Make sure that sensitive information is not exposed through JWT token payload.

---

**`ruby-jwt-hardcoded-secret`** | ERROR | `community-rules\ruby\jwt\security\jwt-hardcode.yaml`
> Hardcoded JWT secret or private key is used. This is a Insufficiently Protected Credentials weakness: https://cwe.mitre.org/data/definitions/522.html Consider using an appropriate security mechanism to protect the credentials (e.g. keeping secrets in environment variables)

---

**`ruby-jwt-none-alg`** | ERROR | `community-rules\ruby\jwt\security\jwt-none-alg.yaml`
> Detected use of the 'none' algorithm in a JWT token. The 'none' algorithm assumes the integrity of the token has already been verified. This would allow a malicious actor to forge a JWT token that will automatically be verified. Do not explicitly use the 'none' algorithm. Instead, use an algorithm such as 'HS256'.

---

**`ruby-pg-sqli`** | WARNING | `community-rules\ruby\rails\security\audit\sqli\ruby-pg-sqli.yaml`
> Detected string concatenation with a non-literal variable in a pg Ruby SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries or prepared statements instead. You can use parameterized queries like so: `conn.exec_params('SELECT $1 AS a, $2 AS b, $3 AS c', [1, 2, nil])` And you can use prepared statements with `exec_prepared`.

---

**`ruby-rails-performance-indexes-are-beneficial`** | INFO | `community-rules\ruby\rails\performance\ruby-rails-performance-indexes-are-really-beneficial.yaml`
> The $COLUMN column appears to be a foreign key. Would it benefit from an index? Having an index can improve performance.

---

**`sequel-sqli`** | WARNING | `community-rules\ruby\aws-lambda\security\sequel-sqli.yaml`
> Detected SQL statement that is tainted by `event` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries or prepared statements instead. You can use parameterized statements like so: `DB['select * from items where name = ?', name]`

---

**`sha224-hash`** | WARNING | `community-rules\ruby\lang\security\audit\sha224-hash.yaml`
> This code uses a 224-bit hash function, which is deprecated or disallowed in some security policies. Consider updating to a stronger hash function such as SHA-384 or higher to ensure compliance and security.

---

**`ssl-mode-no-verify`** | WARNING | `community-rules\ruby\lang\security\ssl-mode-no-verify.yaml`
> Detected SSL that will accept an unverified connection. This makes the connections susceptible to man-in-the-middle attacks. Use 'OpenSSL::SSL::VERIFY_PEER' instead.

---

**`tainted-deserialization`** | WARNING | `community-rules\ruby\aws-lambda\security\tainted-deserialization.yaml`
> Deserialization of a string tainted by `event` object found. Objects in Ruby can be serialized into strings, then later loaded from strings. However, uses of `load` can cause remote code execution. Loading user input with MARSHAL, YAML or CSV can potentially be dangerous. If you need to deserialize untrusted data, you should use JSON as it is only capable of returning 'primitive' types such as strings, arrays, hashes, numbers and nil.

---

**`tainted-sql-string`** | ERROR | `community-rules\ruby\aws-lambda\security\tainted-sql-string.yaml`
> Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify contents of the database. Instead, use a parameterized query which is available by default in most database engines. Alternatively, consider using an object-relational mapper (ORM) such as Sequelize which will protect your queries.

---

**`tainted-sql-string`** | ERROR | `community-rules\ruby\rails\security\injection\tainted-sql-string.yaml`
> Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify contents of the database. Instead, use a parameterized query which is available by default in most database engines. Alternatively, consider using an object-relational mapper (ORM) such as ActiveRecord which will protect your queries.

---

**`tainted-url-host`** | WARNING | `community-rules\ruby\rails\security\injection\tainted-url-host.yaml`
> User data flows into the host portion of this manually-constructed URL. This could allow an attacker to send data to their own server, potentially exposing sensitive data such as cookies or authorization information sent with this request. They could also probe internal servers or other resources that the server running this code can access. (This is called server-side request forgery, or SSRF.) Do not allow arbitrary hosts. Use the `ssrf_filter` gem and guard the url construction with `SsrfFilter(...)`, or create an allowlist for approved hosts.

---

**`unquoted-attribute`** | WARNING | `community-rules\ruby\rails\security\audit\xss\templates\unquoted-attribute.yaml`
> Detected a unquoted template variable as an attribute. If unquoted, a malicious actor could inject custom JavaScript handlers. To fix this, add quotes around the template expression, like this: "<%= expr %>".

---

**`var-in-href`** | WARNING | `community-rules\ruby\rails\security\audit\xss\templates\var-in-href.yaml`
> Detected a template variable used in an anchor tag with the 'href' attribute. This allows a malicious actor to input the 'javascript:' URI and is subject to cross- site scripting (XSS) attacks. If using a relative URL, start with a literal forward slash and concatenate the URL, like this: href='/<%= link =>'. You may also consider setting the Content Security Policy (CSP) header.

---

**`var-in-script-tag`** | WARNING | `community-rules\ruby\rails\security\audit\xss\templates\var-in-script-tag.yaml`
> Detected a template variable used in a script tag. Although template variables are HTML escaped, HTML escaping does not always prevent cross-site scripting (XSS) attacks when used directly in JavaScript. If you need to do this, use `escape_javascript` or its alias, `j`. However, this will not protect from XSS in all circumstances; see the references for more information. Consider placing this value in the HTML portion (outside of a script tag).

---

**`weak-hashes-md5`** | WARNING | `community-rules\ruby\lang\security\weak-hashes-md5.yaml`
> Should not use md5 to generate hashes. md5 is proven to be vulnerable through the use of brute-force attacks. Could also result in collisions, leading to potential collision attacks. Use SHA256 or other hashing functions instead.

---

**`weak-hashes-sha1`** | WARNING | `community-rules\ruby\lang\security\weak-hashes-sha1.yaml`
> Should not use SHA1 to generate hashes. There is a proven SHA1 hash collision by Google, which could lead to vulnerabilities. Use SHA256, SHA3 or other hashing functions instead.

---

**`xml-external-entities-enabled`** | ERROR | `community-rules\ruby\rails\security\audit\xxe\xml-external-entities-enabled.yaml`
> This application is explicitly enabling external entities enabling an attacker to inject malicious XML to exploit an XML External Entities (XXE) vulnerability. This could let the attacker cause a denial-of-service by forcing the parser to parse large files, or at worst, let the attacker download sensitive files or user data. Use the built-in Rails XML parser, REXML, instead.

---

## Rust (10 rules)

**`args`** | INFO | `community-rules\rust\lang\security\args.yml`
> args should not be used for security operations. From the docs: "The first element is traditionally the path of the executable, but it can be set to arbitrary text, and might not even exist. This means this property should not be relied upon for security purposes."

---

**`args-os`** | INFO | `community-rules\rust\lang\security\args-os.yml`
> args_os should not be used for security operations. From the docs: "The first element is traditionally the path of the executable, but it can be set to arbitrary text, and might not even exist. This means this property should not be relied upon for security purposes."

---

**`current-exe`** | INFO | `community-rules\rust\lang\security\current-exe.yml`
> current_exe should not be used for security operations. From the docs: "The output of this function should not be trusted for anything that might have security implications. Basically, if users can run the executable, they can change the output arbitrarily."

---

**`insecure-hashes`** | WARNING | `community-rules\rust\lang\security\insecure-hashes.yml`
> Detected cryptographically insecure hashing function

---

**`reqwest-accept-invalid`** | WARNING | `community-rules\rust\lang\security\reqwest-accept-invalid.yml`
> Dangerously accepting invalid TLS information

---

**`reqwest-set-sensitive`** | INFO | `community-rules\rust\lang\security\reqwest-set-sensitive.yml`
> Set sensitive flag on security headers with 'set_sensitive' to treat data with special care

---

**`rustls-dangerous`** | WARNING | `community-rules\rust\lang\security\rustls-dangerous.yml`
> Dangerous client config used, ensure SSL verification

---

**`ssl-verify-none`** | WARNING | `community-rules\rust\lang\security\ssl-verify-none.yml`
> SSL verification disabled, this allows for MitM attacks

---

**`temp-dir`** | INFO | `community-rules\rust\lang\security\temp-dir.yml`
> temp_dir should not be used for security operations. From the docs: 'The temporary directory may be shared among users, or between processes with different privileges; thus, the creation of any files or directories in the temporary directory must use a secure method to create a uniquely named file. Creating a file or directory with a fixed or predictable name may result in “insecure temporary file” security vulnerabilities.'

---

**`unsafe-usage`** | INFO | `community-rules\rust\lang\security\unsafe-usage.yml`
> Detected 'unsafe' usage, please audit for secure usage

---

## Scala (27 rules)

**`conf-csrf-headers-bypass`** | ERROR | `community-rules\scala\play\security\conf-csrf-headers-bypass.yaml`
> Possibly bypassable CSRF configuration found. CSRF is an attack that forces an end user to execute unwanted actions on a web application in which they’re currently authenticated. Make sure that Content-Type black list is configured and CORS filter is turned on.

---

**`conf-insecure-cookie-settings`** | WARNING | `community-rules\scala\play\security\conf-insecure-cookie-settings.yaml`
> Session cookie `Secure` flag is explicitly disabled. The `secure` flag for cookies prevents the client from transmitting the cookie over insecure channels such as HTTP. Set the `Secure` flag by setting `secure` to `true` in configuration file.

---

**`dangerous-seq-run`** | ERROR | `community-rules\scala\lang\security\audit\dangerous-seq-run.yaml`
> Found dynamic content used for the external process. This is dangerous if arbitrary data can reach this function call because it allows a malicious actor to execute commands. Ensure your variables are not controlled by users or sufficiently sanitized.

---

**`dangerous-shell-run`** | ERROR | `community-rules\scala\lang\security\audit\dangerous-shell-run.yaml`
> Found dynamic content used for the external process. This is dangerous if arbitrary data can reach this function call because it allows a malicious actor to execute commands. Ensure your variables are not controlled by users or sufficiently sanitized.

---

**`dispatch-ssrf`** | WARNING | `community-rules\scala\lang\security\audit\dispatch-ssrf.yaml`
> A parameter being passed directly into `url` most likely lead to SSRF. This could allow an attacker to send data to their own server, potentially exposing sensitive data sent with this request. They could also probe internal servers or other resources that the server running this code can access. Do not allow arbitrary hosts. Instead, create an allowlist for approved hosts, or hardcode the correct host.

---

**`documentbuilder-dtd-enabled`** | WARNING | `community-rules\scala\lang\security\audit\documentbuilder-dtd-enabled.yaml`
> Document Builder being instantiated without calling the `setFeature` functions that are generally used for disabling entity processing. User controlled data in XML Document builder can result in XML Internal Entity Processing vulnerabilities like the disclosure of confidential data, denial of service, Server Side Request Forgery (SSRF), port scanning. Make sure to disable entity processing functionality.

---

**`insecure-random`** | WARNING | `community-rules\scala\lang\security\audit\insecure-random.yaml`
> Flags the use of a predictable random value from `scala.util.Random`. This can lead to vulnerabilities when used in security contexts, such as in a CSRF token, password reset token, or any other secret value. To fix this, use java.security.SecureRandom instead.

---

**`io-source-ssrf`** | WARNING | `community-rules\scala\lang\security\audit\io-source-ssrf.yaml`
> A parameter being passed directly into `fromURL` most likely lead to SSRF. This could allow an attacker to send data to their own server, potentially exposing sensitive data sent with this request. They could also probe internal servers or other resources that the server running this code can access. Do not allow arbitrary hosts. Instead, create an allowlist for approved hosts, or hardcode the correct host.

---

**`jwt-scala-hardcode`** | WARNING | `community-rules\scala\jwt-scala\security\jwt-scala-hardcode.yaml`
> Hardcoded JWT secret or private key is used. This is a Insufficiently Protected Credentials weakness: https://cwe.mitre.org/data/definitions/522.html Consider using an appropriate security mechanism to protect the credentials (e.g. keeping secrets in environment variables)

---

**`path-traversal-fromfile`** | WARNING | `community-rules\scala\lang\security\audit\path-traversal-fromfile.yaml`
> Flags cases of possible path traversal. If an unfiltered parameter is passed into 'fromFile', file from an arbitrary filesystem location could be read. This could lead to sensitive data exposure and other provles. Instead, sanitize the user input instead of performing direct string concatenation.

---

**`positive-number-index-of`** | WARNING | `community-rules\scala\lang\correctness\positive-number-index-of.yaml`
> Flags scala code that look for values that are greater than 0. This ignores the first element, which is most likely a bug. Instead, use indexOf with -1. If the intent is to check the inclusion of a value, use the contains method instead.

---

**`rsa-padding-set`** | WARNING | `community-rules\scala\lang\security\audit\rsa-padding-set.yaml`
> Usage of RSA without OAEP (Optimal Asymmetric Encryption Padding) may weaken encryption. This could lead to sensitive data exposure. Instead, use RSA with `OAEPWithMD5AndMGF1Padding` instead.

---

**`sax-dtd-enabled`** | WARNING | `community-rules\scala\lang\security\audit\sax-dtd-enabled.yaml`
> XML processor being instantiated without calling the `setFeature` functions that are generally used for disabling entity processing. User controlled data in XML Parsers can result in XML Internal Entity Processing vulnerabilities like the disclosure of confidential data, denial of service, Server Side Request Forgery (SSRF), port scanning. Make sure to disable entity processing functionality.

---

**`scala-dangerous-process-run`** | ERROR | `community-rules\scala\lang\security\audit\scala-dangerous-process-run.yaml`
> Found dynamic content used for the external process. This is dangerous if arbitrary data can reach this function call because it allows a malicious actor to execute commands. Use `Seq(...)` for dynamically generated commands.

---

**`scala-jwt-hardcoded-secret`** | ERROR | `community-rules\scala\scala-jwt\security\jwt-hardcode.yaml`
> Hardcoded JWT secret or private key is used. This is a Insufficiently Protected Credentials weakness: https://cwe.mitre.org/data/definitions/522.html Consider using an appropriate security mechanism to protect the credentials (e.g. keeping secrets in environment variables)

---

**`scala-slick-overrideSql-literal`** | ERROR | `community-rules\scala\slick\security\scala-slick-overrideSql-literal.yaml`
> Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Avoid using non literal values in `overrideSql(...)`.

---

**`scala-slick-sql-non-literal`** | ERROR | `community-rules\scala\slick\security\scala-slick-sql-non-literal.yaml`
> Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Avoid using `#$variable` and use `$variable` in `sql"..."` strings instead.

---

**`scalac-debug`** | WARNING | `community-rules\scala\lang\security\audit\scalac-debug.yaml`
> Scala applications built with `debug` set to true in production may leak debug information to attackers. Debug mode also affects performance and reliability. Remove it from configuration.

---

**`scalaj-http-ssrf`** | WARNING | `community-rules\scala\lang\security\audit\scalaj-http-ssrf.yaml`
> A parameter being passed directly into `Http` can likely lead to SSRF. This could allow an attacker to send data to their own server, potentially exposing sensitive data sent with this request. They could also probe internal servers or other resources that the server running this code can access. Do not allow arbitrary hosts. Instead, create an allowlist for approved hosts, or hardcode the correct host.

---

**`scalajs-eval`** | WARNING | `community-rules\scala\lang\security\audit\scalajs-eval.yaml`
> `eval()` function evaluates JavaScript code represented as a string. Executing JavaScript from a string is an enormous security risk. It is far too easy for a bad actor to run arbitrary code when you use `eval()`. Do not use eval(). Alternatively: Ensure evaluated content is not definable by external sources. If it’s not possible, strip everything except alphanumeric characters from an input provided for the command string and arguments.

---

**`tainted-html-response`** | WARNING | `community-rules\scala\play\security\tainted-html-response.yaml`
> Detected a request with potential user-input going into an `Ok()` response. This bypasses any view or template environments, including HTML escaping, which may expose this application to cross-site scripting (XSS) vulnerabilities. Consider using a view technology such as Twirl which automatically escapes HTML views.

---

**`tainted-slick-sqli`** | ERROR | `community-rules\scala\play\security\tainted-slick-sqli.yaml`
> Detected a tainted SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Avoid using using user input for generating SQL strings.

---

**`tainted-sql-from-http-request`** | ERROR | `community-rules\scala\play\security\tainted-sql-from-http-request.yaml`
> User data flows into this manually-constructed SQL string. User data can be safely inserted into SQL strings using prepared statements or an object-relational mapper (ORM). Manually-constructed SQL strings is a possible indicator of SQL injection, which could let an attacker steal or manipulate data from the database. Instead, use prepared statements (`connection.PreparedStatement`) or a safe library.

---

**`tainted-sql-string`** | ERROR | `community-rules\scala\lang\security\audit\tainted-sql-string.yaml`
> User data flows into this manually-constructed SQL string. User data can be safely inserted into SQL strings using prepared statements or an object-relational mapper (ORM). Manually-constructed SQL strings is a possible indicator of SQL injection, which could let an attacker steal or manipulate data from the database. Instead, use prepared statements (`connection.PreparedStatement`) or a safe library.

---

**`twirl-html-var`** | WARNING | `community-rules\scala\play\security\twirl-html-var.yaml`
> Raw html content controlled by a variable detected. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross-site scripting vulnerability, which could let attackers steal sensitive user data. Try to avoid using `Html()` or consider properly sanitizing input data.

---

**`webservice-ssrf`** | WARNING | `community-rules\scala\play\security\webservice-ssrf.yaml`
> A parameter being passed directly into `WSClient` most likely lead to SSRF. This could allow an attacker to send data to their own server, potentially exposing sensitive data sent with this request. They could also probe internal servers or other resources that the server running this code can access. Do not allow arbitrary hosts. Instead, create an allowlist for approved hosts hardcode the correct host.

---

**`xmlinputfactory-dtd-enabled`** | WARNING | `community-rules\scala\lang\security\audit\xmlinputfactory-dtd-enabled.yaml`
> XMLInputFactory being instantiated without calling the setProperty functions that are generally used for disabling entity processing. User controlled data in XML Document builder can result in XML Internal Entity Processing vulnerabilities like the disclosure of confidential data, denial of service, Server Side Request Forgery (SSRF), port scanning. Make sure to disable entity processing functionality.

---

## Solidity (50 rules)

**`accessible-selfdestruct`** | ERROR | `community-rules\solidity\security\accessible-selfdestruct.yaml`
> Contract can be destructed by anyone in $FUNC

---

**`arbitrary-low-level-call`** | ERROR | `community-rules\solidity\security\arbitrary-low-level-call.yaml`
> An attacker may perform call() to an arbitrary address with controlled calldata

---

**`arbitrary-send-erc20`** | WARNING | `community-rules\solidity\security\arbitrary-send-erc20.yaml`
> msg.sender is not being used when calling erc20.transferFrom. Example - Alice approves this contract to spend her ERC20 tokens. Bob can call function 'a' and specify Alice's address as the from parameter in transferFrom, allowing him to transfer Alice's tokens to himself.

---

**`array-length-outside-loop`** | INFO | `community-rules\solidity\performance\array-length-outside-loop.yaml`
> Caching the array length outside a loop saves reading it on each iteration, as long as the array's length is not changed during the loop.

---

**`balancer-readonly-reentrancy-getpooltokens`** | ERROR | `community-rules\solidity\security\balancer-readonly-reentrancy-getpooltokens.yaml`
> $VAULT.getPoolTokens() call on a Balancer pool is not protected from the read-only reentrancy.

---

**`balancer-readonly-reentrancy-getrate`** | ERROR | `community-rules\solidity\security\balancer-readonly-reentrancy-getrate.yaml`
> $VAR.getRate() call on a Balancer pool is not protected from the read-only reentrancy.

---

**`basic-arithmetic-underflow`** | INFO | `community-rules\solidity\security\basic-arithmetic-underflow.yaml`
> Possible arithmetic underflow

---

**`basic-oracle-manipulation`** | INFO | `community-rules\solidity\security\basic-oracle-manipulation.yaml`
> Price oracle can be manipulated via flashloan

---

**`compound-borrowfresh-reentrancy`** | WARNING | `community-rules\solidity\security\compound-borrowfresh-reentrancy.yaml`
> Function borrowFresh() in Compound performs state update after doTransferOut()

---

**`compound-sweeptoken-not-restricted`** | WARNING | `community-rules\solidity\security\compound-sweeptoken-not-restricted.yaml`
> Function sweepToken is allowed to be called by anyone

---

**`curve-readonly-reentrancy`** | ERROR | `community-rules\solidity\security\curve-readonly-reentrancy.yaml`
> $POOL.get_virtual_price() call on a Curve pool is not protected from the read-only reentrancy.

---

**`delegatecall-to-arbitrary-address`** | ERROR | `community-rules\solidity\security\delegatecall-to-arbitrary-address.yaml`
> An attacker may perform delegatecall() to an arbitrary address.

---

**`encode-packed-collision`** | ERROR | `community-rules\solidity\security\encode-packed-collision.yaml`
> abi.encodePacked hash collision with variable length arguments in $F()

---

**`erc20-public-burn`** | ERROR | `community-rules\solidity\security\erc20-public-burn.yaml`
> Anyone can burn tokens of other accounts

---

**`erc20-public-transfer`** | WARNING | `community-rules\solidity\security\erc20-public-transfer.yaml`
> Custom ERC20 implementation exposes _transfer() as public

---

**`erc677-reentrancy`** | WARNING | `community-rules\solidity\security\erc677-reentrancy.yaml`
> ERC677 callAfterTransfer() reentrancy

---

**`erc721-arbitrary-transferfrom`** | WARNING | `community-rules\solidity\security\erc721-arbitrary-transferfrom.yaml`
> Custom ERC721 implementation lacks access control checks in _transfer()

---

**`erc721-reentrancy`** | WARNING | `community-rules\solidity\security\erc721-reentrancy.yaml`
> ERC721 onERC721Received() reentrancy

---

**`erc777-reentrancy`** | WARNING | `community-rules\solidity\security\erc777-reentrancy.yaml`
> ERC777 tokensReceived() reentrancy

---

**`gearbox-tokens-path-confusion`** | WARNING | `community-rules\solidity\security\gearbox-tokens-path-confusion.yaml`
> UniswapV3 adapter implemented incorrect extraction of path parameters

---

**`incorrect-use-of-blockhash`** | ERROR | `community-rules\solidity\security\incorrect-use-of-blockhash.yaml`
> blockhash(block.number) and blockhash(block.number + N) always returns 0.

---

**`inefficient-state-variable-increment`** | INFO | `community-rules\solidity\performance\inefficient-state-variable-increment.yaml`
> <x> += <y> costs more gas than <x> = <x> + <y> for state variables.

---

**`init-variables-with-default-value`** | INFO | `community-rules\solidity\performance\init-variables-with-default-value.yaml`
> Uninitialized variables are assigned with the types default value. Explicitly initializing a variable with its default value costs unnecessary gas.

---

**`keeper-network-oracle-manipulation`** | WARNING | `community-rules\solidity\security\keeper-network-oracle-manipulation.yaml`
> Keep3rV2.current() call has high data freshness, but it has low security,  an exploiter simply needs to manipulate 2 data points to be able to impact the feed.

---

**`missing-self-transfer-check-ercx`** | ERROR | `community-rules\solidity\security\missing-self-transfer-check-ercx.yaml`
> Missing check for 'from' and 'to' being the same before updating balances could lead to incorrect balance manipulation on self-transfers. Include a check to ensure 'from' and 'to' are not the same before updating balances to prevent balance manipulation during self-transfers.

---

**`msg-value-multicall`** | ERROR | `community-rules\solidity\security\msg-value-multicall.yaml`
> $F with constant msg.value can be called multiple times

---

**`no-bidi-characters`** | WARNING | `community-rules\solidity\security\no-bidi-characters.yaml`
> The code must not contain any of Unicode Direction Control Characters

---

**`no-slippage-check`** | ERROR | `community-rules\solidity\security\no-slippage-check.yaml`
> No slippage check in a Uniswap v2/v3 trade

---

**`non-optimal-variables-swap`** | INFO | `community-rules\solidity\performance\non-optimal-variables-swap.yaml`
> Consider swapping variables using `($VAR1, $VAR2) = ($VAR2, $VAR1)` to save gas

---

**`non-payable-constructor`** | INFO | `community-rules\solidity\performance\non-payable-constructor.yaml`
> Consider making costructor payable to save gas.

---

**`openzeppelin-ecdsa-recover-malleable`** | WARNING | `community-rules\solidity\security\openzeppelin-ecdsa-recover-malleable.yaml`
> Potential signature malleability in $F

---

**`oracle-price-update-not-restricted`** | ERROR | `community-rules\solidity\security\oracle-price-update-not-restricted.yaml`
> Oracle price data can be submitted by anyone

---

**`proxy-storage-collision`** | WARNING | `community-rules\solidity\security\proxy-storage-collision.yaml`
> Proxy declares a state var that may override a storage slot of the implementation

---

**`redacted-cartel-custom-approval-bug`** | ERROR | `community-rules\solidity\security\redacted-cartel-custom-approval-bug.yaml`
> transferFrom() can steal allowance of other accounts

---

**`rigoblock-missing-access-control`** | ERROR | `community-rules\solidity\security\rigoblock-missing-access-control.yaml`
> setMultipleAllowances() is missing onlyOwner modifier

---

**`sense-missing-oracle-access-control`** | ERROR | `community-rules\solidity\security\sense-missing-oracle-access-control.yaml`
> Oracle update is not restricted in $F()

---

**`state-variable-read-in-a-loop`** | INFO | `community-rules\solidity\performance\state-variable-read-in-a-loop.yaml`
> Replace state variable reads and writes within loops with local variable reads and writes.

---

**`superfluid-ctx-injection`** | ERROR | `community-rules\solidity\security\superfluid-ctx-injection.yaml`
> A specially crafted calldata may be used to impersonate other accounts

---

**`tecra-coin-burnfrom-bug`** | ERROR | `community-rules\solidity\security\tecra-coin-burnfrom-bug.yaml`
> Parameter "from" is checked at incorrect position in "_allowances" mapping

---

**`uniswap-callback-not-protected`** | WARNING | `community-rules\solidity\security\uniswap-callback-not-protected.yaml`
> Uniswap callback is not protected

---

**`unnecessary-checked-arithmetic-in-loop`** | INFO | `community-rules\solidity\performance\unnecessary-checked-arithmetic-in-loop.yaml`
> A lot of times there is no risk that the loop counter can overflow.  Using Solidity's unchecked block saves the overflow checks.

---

**`unrestricted-transferownership`** | ERROR | `community-rules\solidity\security\unrestricted-transferownership.yaml`
> Unrestricted transferOwnership

---

**`use-abi-encodecall-instead-of-encodewithselector`** | INFO | `community-rules\solidity\best-practice\use-abi-encodecall-instead-of-encodewithselector.yaml`
> To guarantee arguments type safety it is recommended to use `abi.encodeCall` instead of `abi.encodeWithSelector`.

---

**`use-custom-error-not-require`** | INFO | `community-rules\solidity\performance\use-custom-error-not-require.yaml`
> Consider using custom errors as they are more gas efficient while allowing developers  to describe the error in detail using NatSpec.

---

**`use-multiple-require`** | INFO | `community-rules\solidity\performance\use-multiple-require.yaml`
> Using multiple require statements is cheaper than using && multiple check combinations.  There are more advantages, such as easier to read code and better coverage reports.

---

**`use-nested-if`** | INFO | `community-rules\solidity\performance\use-nested-if.yaml`
> Using nested is cheaper than using && multiple check combinations.  There are more advantages, such as easier to read code and better coverage reports.

---

**`use-ownable2step`** | INFO | `community-rules\solidity\best-practice\use-ownable2step.yaml`
> By demanding that the receiver of the owner permissions actively accept via a contract call of its own,  `Ownable2Step` and `Ownable2StepUpgradeable` prevent the contract ownership from accidentally being transferred  to an address that cannot handle it.

---

**`use-prefix-decrement-not-postfix`** | INFO | `community-rules\solidity\performance\use-prefix-decrement-not-postfix.yaml`
> Consider using the prefix decrement expression whenever the return value is not needed. The prefix decrement expression is cheaper in terms of gas.

---

**`use-prefix-increment-not-postfix`** | INFO | `community-rules\solidity\performance\use-prefix-increment-not-postfix.yaml`
> Consider using the prefix increment expression whenever the return value is not needed. The prefix increment expression is cheaper in terms of gas.

---

**`use-short-revert-string`** | INFO | `community-rules\solidity\performance\use-short-revert-string.yaml`
> Shortening revert strings to fit in 32 bytes will decrease gas costs for deployment and  gas costs when the revert condition has been met.

---

## Swift (4 rules)

**`insecure-random`** | WARNING | `community-rules\swift\lang\crypto\insecure-random.yaml`
> A random number generator was detected which is **not** *guaranteed* to be Cryptographically secure. If the source of entropy is used for security purposes (e.g. with other Cryptographic operations), make sure to use the `SecCopyRandomBytes` API explicitly.

---

**`swift-potential-sqlite-injection`** | WARNING | `community-rules\swift\sqllite\sqllite-injection-audit.yaml`
> Potential Client-side SQL injection which has different impacts depending on the SQL use-case. The impact may include the circumvention of local authentication mechanisms, obtaining of sensitive data from the app, or manipulation of client-side behavior. It wasn't possible to make certain that the source is untrusted, but the application should avoid concatenating dynamic data into SQL queries and should instead leverage parameterized queries.

---

**`swift-user-defaults`** | WARNING | `community-rules\swift\lang\storage\sensitive-storage-userdefaults.yaml`
> Potentially sensitive data was observed to be stored in UserDefaults, which is not adequate protection of sensitive information. For data of a sensitive nature, applications should leverage the Keychain.

---

**`swift-webview-config-allows-js-open-windows`** | WARNING | `community-rules\swift\webview\webview-js-window.yaml`
> Webviews were observed that explictly allow JavaScript in an WKWebview to open windows automatically. Consider disabling this functionality if not required, following the principle of least privelege.

---

## Template.yaml (1 rules)

**`eqeq-is-bad`** | ERROR | `community-rules\template.yaml`
> $X == $X is a useless equality check

---

## Terraform (364 rules)

**`all-origins-allowed`** | WARNING | `community-rules\terraform\lang\security\s3-cors-all-origins.yaml`
> CORS rule on bucket permits any origin

---

**`appservice-account-identity-registered`** | INFO | `community-rules\terraform\azure\security\appservice\appservice-account-identity-registered.yaml`
> Registering the identity used by an App with AD allows it to interact with other services without using username and password. Set the `identity` block in your appservice.

---

**`appservice-authentication-enabled`** | ERROR | `community-rules\terraform\azure\security\appservice\appservice-authentication-enabled.yaml`
> Enabling authentication ensures that all communications in the application are authenticated. The `auth_settings` block needs to be filled out with the appropriate auth backend settings

---

**`appservice-enable-http2`** | INFO | `community-rules\terraform\azure\security\appservice\appservice-enable-http2.yaml`
> Use the latest version of HTTP to ensure you are benefiting from security fixes. Add `http2_enabled = true` to your appservice resource block

---

**`appservice-enable-https-only`** | ERROR | `community-rules\terraform\azure\security\appservice\appservice-enable-https-only.yaml`
> By default, clients can connect to App Service by using both HTTP or HTTPS. HTTP should be disabled enabling the HTTPS Only setting.

---

**`appservice-require-client-cert`** | INFO | `community-rules\terraform\azure\security\appservice\appservice-require-client-cert.yaml`
> Detected an AppService that was not configured to use a client certificate. Add `client_cert_enabled = true` in your resource block.

---

**`appservice-use-secure-tls-policy`** | ERROR | `community-rules\terraform\azure\security\appservice\appservice-use-secure-tls-policy.yaml`
> Detected an AppService that was not configured to use TLS 1.2. Add `site_config.min_tls_version = "1.2"` in your resource block.

---

**`aws-athena-client-can-disable-workgroup-encryption`** | WARNING | `community-rules\terraform\aws\security\aws-athena-client-can-disable-workgroup-encryption.yaml`
> The Athena workgroup configuration can be overriden by client-side settings. The client can make changes to disable encryption settings. Enforce the configuration to prevent client overrides.

---

**`aws-athena-database-unencrypted`** | WARNING | `community-rules\terraform\aws\security\aws-athena-database-unencrypted.yaml`
> The Athena database is unencrypted at rest. These databases are generally derived from data in S3 buckets and should have the same level of at rest protection. The AWS KMS encryption key protects database contents. To create your own, create a aws_kms_key resource or use the ARN string of a key in your account.

---

**`aws-athena-workgroup-unencrypted`** | WARNING | `community-rules\terraform\aws\security\aws-athena-workgroup-unencrypted.yaml`
> The AWS Athena Work Group is unencrypted. The AWS KMS encryption key protects backups in the work group. To create your own, create a aws_kms_key resource or use the ARN string of a key in your account.

---

**`aws-backup-vault-unencrypted`** | WARNING | `community-rules\terraform\aws\security\aws-backup-vault-unencrypted.yaml`
> The AWS Backup vault is unencrypted. The AWS KMS encryption key protects backups in the Backup vault. To create your own, create a aws_kms_key resource or use the ARN string of a key in your account.

---

**`aws-cloudtrail-encrypted-with-cmk`** | WARNING | `community-rules\terraform\aws\security\aws-cloudtrail-encrypted-with-cmk.yaml`
> Ensure CloudTrail logs are encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.

---

**`aws-cloudwatch-log-group-no-retention`** | WARNING | `community-rules\terraform\aws\security\aws-cloudwatch-log-group-no-retention.yaml`
> The AWS CloudWatch Log Group has no retention. Missing retention in log groups can cause losing important event information.

---

**`aws-cloudwatch-log-group-unencrypted`** | WARNING | `community-rules\terraform\aws\security\aws-cloudwatch-log-group-unencrypted.yaml`
> By default, AWS CloudWatch Log Group is encrypted using AWS-managed keys. However, for added security, it's recommended to configure your own AWS KMS encryption key to protect your log group in CloudWatch. You can either create a new aws_kms_key resource or use the ARN of an existing key in your AWS account to do so.

---

**`aws-codebuild-artifacts-unencrypted`** | WARNING | `community-rules\terraform\aws\security\aws-codebuild-artifacts-unencrypted.yaml`
> The CodeBuild project artifacts are unencrypted. All artifacts produced by your CodeBuild project pipeline should be encrypted to prevent them from being read if compromised.

---

**`aws-codebuild-project-artifacts-unencrypted`** | WARNING | `community-rules\terraform\aws\security\aws-codebuild-project-artifacts-unencrypted.yaml`
> The AWS CodeBuild Project Artifacts are unencrypted. The AWS KMS encryption key protects artifacts in the CodeBuild Projects. To create your own, create a aws_kms_key resource or use the ARN string of a key in your account.

---

**`aws-codebuild-project-unencrypted`** | WARNING | `community-rules\terraform\aws\security\aws-codebuild-project-unencrypted.yaml`
> The AWS CodeBuild Project is unencrypted. The AWS KMS encryption key protects projects in the CodeBuild. To create your own, create a aws_kms_key resource or use the ARN string of a key in your account.

---

**`aws-config-aggregator-not-all-regions`** | WARNING | `community-rules\terraform\aws\security\aws-config-aggregator-not-all-regions.yaml`
> The AWS configuration aggregator does not aggregate all AWS Config region. This may result in unmonitored configuration in regions that are thought to be unused. Configure the aggregator with all_regions for the source.

---

**`aws-db-instance-no-logging`** | WARNING | `community-rules\terraform\aws\security\aws-db-instance-no-logging.yaml`
> Database instance has no logging. Missing logs can cause missing important event information.

---

**`aws-docdb-encrypted-with-cmk`** | WARNING | `community-rules\terraform\aws\security\aws-docdb-encrypted-with-cmk.yaml`
> Ensure DocDB is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.

---

**`aws-documentdb-auditing-disabled`** | INFO | `community-rules\terraform\aws\security\aws-documentdb-auditing-disabled.yaml`
> Auditing is not enabled for DocumentDB. To ensure that you are able to accurately audit the usage of your DocumentDB cluster, you should enable auditing and export logs to CloudWatch.

---

**`aws-documentdb-storage-unencrypted`** | WARNING | `community-rules\terraform\aws\security\aws-documentdb-storage-unencrypted.yaml`
> The AWS DocumentDB cluster is unencrypted. The data could be read if the underlying disks are compromised. You should enable storage encryption.

---

**`aws-dynamodb-point-in-time-recovery-disabled`** | INFO | `community-rules\terraform\aws\security\aws-dynamodb-point-in-time-recovery-disabled.yaml`
> Point-in-time recovery is not enabled for the DynamoDB table. DynamoDB tables should be protected against accidental or malicious write/delete actions. By enabling point-in-time-recovery you can restore to a known point in the event of loss of data.

---

**`aws-dynamodb-table-unencrypted`** | WARNING | `community-rules\terraform\aws\security\aws-dynamodb-table-unencrypted.yaml`
> By default, AWS DynamoDB Table is encrypted using AWS-managed keys. However, for added security, it's recommended to configure your own AWS KMS encryption key to protect your data in the DynamoDB table. You can either create a new aws_kms_key resource or use the ARN of an existing key in your AWS account to do so.

---

**`aws-ebs-snapshot-encrypted-with-cmk`** | WARNING | `community-rules\terraform\aws\security\aws-ebs-snapshot-encrypted-with-cmk.yaml`
> Ensure EBS Snapshot is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.

---

**`aws-ebs-unencrypted`** | WARNING | `community-rules\terraform\aws\security\aws-ebs-unencrypted.yaml`
> The AWS EBS is unencrypted. The AWS EBS encryption protects data in the EBS.

---

**`aws-ebs-volume-encrypted-with-cmk`** | WARNING | `community-rules\terraform\aws\security\aws-ebs-volume-encrypted-with-cmk.yaml`
> Ensure EBS Volume is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.

---

**`aws-ebs-volume-unencrypted`** | WARNING | `community-rules\terraform\aws\security\aws-ebs-volume-unencrypted.yaml`
> The AWS EBS volume is unencrypted. The volume, the disk I/O and any derived snapshots could be read if compromised. Volumes should be encrypted to ensure sensitive data is stored securely.

---

**`aws-ec2-has-public-ip`** | WARNING | `community-rules\terraform\aws\security\aws-ec2-has-public-ip.yaml`
> EC2 instances should not have a public IP address attached in order to block public access to the instances. To fix this, set your `associate_public_ip_address` to `"false"`.

---

**`aws-ec2-launch-configuration-ebs-block-device-unencrypted`** | WARNING | `community-rules\terraform\aws\security\aws-ec2-launch-configuration-ebs-block-device-unencrypted.yaml`
> The AWS launch configuration EBS block device is unencrypted. The block device could be read if compromised. Block devices should be encrypted to ensure sensitive data is held securely at rest.

---

**`aws-ec2-launch-configuration-root-block-device-unencrypted`** | WARNING | `community-rules\terraform\aws\security\aws-ec2-launch-configuration-root-block-device-unencrypted.yml`
> The AWS launch configuration root block device is unencrypted. The block device could be read if compromised. Block devices should be encrypted to ensure sensitive data is held securely at rest.

---

**`aws-ec2-launch-template-metadata-service-v1-enabled`** | WARNING | `community-rules\terraform\aws\security\aws-ec2-launch-template-metadata-service-v1-enabled.yaml`
> The EC2 launch template has Instance Metadata Service Version 1 (IMDSv1) enabled. IMDSv2 introduced session authentication tokens which improve security when talking to IMDS. You should either disable IMDS or require the use of IMDSv2.

---

**`aws-ec2-security-group-allows-public-ingress`** | WARNING | `community-rules\terraform\aws\security\aws-ec2-security-group-allows-public-ingress.yaml`
> The security group rule allows ingress from public internet. Opening up ports to the public internet is potentially dangerous. You should restrict access to IP addresses or ranges that explicitly require it where possible. Set a more restrictive CIDR range.

---

**`aws-ec2-security-group-rule-missing-description`** | INFO | `community-rules\terraform\aws\security\aws-ec2-security-group-rule-missing-description.yaml`
> The AWS security group rule is missing a description, or its description is empty or the default value.  Security groups rules should include a meaningful description in order to simplify auditing, debugging, and managing security groups.

---

**`aws-ecr-image-scanning-disabled`** | WARNING | `community-rules\terraform\aws\security\aws-ecr-image-scanning-disabled.yaml`
> The ECR repository has image scans disabled. Repository image scans should be enabled to ensure vulnerable software can be discovered and remediated as soon as possible.

---

**`aws-ecr-mutable-image-tags`** | WARNING | `community-rules\terraform\aws\security\aws-ecr-mutable-image-tags.yaml`
> The ECR repository allows tag mutability. Image tags could be overwritten with compromised images. ECR images should be set to IMMUTABLE to prevent code injection through image mutation. This can be done by setting `image_tag_mutability` to IMMUTABLE.

---

**`aws-ecr-repository-wildcard-principal`** | WARNING | `community-rules\terraform\aws\security\aws-ecr-repository-wildcard-principal.yaml`
> Detected wildcard access granted in your ECR repository policy principal. This grants access to all users, including anonymous users (public access). Instead, limit principals, actions and resources to what you need according to least privilege.

---

**`aws-efs-filesystem-encrypted-with-cmk`** | WARNING | `community-rules\terraform\aws\security\aws-efs-filesystem-encrypted-with-cmk.yaml`
> Ensure EFS filesystem is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.

---

**`aws-elasticache-automatic-backup-not-enabled`** | WARNING | `community-rules\terraform\aws\best-practice\aws-elasticache-automatic-backup-not-enabled.yaml`
> Ensure that Amazon ElastiCache clusters have automatic backup turned on. To fix this, set a `snapshot_retention_limit`.

---

**`aws-elasticsearch-insecure-tls-version`** | WARNING | `community-rules\terraform\aws\security\aws-elasticsearch-insecure-tls-version.yaml`
> Detected an AWS Elasticsearch domain using an insecure version of TLS. To fix this, set "tls_security_policy" equal to "Policy-Min-TLS-1-2-2019-07".

---

**`aws-elasticsearch-nodetonode-encryption-not-enabled`** | WARNING | `community-rules\terraform\aws\security\aws-elasticsearch-nodetonode-encryption.yaml`
> Ensure all Elasticsearch has node-to-node encryption enabled.	

---

**`aws-elb-access-logs-not-enabled`** | WARNING | `community-rules\terraform\aws\security\aws-elb-access-logs-not-enabled.yaml`
> ELB has no logging. Missing logs can cause missing important event information.

---

**`aws-emr-encrypted-with-cmk`** | WARNING | `community-rules\terraform\aws\security\aws-emr-encrypted-with-cmk.yaml`
> Ensure EMR is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.

---

**`aws-fsx-lustre-filesystem-encrypted-with-cmk`** | WARNING | `community-rules\terraform\aws\security\aws-fsx-lustre-files-ystem.yaml`
> Ensure FSX Lustre file system is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.

---

**`aws-fsx-lustre-filesystem-encrypted-with-cmk`** | WARNING | `community-rules\terraform\aws\security\aws-fsx-lustre-filesystem-encrypted-with-cmk.yaml`
> Ensure FSX Lustre file system is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.

---

**`aws-fsx-ontapfs-encrypted-with-cmk`** | WARNING | `community-rules\terraform\aws\security\aws-fsx-ontapfs-encrypted-with-cmk.yaml`
> Ensure FSX ONTAP file system is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.

---

**`aws-fsx-windows-encrypted-with-cmk`** | WARNING | `community-rules\terraform\aws\security\aws-fsx-windows-encrypted-with-cmk.yaml`
> Ensure FSX Windows file system is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.

---

**`aws-glacier-vault-any-principal`** | ERROR | `community-rules\terraform\aws\security\aws-glacier-vault-any-principal.yaml`
> Detected wildcard access granted to Glacier Vault. This means anyone within your AWS account ID can perform actions on Glacier resources. Instead, limit to a specific identity in your account, like this: `arn:aws:iam::<account_id>:<identity>`.

---

**`aws-iam-admin-policy`** | ERROR | `community-rules\terraform\aws\security\aws-iam-admin-policy.yaml`
> Detected admin access granted in your policy. This means anyone with this policy can perform administrative actions. Instead, limit actions and resources to what you need according to least privilege.

---

**`aws-iam-admin-policy-ssoadmin`** | ERROR | `community-rules\terraform\aws\security\aws-iam-admin-policy-ssoadmin.yaml`
> Detected admin access granted in your policy. This means anyone with this policy can perform administrative actions. Instead, limit actions and resources to what you need according to least privilege.

---

**`aws-imagebuilder-component-encrypted-with-cmk`** | WARNING | `community-rules\terraform\aws\security\aws-imagebuilder-component-encrypted-with-cmk.yaml`
> Ensure ImageBuilder component is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.

---

**`aws-insecure-api-gateway-tls-version`** | WARNING | `community-rules\terraform\aws\security\aws-insecure-api-gateway-tls-version.yaml`
> Detected AWS API Gateway to be using an insecure version of TLS. To fix this issue make sure to set "security_policy" equal to "TLS_1_2".

---

**`aws-insecure-cloudfront-distribution-tls-version`** | WARNING | `community-rules\terraform\aws\security\aws-cloudfront-insecure-tls.yaml`
> Detected an AWS CloudFront Distribution with an insecure TLS version. TLS versions less than 1.2 are considered insecure because they can be broken. To fix this, set your `minimum_protocol_version` to `"TLSv1.2_2018", "TLSv1.2_2019", "TLSv1.2_2021", "TLSv1.2_2025" or "TLSv1.3_2025"`.

---

**`aws-insecure-redshift-ssl-configuration`** | WARNING | `community-rules\terraform\aws\security\aws-insecure-redshift-ssl-configuration.yaml`
> Detected an AWS Redshift configuration with a SSL disabled. To fix this, set your `require_ssl` to `"true"`.

---

**`aws-kinesis-stream-encrypted-with-cmk`** | WARNING | `community-rules\terraform\aws\security\aws-kinesis-stream-encrypted-with-cmk.yaml`
> Ensure Kinesis stream is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.

---

**`aws-kinesis-stream-unencrypted`** | WARNING | `community-rules\terraform\aws\security\aws-kinesis-stream-unencrypted.yaml`
> The AWS Kinesis stream does not encrypt data at rest. The data could be read if the Kinesis stream storage layer is compromised. Enable Kinesis stream server-side encryption.

---

**`aws-kinesis-video-stream-encrypted-with-cmk`** | WARNING | `community-rules\terraform\aws\security\aws-kinesis-video-stream-encrypted-with-cmk.yaml`
> Ensure Kinesis video stream is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.

---

**`aws-kms-key-wildcard-principal`** | ERROR | `community-rules\terraform\aws\security\aws-kms-key-wildcard-principal.yaml`
> Detected wildcard access granted in your KMS key. This means anyone with this policy can perform administrative actions over the keys. Instead, limit principals, actions and resources to what you need according to least privilege.

---

**`aws-kms-no-rotation`** | WARNING | `community-rules\terraform\aws\security\aws-kms-no-rotation.yaml`
> The AWS KMS has no rotation. Missing rotation can cause leaked key to be used by attackers. To fix this, set a `enable_key_rotation`.

---

**`aws-lambda-environment-credentials`** | ERROR | `community-rules\terraform\aws\security\aws-lambda-environment-credentials.yaml`
> A hard-coded credential was detected. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`aws-lambda-environment-unencrypted`** | WARNING | `community-rules\terraform\aws\security\aws-lambda-environment-unencrypted.yaml`
> By default, the AWS Lambda Environment is encrypted using AWS-managed keys. However, for added security, it's recommended to configure your own AWS KMS encryption key to protect your environment variables in Lambda. You can either create a new aws_kms_key resource or use the ARN of an existing key in your AWS account to do so.

---

**`aws-lambda-permission-unrestricted-source-arn`** | ERROR | `community-rules\terraform\aws\security\aws-lambda-permission-unrestricted-source-arn.yaml`
> The AWS Lambda permission has an AWS service principal but does not specify a source ARN. If you grant permission to a service principal without specifying the source, other accounts could potentially configure resources in their account to invoke your Lambda function. Set the source_arn value to the ARN of the AWS resource that invokes the function, eg. an S3 bucket, CloudWatch Events Rule, API Gateway, or SNS topic.

---

**`aws-lambda-x-ray-tracing-not-active`** | INFO | `community-rules\terraform\aws\security\aws-lambda-x-ray-tracing-not-active.yaml`
> The AWS Lambda function does not have active X-Ray tracing enabled. X-Ray tracing enables end-to-end debugging and analysis of all function activity. This makes it easier to trace the flow of logs and identify bottlenecks, slow downs and timeouts.

---

**`aws-network-acl-allows-all-ports`** | WARNING | `community-rules\terraform\aws\security\aws-network-acl-allows-all-ports.yaml`
> Ingress and/or egress is allowed for all ports in the network ACL rule. Ensure access to specific required ports is allowed, and nothing else.

---

**`aws-network-acl-allows-public-ingress`** | WARNING | `community-rules\terraform\aws\security\aws-network-acl-allows-public-ingress.yaml`
> The network ACL rule allows ingress from public internet. Opening up ACLs to the public internet is potentially dangerous. You should restrict access to IP addresses or ranges that explicitly require it where possible. Set a more restrictive CIDR range.

---

**`aws-opensearchserverless-encrypted-with-cmk`** | WARNING | `community-rules\terraform\aws\security\aws-opensearchserverless-encrypted-with-cmk.yaml`
> Ensure opensearch serverless is encrypted at rest using AWS KMS (Key Management Service) CMK (Customer Managed Keys). CMKs give you control over the encryption key in terms of access and rotation.

---

**`aws-provider-static-credentials`** | WARNING | `community-rules\terraform\aws\security\aws-provider-static-credentials.yaml`
> A hard-coded credential was detected. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It is recommended to use environment variables to securely provide credentials or retrieve credentials from a secure vault or HSM (Hardware Security Module).

---

**`aws-provisioner-exec`** | WARNING | `community-rules\terraform\aws\security\aws-provisioner-exec.yaml`
> Provisioners are a tool of last resort and should be avoided where possible. Provisioner behavior cannot be mapped by Terraform as part of a plan, and execute arbitrary shell commands by design.

---

**`aws-qldb-inadequate-ledger-permissions-mode`** | WARNING | `community-rules\terraform\aws\best-practice\aws-qldb-inadequate-ledger-permissions-mode.yaml`
> The AWS QLDB ledger permissions are too permissive. Consider using "'STANDARD'" permissions mode if possible.

---

**`aws-rds-backup-no-retention`** | WARNING | `community-rules\terraform\aws\security\aws-rds-backup-no-retention.yaml`
> The AWS RDS has no retention. Missing retention can cause losing important event information. To fix this, set a `backup_retention_period`.

---

**`aws-rds-cluster-iam-authentication-not-enabled`** | WARNING | `community-rules\terraform\aws\best-practice\aws-rds-cluster-iam-authentication-not-enabled.yaml`
> The AWS RDS Cluster is not configured to use IAM authentication. Consider using IAM for authentication.

---

**`aws-rds-iam-authentication-not-enabled`** | WARNING | `community-rules\terraform\aws\best-practice\aws-rds-iam-authentication-not-enabled.yaml`
> The AWS RDS is not configured to use IAM authentication. Consider using IAM for authentication.

---

**`aws-rds-multiaz-not-enabled`** | WARNING | `community-rules\terraform\aws\best-practice\aws-rds-multiaz-not-enabled.yaml`
> The AWS RDS is not configured to use multi-az. Consider using it if possible.

---

**`aws-redshift-cluster-encrypted-with-cmk`** | WARNING | `community-rules\terraform\aws\security\aws-redshift-cluster-encrypted-with-cmk.yaml`
> Ensure AWS Redshift cluster is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.

---

**`aws-s3-bucket-object-encrypted-with-cmk`** | WARNING | `community-rules\terraform\aws\security\aws-s3-bucket-object-encrypted-with-cmk.yaml`
> Ensure S3 bucket object is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.

---

**`aws-s3-bucket-versioning-not-enabled`** | WARNING | `community-rules\terraform\aws\best-practice\aws-s3-bucket-versioning-not-enabled.yaml`
> Ensure that Amazon S3 bucket versioning is not enabled. Consider using versioning if you don't have alternative backup mechanism.

---

**`aws-s3-object-copy-encrypted-with-cmk`** | WARNING | `community-rules\terraform\aws\security\aws-s3-object-copy-encrypted-with-cmk.yaml`
> Ensure S3 object copies are encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.

---

**`aws-s3-object-lock-not-enabled`** | WARNING | `community-rules\terraform\aws\best-practice\aws-s3-object-lock-not-enabled.yaml`
> The AWS S3 object lock is not enabled. Consider using it if possible.

---

**`aws-sagemaker-domain-encrypted-with-cmk`** | WARNING | `community-rules\terraform\aws\security\aws-sagemaker-domain-encrypted-with-cmk.yaml`
> Ensure AWS Sagemaker domains are encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.

---

**`aws-secretsmanager-secret-unencrypted`** | WARNING | `community-rules\terraform\aws\security\aws-secretsmanager-secret-unencrypted.yaml`
> By default, AWS SecretManager secrets are encrypted using AWS-managed keys. However, for added security, it's recommended to configure your own AWS KMS encryption key to protect your secrets in the Secret Manager. You can either create a new aws_kms_key resource or use the ARN of an existing key in your AWS account to do so.

---

**`aws-sns-topic-unencrypted`** | WARNING | `community-rules\terraform\aws\security\aws-sns-topic-unencrypted.yaml`
> The AWS SNS topic is unencrypted. The SNS topic messages could be read if compromised. The AWS KMS encryption key protects topic contents. To create your own, create a aws_kms_key resource or use the ARN string of a key in your account.

---

**`aws-sqs-queue-policy-wildcard-action`** | INFO | `community-rules\terraform\aws\security\aws-sqs-queue-policy-wildcard-action.yaml`
> Wildcard used in your SQS queue policy action. SQS queue policies should always grant least privilege - that is, only grant the permissions required to perform a specific task. Implementing least privilege is important to reducing security risks and reducing the effect of errors or malicious intent.

---

**`aws-sqs-queue-policy-wildcard-principal`** | ERROR | `community-rules\terraform\aws\security\aws-sqs-queue-policy-wildcard-principal.yaml`
> Wildcard used in your SQS queue policy principal. This grants access to all users, including anonymous users (public access). Unless you explicitly require anyone on the internet to be able to read or write to your queue, limit principals, actions and resources to what you need according to least privilege.

---

**`aws-sqs-queue-unencrypted`** | WARNING | `community-rules\terraform\aws\security\aws-sqs-queue-unencrypted.yaml`
> The AWS SQS queue contents are unencrypted. The data could be read if compromised. Enable server-side encryption for your queue using SQS-managed encryption keys (SSE-SQS), or using your own AWS KMS key (SSE-KMS).

---

**`aws-ssm-document-logging-issues`** | WARNING | `community-rules\terraform\aws\security\aws-ssm-document-logging-issues.yaml`
> The AWS SSM logs are unencrypted or disabled. Please enable logs and use AWS KMS encryption key to protect SSM logs. To create your own, create a aws_kms_key resource or use the ARN string of a key in your account.

---

**`aws-subnet-has-public-ip-address`** | WARNING | `community-rules\terraform\aws\security\aws-subnet-has-public-ip-address.yaml`
> Resources in the AWS subnet are assigned a public IP address. Resources should not be exposed on the public internet, but should have access limited to consumers required for the function of your application. Set `map_public_ip_on_launch` to false so that resources are not publicly-accessible.

---

**`aws-timestream-database-encrypted-with-cmk`** | WARNING | `community-rules\terraform\aws\security\aws-timestream-database-encrypted-with-cmk.yaml`
> Ensure Timestream database is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.

---

**`aws-transfer-server-is-public`** | WARNING | `community-rules\terraform\aws\security\aws-transfer-server-is-public.yaml`
> Transfer Server endpoint type should not have public or null configured in order to block public access. To fix this, set your `endpoint_type` to `"VPC"`.

---

**`aws-workspaces-root-volume-unencrypted`** | WARNING | `community-rules\terraform\aws\security\aws-workspaces-root-volume-unencrypted.yaml`
> The AWS Workspace root volume is unencrypted. The AWS KMS encryption key protects root volume. To create your own, create a aws_kms_key resource or use the ARN string of a key in your account.

---

**`aws-workspaces-user-volume-unencrypted`** | WARNING | `community-rules\terraform\aws\security\aws-workspaces-user-volume-unencrypted.yaml`
> The AWS Workspace user volume is unencrypted. The AWS KMS encryption key protects user volume. To create your own, create a aws_kms_key resource or use the ARN string of a key in your account.

---

**`azure-ad-used-auth-service-fabric`** | WARNING | `community-rules\terraform\azure\best-practice\azure-ad-used-auth-service-fabric.yaml`
> Ensures that Active Directory is used for authentication for Service Fabric	

---

**`azure-aks-apiserver-auth-ip-ranges`** | WARNING | `community-rules\terraform\azure\security\aks\azure-aks-apiserver-auth-ip-ranges.yaml`
> Ensure AKS has an API Server Authorized IP Ranges enabled	

---

**`azure-aks-private-clusters-enabled`** | WARNING | `community-rules\terraform\azure\security\aks\azure-aks-private-clusters-enabled.yaml`
> Ensure that AKS enables private clusters	

---

**`azure-aks-uses-azure-policies-addon`** | INFO | `community-rules\terraform\azure\best-practice\azure-aks-uses-azure-policies-addon.yaml`
> Ensure that AKS uses Azure Policies Add-on

---

**`azure-aks-uses-disk-encryptionset`** | WARNING | `community-rules\terraform\azure\security\aks\azure-aks-uses-disk-encryptionset.yaml`
> Ensure that AKS uses disk encryption set

---

**`azure-apiservices-use-virtualnetwork`** | WARNING | `community-rules\terraform\azure\security\apiservice\azure-apiservices-use-virtualnetwork.yaml`
> Ensure that API management services use virtual networks

---

**`azure-appgateway-enables-waf`** | WARNING | `community-rules\terraform\azure\best-practice\azure-appgateway-enables-waf.yaml`
> Ensure that Application Gateway enables WAF

---

**`azure-appservice-auth`** | WARNING | `community-rules\terraform\azure\security\appservice\azure-appservice-auth.yaml`
> Ensure App Service Authentication is set on Azure App Service

---

**`azure-appservice-client-certificate`** | WARNING | `community-rules\terraform\azure\security\appservice\azure-appservice-client-certificate.yaml`
> Ensure the web app has Client Certificates

---

**`azure-appservice-detailed-errormessages-enabled`** | WARNING | `community-rules\terraform\azure\security\appservice\azure-appservice-detailed-errormessages-enabled.yaml`
> Ensure that App service enables detailed error messages

---

**`azure-appservice-disallowed-cors`** | WARNING | `community-rules\terraform\azure\security\appservice\azure-appservice-disallowed-cors.yaml`
> Ensure that CORS disallows every resource to access app services

---

**`azure-appservice-dotnet-framework-version`** | INFO | `community-rules\terraform\azure\best-practice\azure-appservice-dotnet-framework-version.yaml`
> Ensure that Net Framework version is the latest, if used as a part of the web app

---

**`azure-appservice-enabled-failed-request`** | WARNING | `community-rules\terraform\azure\security\appservice\azure-appservice-enabled-failed-request.yaml`
> Ensure that App service enables failed request tracing

---

**`azure-appservice-ftps-state`** | WARNING | `community-rules\terraform\azure\best-practice\azure-appservice-ftps-state.yaml`
> Ensure FTP deployments are disabled

---

**`azure-appservice-http-logging-enabled`** | WARNING | `community-rules\terraform\azure\security\appservice\azure-appservice-http-logging-enabled.yaml`
> Ensure that App service enables HTTP logging

---

**`azure-appservice-https-20-enabled`** | WARNING | `community-rules\terraform\azure\best-practice\azure-appservice-https-20-enabled.yaml`
> Ensure that HTTP Version is the latest if used to run the web app

---

**`azure-appservice-https-only`** | WARNING | `community-rules\terraform\azure\security\appservice\azure-appservice-https-only.yaml`
> Ensure web app redirects all HTTP traffic to HTTPS in Azure App Service Slot

---

**`azure-appservice-identity`** | WARNING | `community-rules\terraform\azure\security\appservice\azure-appservice-identity.yaml`
> Ensure App Service Authentication is set on Azure App Service

---

**`azure-appservice-identityprovider-enabled`** | WARNING | `community-rules\terraform\azure\security\appservice\azure-appservice-identityprovider-enabled.yaml`
> Ensure that Managed identity provider is enabled for app services

---

**`azure-appservice-java-version`** | INFO | `community-rules\terraform\azure\best-practice\azure-appservice-java-version.yaml`
> Ensure that Java version is the latest, if used to run the web app

---

**`azure-appservice-min-tls-version`** | WARNING | `community-rules\terraform\azure\security\appservice\azure-appservice-min-tls-version.yaml`
> Ensure web app is using the latest version of TLS encryption

---

**`azure-appservice-php-version`** | INFO | `community-rules\terraform\azure\best-practice\azure-appservice-php-version.yaml`
> Ensure that PHP version is the latest, if used to run the web app

---

**`azure-appservice-python-version`** | INFO | `community-rules\terraform\azure\best-practice\azure-appservice-python-version.yaml`
> Ensure that Python version is the latest, if used to run the web app

---

**`azure-appservice-used-azure-files`** | INFO | `community-rules\terraform\azure\best-practice\azure-appservice-used-azure-files.yaml`
> Ensure that app services use Azure Files

---

**`azure-automation-encrypted`** | WARNING | `community-rules\terraform\azure\security\azure-automation-encrypted.yaml`
> Ensure that Automation account variables are encrypted

---

**`azure-batchaccount-uses-keyvault-encrpytion`** | WARNING | `community-rules\terraform\azure\security\azure-batchaccount-uses-keyvault-encrpytion.yaml`
> Ensure that Azure Batch account uses key vault to encrypt data

---

**`azure-cognitiveservices-disables-public-network`** | WARNING | `community-rules\terraform\azure\security\azure-cognitiveservices-disables-public-network.yaml`
> Ensure that Cognitive Services accounts disable public network access

---

**`azure-containergroup-deployed-into-virtualnetwork`** | WARNING | `community-rules\terraform\azure\security\azure-containergroup-deployed-into-virtualnetwork.yaml`
> Ensure that Azure Container group is deployed into virtual network

---

**`azure-cosmosdb-accounts-restricted-access`** | WARNING | `community-rules\terraform\azure\security\azure-cosmosdb-accounts-restricted-access.yaml`
> Ensure Cosmos DB accounts have restricted access

---

**`azure-cosmosdb-disable-access-key-write`** | WARNING | `community-rules\terraform\azure\security\azure-cosmosdb-disable-access-key-write.yaml`
> Ensure that Cosmos DB accounts have access key write capability disabled

---

**`azure-cosmosdb-disables-public-network`** | WARNING | `community-rules\terraform\azure\security\azure-cosmosdb-disables-public-network.yaml`
> Ensure that Azure Cosmos DB disables public network access

---

**`azure-cosmosdb-have-cmk`** | WARNING | `community-rules\terraform\azure\security\azure-cosmosdb-have-cmk.yaml`
> Ensure that Cosmos DB accounts have customer-managed keys to encrypt data at rest

---

**`azure-customrole-definition-subscription-owner`** | WARNING | `community-rules\terraform\azure\security\azure-customrole-definition-subscription-owner.yaml`
> Ensure that no custom subscription owner roles are created

---

**`azure-dataexplorer-double-encryption-enabled`** | WARNING | `community-rules\terraform\azure\security\azure-dataexplorer-double-encryption-enabled.yaml`
> Ensure that Azure Data Explorer uses double encryption

---

**`azure-dataexplorer-uses-disk-encryption`** | WARNING | `community-rules\terraform\azure\security\azure-dataexplorer-uses-disk-encryption.yaml`
> Ensure that Azure Data Explorer uses disk encryption

---

**`azure-datafactory-no-public-network-access`** | WARNING | `community-rules\terraform\azure\security\azure-datafactory-no-public-network-access.yaml`
> Ensure that Azure Data factory public network access is disabled

---

**`azure-datafactory-uses-git-repository`** | WARNING | `community-rules\terraform\azure\security\azure-datafactory-uses-git-repository.yaml`
> Ensure that Azure Data Factory uses Git repository for source control

---

**`azure-datalake-store-encryption`** | WARNING | `community-rules\terraform\azure\security\azure-datalake-store-encryption.yaml`
> Ensure that Data Lake Store accounts enables encryption

---

**`azure-defenderon-appservices`** | WARNING | `community-rules\terraform\azure\best-practice\azure-defenderon-appservices.yaml`
> Ensure that Azure Defender is set to On for App Service

---

**`azure-defenderon-container-registry`** | WARNING | `community-rules\terraform\azure\best-practice\azure-defenderon-container-registry.yaml`
> Ensure that Azure Defender is set to On for Container

---

**`azure-defenderon-keyvaults`** | WARNING | `community-rules\terraform\azure\best-practice\azure-defenderon-keyvaults.yaml`
> Ensure that Azure Defender is set to On for Key Vault

---

**`azure-defenderon-kubernetes`** | WARNING | `community-rules\terraform\azure\best-practice\azure-defenderon-kubernetes.yaml`
> Ensure that Azure Defender is set to On for Kubernetes

---

**`azure-defenderon-servers`** | WARNING | `community-rules\terraform\azure\best-practice\azure-defenderon-servers.yaml`
> Ensure that Azure Defender is set to On for Servers

---

**`azure-defenderon-sqlservers`** | WARNING | `community-rules\terraform\azure\best-practice\azure-defenderon-sqlservers.yaml`
> Ensure that Azure Defender is set to On for SQL servers

---

**`azure-defenderon-sqlservers-vms`** | WARNING | `community-rules\terraform\azure\best-practice\azure-defenderon-sqlservers-vms.yaml`
> Ensure that Azure Defender is set to On for SQL servers on machines

---

**`azure-defenderon-storage`** | WARNING | `community-rules\terraform\azure\best-practice\azure-defenderon-storage.yaml`
> Ensure that Azure Defender is set to On for Storage

---

**`azure-eventgrid-domain-network-access`** | WARNING | `community-rules\terraform\azure\security\azure-eventgrid-domain-network-access.yaml`
> Ensure that Azure Event Grid Domain public network access is disabled

---

**`azure-frontdoor-enables-waf`** | WARNING | `community-rules\terraform\azure\best-practice\azure-frontdoor-enables-waf.yaml`
> Ensure that Azure Front Door enables WAF

---

**`azure-frontdoor-use-wafmode`** | WARNING | `community-rules\terraform\azure\best-practice\azure-frontdoor-use-wafmode.yaml`
> Ensure that Azure Front Door uses WAF and configured in “Detection” or “Prevention” modes

---

**`azure-functionapp-disallow-cors`** | WARNING | `community-rules\terraform\azure\security\azure-functionapp-disallow-cors.yaml`
> ensure that CORS disallows all resources to access Function app

---

**`azure-functionapp-http-version-latest`** | WARNING | `community-rules\terraform\azure\best-practice\azure-functionapp-http-version-latest.yaml`
> Ensure that HTTP Version is the latest if used to run the Function app

---

**`azure-functionapps-accessible-over-https`** | WARNING | `community-rules\terraform\azure\best-practice\azure-functionapps-accessible-over-https.yaml`
> Ensure that HTTP Version is the latest if used to run the Function app

---

**`azure-functionapps-enable-auth`** | WARNING | `community-rules\terraform\azure\security\azure-functionapps-enable-auth.yaml`
> Ensure that function apps enables Authentication

---

**`azure-instance-extensions`** | WARNING | `community-rules\terraform\azure\security\azure-instance-extensions.yaml`
> Ensure Virtual Machine Extensions are not Installed

---

**`azure-iot-no-public-network-access`** | WARNING | `community-rules\terraform\azure\security\azure-iot-no-public-network-access.yaml`
> Ensure that Azure IoT Hub disables public network access

---

**`azure-key-backedby-hsm`** | WARNING | `community-rules\terraform\azure\security\azure-key-backedby-hsm.yaml`
> Ensure that key vault key is backed by HSM

---

**`azure-key-no-expiration-date`** | WARNING | `community-rules\terraform\azure\security\azure-key-no-expiration-date.yaml`
> Ensure that the expiration date is set on all keys

---

**`azure-keyvault-enables-firewall-rules-settings`** | WARNING | `community-rules\terraform\azure\best-practice\azure-keyvault-enables-firewall-rules-settings.yaml`
> Ensure that key vault allows firewall rules settings

---

**`azure-keyvault-enables-purge-protection`** | WARNING | `community-rules\terraform\azure\best-practice\azure-keyvault-enables-purge-protection.yaml`
> Ensure that key vault enables purge protection

---

**`azure-keyvault-enables-soft-delete`** | WARNING | `community-rules\terraform\azure\best-practice\azure-keyvault-enables-soft-delete.yaml`
> Ensure that key vault enables soft delete

---

**`azure-keyvault-recovery-enabled`** | WARNING | `community-rules\terraform\azure\best-practice\azure-keyvault-recovery-enabled.yaml`
> Ensure the key vault is recoverable https://docs.bridgecrew.io/docs/ensure-the-key-vault-is-recoverable

---

**`azure-managed-disk-encryption`** | WARNING | `community-rules\terraform\azure\security\azure-managed-disk-encryption.yaml`
> Ensure Azure managed disk has encryption enabled

---

**`azure-managed-disk-encryption-set`** | WARNING | `community-rules\terraform\azure\security\azure-managed-disk-encryption-set.yaml`
> Ensure that managed disks use a specific set of disk encryption sets for the customer-managed key encryption

---

**`azure-mariadb-geo-backup-enabled`** | WARNING | `community-rules\terraform\azure\best-practice\azure-mariadb-geo-backup-enabled.yaml`
> Ensure that MariaDB server enables geo-redundant backups

---

**`azure-mariadb-public-access-disabled`** | WARNING | `community-rules\terraform\azure\security\azure-mariadb-public-access-disabled.yaml`
> Ensure public network access enabled is set to False for MariaDB servers

---

**`azure-mariadb-sslenforcement-enabled`** | WARNING | `community-rules\terraform\azure\best-practice\azure-mariadb-sslenforcement-enabled.yaml`
> Ensure Enforce SSL connection is set to Enabled for MariaDB servers

---

**`azure-monitor-log-profile-categories`** | WARNING | `community-rules\terraform\azure\best-practice\azure-monitor-log-profile-categories.yaml`
> Ensure audit profile captures all the activities

---

**`azure-monitor-log-profile-retention-days`** | WARNING | `community-rules\terraform\azure\best-practice\azure-monitor-log-profile-retention-days.yaml`
> Ensure that Activity Log Retention is set 365 days or greater

---

**`azure-monitor-log-profile-retention-days`** | WARNING | `community-rules\terraform\azure\security\azure-monitor-log-profile-retention-days.yaml`
> Ensure that Activity Log Retention is set 365 days or greater

---

**`azure-mssql-service-mintls-version`** | WARNING | `community-rules\terraform\azure\security\azure-mssql-service-mintls-version.yaml`
> Ensure MSSQL is using the latest version of TLS encryption

---

**`azure-mysql-encryption-enabled`** | WARNING | `community-rules\terraform\azure\security\azure-mysql-encryption-enabled.yaml`
> Ensure that MySQL server enables infrastructure encryption

---

**`azure-mysql-geo-backup-enabled`** | WARNING | `community-rules\terraform\azure\best-practice\azure-mysql-geo-backup-enabled.yaml`
> Ensure that MySQL server enables geo-redundant backups

---

**`azure-mysql-mintls-version`** | WARNING | `community-rules\terraform\azure\security\azure-mysql-mintls-version.yaml`
> Ensure MySQL is using the latest version of TLS encryption

---

**`azure-mysql-public-access-disabled`** | WARNING | `community-rules\terraform\azure\security\azure-mysql-public-access-disabled.yaml`
> Ensure public network access enabled is set to False for MySQL servers

---

**`azure-mysql-server-tlsenforcement-enabled`** | WARNING | `community-rules\terraform\azure\best-practice\azure-mysql-server-tlsenforcement-enabled.yaml`
> Ensure Enforce SSL connection is set to Enabled for MySQL servers

---

**`azure-mysql-threat-detection-enabled`** | WARNING | `community-rules\terraform\azure\best-practice\azure-mysql-threat-detection-enabled.yaml`
> Ensure that MySQL server enables Threat detection policy

---

**`azure-network-watcher-flowlog-period`** | WARNING | `community-rules\terraform\azure\security\azure-network-watcher-flowlog-period.yaml`
> Ensure that Network Security Group Flow Log retention period is 90 days or greater

---

**`azure-networkinterface-enable-ip-forwarding`** | WARNING | `community-rules\terraform\azure\best-practice\azure-networkinterface-enable-ip-forwarding.yaml`
> Ensure that Network Interfaces disable IP forwarding

---

**`azure-postgresql-encryption-enabled`** | WARNING | `community-rules\terraform\azure\security\azure-postgresql-encryption-enabled.yaml`
> Ensure that PostgreSQL server enables infrastructure encryption

---

**`azure-postgresql-flexi-server-geo-backup-enabled`** | WARNING | `community-rules\terraform\azure\best-practice\azure-postgresql-flexi-server-geo-backup-enabled.yaml`
> Ensure that PostgreSQL Flexible server enables geo-redundant backups

---

**`azure-postgresql-geo-backup-enabled`** | WARNING | `community-rules\terraform\azure\best-practice\azure-postgresql-geo-backup-enabled.yaml`
> Ensure that PostgreSQL server enables geo-redundant backups

---

**`azure-postgresql-min-tls-version`** | WARNING | `community-rules\terraform\azure\security\azure-postgresql-min-tls-version.yaml`
> Ensure PostgreSQL is using the latest version of TLS encryption

---

**`azure-postgresql-server-connection-throttling-enabled`** | WARNING | `community-rules\terraform\azure\best-practice\azure-postgresql-server-connection-throttling-enabled.yaml`
> Ensure server parameter connection_throttling is set to ON for PostgreSQL Database Server

---

**`azure-postgresql-server-log-checkpoint-enabled`** | WARNING | `community-rules\terraform\azure\best-practice\azure-postgresql-server-log-checkpoint-enabled.yaml`
> Ensure server parameter log_checkpoints is set to ON for PostgreSQL Database Server

---

**`azure-postgresql-server-log-connections-enabled`** | WARNING | `community-rules\terraform\azure\best-practice\azure-postgresql-server-log-connections-enabled.yaml`
> Ensure server parameter log_connections is set to ON for PostgreSQL Database Server

---

**`azure-postgresql-server-public-access-disabled`** | WARNING | `community-rules\terraform\azure\security\azure-postgresql-server-public-access-disabled.yaml`
> Ensure public network access enabled is set to False for PostgreSQL servers

---

**`azure-postgresql-ssl-enforcement-enabled`** | WARNING | `community-rules\terraform\azure\best-practice\azure-postgresql-ssl-enforcement-enabled.yaml`
> Ensure Enforce SSL connection is set to Enabled for PostgreSQL servers

---

**`azure-postgresql-threat-detection-enabled`** | WARNING | `community-rules\terraform\azure\best-practice\azure-postgresql-threat-detection-enabled.yaml`
> Ensure that PostgreSQL server enables Threat detection policy

---

**`azure-redis-cache-enable-non-ssl-port`** | WARNING | `community-rules\terraform\azure\security\azure-redis-cache-enable-non-ssl-port.yaml`
> Ensure that only SSL are enabled for Cache for Redis

---

**`azure-redis-cache-public-network-access-enabled`** | WARNING | `community-rules\terraform\azure\security\azure-redis-cache-public-network-access-enabled.yaml`
> Ensure that Azure Cache for Redis disables public network access

---

**`azure-remote-debugging-not-enabled`** | WARNING | `community-rules\terraform\azure\security\azure-remote-debugging-not-enabled.yaml`
> Ensure that remote debugging is not enabled for app services

---

**`azure-scale-set-password`** | WARNING | `community-rules\terraform\azure\security\azure-scale-set-password.yaml`
> Ensure that Virtual machine does not enable password authentication

---

**`azure-search-publicnetwork-access-disabled`** | WARNING | `community-rules\terraform\azure\security\azure-search-publicnetwork-access-disabled.yaml`
> Ensure that Azure Cognitive Search disables public network access

---

**`azure-secret-content-type`** | WARNING | `community-rules\terraform\azure\best-practice\azure-secret-content-type.yaml`
> Ensure that key vault secrets have “content_type” set

---

**`azure-secret-expiration-date`** | WARNING | `community-rules\terraform\azure\best-practice\azure-secret-expiration-date.yaml`
> Ensure that the expiration date is set on all secrets

---

**`azure-securitcenter-email-alert`** | WARNING | `community-rules\terraform\azure\best-practice\azure-securitcenter-email-alert.yaml`
> Ensure that Send email notification for high severity alerts is set to On

---

**`azure-securitycenter-contact-emails`** | WARNING | `community-rules\terraform\azure\best-practice\azure-securitycenter-contact-emails.yaml`
> Ensure that Security contact emails is set

---

**`azure-securitycenter-contact-phone`** | WARNING | `community-rules\terraform\azure\best-practice\azure-securitycenter-contact-phone.yaml`
> Ensure that Security contact Phone number is set

---

**`azure-securitycenter-email-alert-admins`** | WARNING | `community-rules\terraform\azure\best-practice\azure-securitycenter-email-alert-admins.yaml`
> Ensure that Send email notification for high severity alerts is set to On

---

**`azure-securitycenter-standard-pricing`** | WARNING | `community-rules\terraform\azure\best-practice\azure-securitycenter-standard-pricing.yaml`
> Ensure that standard pricing tier is selected

---

**`azure-service-fabric-cluster-protection-level`** | WARNING | `community-rules\terraform\azure\security\azure-service-fabric-cluster-protection-level.yaml`
> Ensure that Service Fabric use three levels of protection available

---

**`azure-sqlserver-email-alerts-enabled`** | WARNING | `community-rules\terraform\azure\best-practice\azure-sqlserver-email-alerts-enabled.yaml`
> Ensure that Send Alerts To is enabled for MSSQL servers

---

**`azure-sqlserver-email-alerts-toadmins-enabled`** | WARNING | `community-rules\terraform\azure\best-practice\azure-sqlserver-email-alerts-toadmins-enabled.yaml`
> Ensure that Email service and co-administrators is Enabled for MSSQL servers

---

**`azure-sqlserver-no-public-access`** | WARNING | `community-rules\terraform\azure\security\azure-sqlserver-no-public-access.yaml`
> Ensure no SQL Databases allow ingress from 0.0.0.0/0 (ANY IP)

---

**`azure-sqlserver-public-access-disabled`** | WARNING | `community-rules\terraform\azure\security\azure-sqlserver-public-access-disabled.yaml`
> Ensure that SQL server disables public network access

---

**`azure-sqlserver-threat-detection-types`** | WARNING | `community-rules\terraform\azure\best-practice\azure-sqlserver-threat-detection-types.yaml`
> Ensure that Threat Detection types is set to All

---

**`azure-storage-account-disable-public-access`** | WARNING | `community-rules\terraform\azure\security\azure-storage-account-disable-public-access.yaml`
> Ensure default network access rule for Storage Accounts is set to deny

---

**`azure-storage-account-enables-secure-transfer`** | WARNING | `community-rules\terraform\azure\best-practice\azure-storage-account-enables-secure-transfer.yaml`
> Ensure that storage account enables secure transfer

---

**`azure-storage-account-minimum-tlsversion`** | WARNING | `community-rules\terraform\azure\security\azure-storage-account-minimum-tlsversion.yaml`
> Ensure Storage Account is using the latest version of TLS encryption

---

**`azure-storage-blob-service-container-private-access`** | WARNING | `community-rules\terraform\azure\security\azure-storage-blob-service-container-private-access.yaml`
> Ensure that Public access level is set to Private for blob containers

---

**`azure-storage-sync-public-access-disabled`** | WARNING | `community-rules\terraform\azure\security\azure-storage-sync-public-access-disabled.yaml`
> Ensure that Azure File Sync disables public network access

---

**`azure-synapse-workscape-enables-managed-virtual-network`** | WARNING | `community-rules\terraform\azure\best-practice\azure-synapse-workscape-enables-managed-virtual-network.yaml`
> Ensure that Azure Synapse workspaces enables managed virtual networks

---

**`azure-vmencryption-at-host-enabled`** | WARNING | `community-rules\terraform\azure\security\azure-vmencryption-at-host-enabled.yaml`
> Ensure that Virtual machine scale sets have encryption at host enabled

---

**`azure-vmscale-sets-auto-os-image-patching-enabled`** | WARNING | `community-rules\terraform\azure\best-practice\azure-vmscale-sets-auto-os-image-patching-enabled.yaml`
> Ensure that automatic OS image patching is enabled for Virtual Machine Scale Sets

---

**`azure-waf-specificed-mode-app-gw`** | WARNING | `community-rules\terraform\azure\best-practice\azure-waf-specificed-mode-app-gw.yaml`
> Ensure that Application Gateway uses WAF in “Detection” or “Prevention” modes

---

**`ec2-imdsv1-optional`** | ERROR | `community-rules\terraform\lang\security\ec2-imdsv1-optional.yaml`
> AWS EC2 Instance allowing use of the IMDSv1

---

**`ecr-image-scan-on-push`** | WARNING | `community-rules\terraform\lang\security\ecr-image-scan-on-push.yaml`
> The ECR Repository isn't configured to scan images on push

---

**`eks-insufficient-control-plane-logging`** | WARNING | `community-rules\terraform\lang\security\eks-insufficient-control-plane-logging.yaml`
> Missing EKS control plane logging. It is recommended to enable at least Kubernetes API server component logs ("api") and audit logs ("audit") of the EKS control plane through the enabled_cluster_log_types attribute.

---

**`eks-public-endpoint-enabled`** | WARNING | `community-rules\terraform\lang\security\eks-public-endpoint-enabled.yaml`
> The vpc_config resource inside the eks cluster has not explicitly disabled public endpoint access

---

**`elastic-search-encryption-at-rest`** | WARNING | `community-rules\terraform\lang\security\elastic-search-encryption-at-rest.yaml`
> Encryption at rest is not enabled for the elastic search domain resource

---

**`functionapp-authentication-enabled`** | INFO | `community-rules\terraform\azure\security\functionapp\functionapp-authentication-enabled.yaml`
> Enabling authentication ensures that all communications in the application are authenticated. The `auth_settings` block needs to be filled out with the appropriate auth backend settings

---

**`functionapp-enable-http2`** | INFO | `community-rules\terraform\azure\security\functionapp\functionapp-enable-http2.yaml`
> Use the latest version of HTTP to ensure you are benefiting from security fixes. Add `http2_enabled = true` to your function app resource block

---

**`gcp-artifact-registry-encrypted-with-cmk`** | WARNING | `community-rules\terraform\gcp\security\gcp-artifact-registry-encrypted-with-cmk.yaml`
> Ensure Artifact Registry Repositories are encrypted with Customer Supplied Encryption Keys (CSEK)

---

**`gcp-artifact-registry-private-repo-iam-binding`** | WARNING | `community-rules\terraform\gcp\security\gcp-artifact-registry-private-repo-iam-binding.yaml`
> Ensure that Artifact Registry repositories are not anonymously or publicly accessible	

---

**`gcp-artifact-registry-private-repo-iam-member`** | WARNING | `community-rules\terraform\gcp\security\gcp-artifact-registry-private-repo-iam-member.yaml`
> Ensure that Artifact Registry repositories are not anonymously or publicly accessible	

---

**`gcp-bigquery-dataset-encrypted-with-cmk`** | WARNING | `community-rules\terraform\gcp\security\gcp-bigquery-dataset-encrypted-with-cmk.yaml`
> Ensure that BigQuery datasets are not anonymously or publicly accessible	

---

**`gcp-bigquery-private-table-iam-binding`** | WARNING | `community-rules\terraform\gcp\security\gcp-bigquery-private-table-iam-binding.yaml`
> Ensure that BigQuery Tables are not anonymously or publicly accessible		

---

**`gcp-bigquery-private-table-iam-member`** | WARNING | `community-rules\terraform\gcp\security\gcp-bigquery-private-table-iam-member.yaml`
> Ensure that BigQuery Tables are not anonymously or publicly accessible		

---

**`gcp-bigquery-table-encrypted-with-cmk`** | WARNING | `community-rules\terraform\gcp\security\gcp-bigquery-table-encrypted-with-cmk.yaml`
> Ensure Big Query Tables are encrypted with Customer Supplied Encryption Keys (CSEK)	

---

**`gcp-bigtable-instance-encrypted-with-cmk`** | WARNING | `community-rules\terraform\gcp\security\gcp-bigtable-instance-encrypted-with-cmk.yaml`
> Ensure Big Table Instances are encrypted with Customer Supplied Encryption Keys (CSEK)	

---

**`gcp-build-workers-private`** | WARNING | `community-rules\terraform\gcp\security\gcp-build-workers-private.yaml`
> Ensure Cloud build workers are private	

---

**`gcp-cloud-storage-logging`** | WARNING | `community-rules\terraform\gcp\security\gcp-cloud-storage-logging.yaml`
> Ensure bucket logs access.

---

**`gcp-compute-boot-disk-encryption`** | WARNING | `community-rules\terraform\gcp\security\gcp-compute-boot-disk-encryption.yaml`
> Ensure VM disks for critical VMs are encrypted with Customer Supplied Encryption Keys (CSEK)

---

**`gcp-compute-disk-encryption`** | WARNING | `community-rules\terraform\gcp\security\gcp-compute-disk-encryption.yaml`
> Ensure VM disks for critical VMs are encrypted with Customer Supplied Encryption Keys (CSEK)

---

**`gcp-compute-firewall-unrestricted-ingress-20`** | WARNING | `community-rules\terraform\gcp\security\gcp-compute-firewall-unrestricted-ingress-20.yaml`
> Ensure Google compute firewall ingress does not allow unrestricted FTP access

---

**`gcp-compute-firewall-unrestricted-ingress-21`** | WARNING | `community-rules\terraform\gcp\security\gcp-compute-firewall-unrestricted-ingress-21.yaml`
> Ensure Google compute firewall ingress does not allow unrestricted FTP access

---

**`gcp-compute-firewall-unrestricted-ingress-22`** | WARNING | `community-rules\terraform\gcp\security\gcp-compute-firewall-unrestricted-ingress-22.yaml`
> Ensure Google compute firewall ingress does not allow unrestricted SSH access

---

**`gcp-compute-firewall-unrestricted-ingress-3306`** | WARNING | `community-rules\terraform\gcp\security\gcp-compute-firewall-unrestricted-ingress-3306.yaml`
> Ensure Google compute firewall ingress does not allow unrestricted MySQL access

---

**`gcp-compute-firewall-unrestricted-ingress-3389`** | WARNING | `community-rules\terraform\gcp\security\gcp-compute-firewall-unrestricted-ingress-3389.yaml`
> Ensure Google compute firewall ingress does not allow unrestricted RDP access

---

**`gcp-compute-firewall-unrestricted-ingress-80`** | WARNING | `community-rules\terraform\gcp\security\gcp-compute-firewall-unrestricted-ingress-80.yaml`
> Ensure Google compute firewall ingress does not allow unrestricted HTTP access

---

**`gcp-compute-ip-forward`** | INFO | `community-rules\terraform\gcp\security\gcp-compute-ip-forward.yaml`
> Ensure that IP forwarding is not enabled on Instances. This lets the instance act as a traffic router and receive traffic not intended for it, which may route traffic through unintended passages.	

---

**`gcp-compute-os-login`** | WARNING | `community-rules\terraform\gcp\security\gcp-compute-os-login.yaml`
> Ensure that no instance in the project overrides the project setting for enabling OSLogin (OSLogin needs to be enabled in project metadata for all instances)	

---

**`gcp-compute-project-os-login`** | WARNING | `community-rules\terraform\gcp\security\gcp-compute-project-os-login.yaml`
> Ensure oslogin is enabled for a Project	

---

**`gcp-compute-public-ip`** | WARNING | `community-rules\terraform\gcp\security\gcp-compute-public-ip.yaml`
> Ensure that Compute instances do not have public IP addresses	

---

**`gcp-compute-serial-ports`** | WARNING | `community-rules\terraform\gcp\security\gcp-compute-serial-ports.yaml`
> Ensure 'Enable connecting to serial ports' is not enabled for VM Instance	

---

**`gcp-compute-shielded-vm`** | WARNING | `community-rules\terraform\gcp\best-practice\gcp-compute-shielded-vm.yaml`
> Ensure Compute instances are launched with Shielded VM enabled

---

**`gcp-compute-ssl-policy`** | WARNING | `community-rules\terraform\gcp\security\gcp-compute-ssl-policy.yaml`
> Ensure no HTTPS or SSL proxy load balancers permit SSL policies with weak cipher suites

---

**`gcp-compute-template-ip-forward`** | INFO | `community-rules\terraform\gcp\security\gcp-compute-template-ip-forward.yaml`
> Ensure that IP forwarding is not enabled on Instances. This lets the instance act as a traffic router and receive traffic not intended for it, which may route traffic through unintended passages.

---

**`gcp-compute-template-public-ip`** | WARNING | `community-rules\terraform\gcp\security\gcp-compute-template-public-ip.yaml`
> Ensure that Compute instances do not have public IP addresses	

---

**`gcp-compute-template-shielded-vm`** | WARNING | `community-rules\terraform\gcp\best-practice\gcp-compute-template-shielded-vm.yaml`
> Ensure Compute instances are launched with Shielded VM enabled

---

**`gcp-dataflow-job-encrypted-with-cmk`** | WARNING | `community-rules\terraform\gcp\security\gcp-dataflow-job-encrypted-with-cmk.yaml`
> Ensure data flow jobs are encrypted with Customer Supplied Encryption Keys (CSEK)

---

**`gcp-dataflow-private-job`** | WARNING | `community-rules\terraform\gcp\security\gcp-dataflow-private-job.yaml`
> Ensure Dataflow jobs are private

---

**`gcp-datafusion-private-instance`** | WARNING | `community-rules\terraform\gcp\security\gcp-datafusion-private-instance.yaml`
> Ensure Data fusion instances are private

---

**`gcp-datafusion-stack-driver-logging`** | WARNING | `community-rules\terraform\gcp\security\gcp-datafusion-stack-driver-logging.yaml`
> Ensure Datafusion has stack driver logging enabled.

---

**`gcp-datafusion-stack-driver-monitoring`** | WARNING | `community-rules\terraform\gcp\security\gcp-datafusion-stack-driver-monitoring.yaml`
> Ensure Datafusion has stack driver monitoring enabled.

---

**`gcp-dataproc-cluster-encrypted-with-cmk`** | WARNING | `community-rules\terraform\gcp\security\gcp-dataproc-cluster-encrypted-with-cmk.yaml`
> Ensure Dataproc cluster is encrypted with Customer Supplied Encryption Keys (CSEK)	

---

**`gcp-dataproc-cluster-public-ip`** | WARNING | `community-rules\terraform\gcp\security\gcp-dataproc-cluster-public-ip.yaml`
> Ensure Dataproc Clusters do not have public IPs

---

**`gcp-dataproc-private-cluster-iam-binding`** | WARNING | `community-rules\terraform\gcp\security\gcp-dataproc-private-cluster-iam-binding.yaml`
> Ensure that Dataproc clusters are not anonymously or publicly accessible

---

**`gcp-dataproc-private-cluster-iam-member`** | WARNING | `community-rules\terraform\gcp\security\gcp-dataproc-private-cluster-iam-member.yaml`
> Ensure that Dataproc clusters are not anonymously or publicly accessible

---

**`gcp-dns-key-specs-rsasha1`** | WARNING | `community-rules\terraform\gcp\security\gcp-dns-key-specs-rsasha1.yaml`
> Ensure that RSASHA1 is not used for the zone-signing and key-signing keys in Cloud DNS DNSSEC	

---

**`gcp-dnssec-enabled`** | WARNING | `community-rules\terraform\gcp\best-practice\gcp-dnssec-enabled.yaml`
> Ensure that RSASHA1 is not used for the zone-signing and key-signing keys in Cloud DNS DNSSEC	

---

**`gcp-folder-impersonation-roles-iam-binding`** | WARNING | `community-rules\terraform\gcp\security\gcp-folder-impersonation-roles-iam-binding.yaml`
> Ensure no roles that enable to impersonate and manage all service accounts are used at a folder level	

---

**`gcp-folder-impersonation-roles-iam-member`** | WARNING | `community-rules\terraform\gcp\security\gcp-folder-impersonation-roles-iam-member.yaml`
> Ensure no roles that enable to impersonate and manage all service accounts are used at a folder level	

---

**`gcp-folder-member-default-service-account-iam-binding`** | WARNING | `community-rules\terraform\gcp\security\gcp-folder-member-default-service-account-iam-binding.yaml`
> Ensure Default Service account is not used at a folder level

---

**`gcp-folder-member-default-service-account-iam-member`** | WARNING | `community-rules\terraform\gcp\security\gcp-folder-member-default-service-account-iam-member.yaml`
> Ensure Default Service account is not used at a folder level

---

**`gcp-gke-alias-ip-enabled`** | WARNING | `community-rules\terraform\gcp\best-practice\gcp-gke-alias-ip-enabled.yaml`
> Ensure Kubernetes Cluster is created with Alias IP ranges enabled

---

**`gcp-gke-basic-auth`** | WARNING | `community-rules\terraform\gcp\security\gcp-gke-basic-auth.yaml`
> Ensure GKE basic auth is disabled	

---

**`gcp-gke-binary-authorization`** | WARNING | `community-rules\terraform\gcp\best-practice\gcp-gke-binary-authorization.yaml`
> Ensure use of Binary Authorization	

---

**`gcp-gke-client-certificate-disabled`** | WARNING | `community-rules\terraform\gcp\security\gcp-gke-client-certificate-disabled.yaml`
> Ensure client certificate authentication to Kubernetes Engine Clusters is disabled

---

**`gcp-gke-cluster-logging`** | WARNING | `community-rules\terraform\gcp\security\gcp-gke-cluster-logging.yaml`
> Ensure logging is set to Enabled on Kubernetes Engine Clusters

---

**`gcp-gke-enable-shielded-nodes`** | WARNING | `community-rules\terraform\gcp\best-practice\gcp-gke-enable-shielded-nodes.yaml`
> Ensure Shielded GKE Nodes are Enabled

---

**`gcp-gke-enabled-vpc-flow-logs`** | WARNING | `community-rules\terraform\gcp\security\gcp-gke-enabled-vpc-flow-logs.yaml`
> Enable VPC Flow Logs and Intranode Visibility

---

**`gcp-gke-ensure-integrity-monitoring`** | WARNING | `community-rules\terraform\gcp\security\gcp-gke-ensure-integrity-monitoring.yaml`
> Ensure Integrity Monitoring for Shielded GKE Nodes is Enabled

---

**`gcp-gke-has-labels`** | WARNING | `community-rules\terraform\gcp\best-practice\gcp-gke-has-labels.yaml`
> Ensure Kubernetes Clusters are configured with Labels

---

**`gcp-gke-kubernetes-rbac-google-groups`** | WARNING | `community-rules\terraform\gcp\security\gcp-gke-kubernetes-rbac-google-groups.yaml`
> Manage Kubernetes RBAC users with Google Groups for GKE

---

**`gcp-gke-legacy-auth-enabled`** | WARNING | `community-rules\terraform\gcp\security\gcp-gke-legacy-auth-enabled.yaml`
> Ensure Legacy Authorization is set to Disabled on Kubernetes Engine Clusters

---

**`gcp-gke-legacy-instance-metadata-disabled`** | WARNING | `community-rules\terraform\gcp\security\gcp-gke-legacy-instance-metadata-disabled.yaml`
> Ensure legacy Compute Engine instance metadata APIs are Disabled

---

**`gcp-gke-master-authz-networks-enabled`** | WARNING | `community-rules\terraform\gcp\security\gcp-gke-master-authz-networks-enabled.yaml`
> Ensure master authorized networks is set to enabled in GKE clusters

---

**`gcp-gke-metadata-server-enabled`** | WARNING | `community-rules\terraform\gcp\best-practice\gcp-gke-metadata-server-enabled.yaml`
> Ensure the GKE Metadata Server is Enabled	

---

**`gcp-gke-monitoring-enabled`** | WARNING | `community-rules\terraform\gcp\security\gcp-gke-monitoring-enabled.yaml`
> Ensure monitoring is set to Enabled on Kubernetes Engine Clusters

---

**`gcp-gke-network-policy-enabled`** | WARNING | `community-rules\terraform\gcp\security\gcp-gke-network-policy-enabled.yaml`
> Ensure Network Policy is enabled on Kubernetes Engine Clusters

---

**`gcp-gke-nodepool-auto-repair-enabled`** | WARNING | `community-rules\terraform\gcp\best-practice\gcp-gke-nodepool-auto-repair-enabled.yaml`
> Ensure 'Automatic node repair' is enabled for Kubernetes Clusters

---

**`gcp-gke-nodepool-auto-upgrade-enabled`** | WARNING | `community-rules\terraform\gcp\best-practice\gcp-gke-nodepool-auto-upgrade-enabled.yaml`
> Ensure 'Automatic node upgrade' is enabled for Kubernetes Clusters

---

**`gcp-gke-nodepool-integrity-monitoring`** | WARNING | `community-rules\terraform\gcp\security\gcp-gke-nodepool-integrity-monitoring.yaml`
> Ensure Integrity Monitoring for Shielded GKE Nodes is Enabled

---

**`gcp-gke-nodepool-metadata-server-enabled`** | WARNING | `community-rules\terraform\gcp\best-practice\gcp-gke-nodepool-metadata-server-enabled.yaml`
> Ensure the GKE Metadata Server is Enabled	

---

**`gcp-gke-nodepool-secure-boot-for-shielded-nodes`** | WARNING | `community-rules\terraform\gcp\best-practice\gcp-gke-nodepool-secure-boot-for-shielded-nodes.yaml`
> Ensure Secure Boot for Shielded GKE Nodes is Enabled	

---

**`gcp-gke-pod-security-policy-enabled`** | WARNING | `community-rules\terraform\gcp\security\gcp-gke-pod-security-policy-enabled.yaml`
> Ensure PodSecurityPolicy controller is enabled on the Kubernetes Engine Clusters

---

**`gcp-gke-private-cluster-config`** | WARNING | `community-rules\terraform\gcp\security\gcp-gke-private-cluster-config.yaml`
> Ensure Kubernetes Cluster is created with Private cluster enabled

---

**`gcp-gke-public-control-plane`** | WARNING | `community-rules\terraform\gcp\security\gcp-gke-public-control-plane.yaml`
> Ensure GKE Control Plane is not public

---

**`gcp-gke-secure-boot-for-shielded-nodes`** | WARNING | `community-rules\terraform\gcp\security\gcp-gke-secure-boot-for-shielded-nodes.yaml`
> Ensure Secure Boot for Shielded GKE Nodes is Enabled	

---

**`gcp-gke-sql-backup-configuration-enabled`** | WARNING | `community-rules\terraform\gcp\best-practice\gcp-gke-sql-backup-configuration-enabled.yaml`
> Ensure all Cloud SQL database instance have backup configuration enabled

---

**`gcp-gke-use-cos-image`** | WARNING | `community-rules\terraform\gcp\best-practice\gcp-gke-use-cos-image.yaml`
> Ensure Container-Optimized OS (cos) is used for Kubernetes Engine Clusters Node image

---

**`gcp-insecure-load-balancer-tls-version`** | WARNING | `community-rules\terraform\gcp\security\gcp-insecure-load-balancer-tls-version.yaml`
> Detected GCP Load Balancer to be using an insecure version of TLS. To fix this set your "min_tls_version" to "TLS_1_2"

---

**`gcp-ipv6-private-google-enabled`** | WARNING | `community-rules\terraform\gcp\best-practice\gcp-ipv6-private-google-enabled.yaml`
> Ensure that Private google access is enabled for IPV6

---

**`gcp-kms-prevent-destroy`** | WARNING | `community-rules\terraform\gcp\security\gcp-kms-prevent-destroy.yaml`
> Ensure KMS keys are protected from deletion

---

**`gcp-memory-store-for-redis-auth-enabled`** | WARNING | `community-rules\terraform\gcp\security\gcp-memory-store-for-redis-auth-enabled.yaml`
> Ensure Memorystore for Redis has AUTH enabled

---

**`gcp-memory-store-for-redis-intransit-encryption`** | WARNING | `community-rules\terraform\gcp\security\gcp-memory-store-for-redis-intransit-encryption.yaml`
> Ensure Memorystore for Redis uses intransit encryption

---

**`gcp-mysql-local-in-file-off`** | WARNING | `community-rules\terraform\gcp\best-practice\gcp-mysql-local-in-file-off.yaml`
> Ensure MySQL database 'local_infile' flag is set to 'off'

---

**`gcp-org-impersonation-roles-iam-binding`** | WARNING | `community-rules\terraform\gcp\security\gcp-org-impersonation-roles-iam-binding.yaml`
> Ensure no roles that enable to impersonate and manage all service accounts are used at an organization level	

---

**`gcp-org-impersonation-roles-iam-member`** | WARNING | `community-rules\terraform\gcp\security\gcp-org-impersonation-roles-iam-member.yaml`
> Ensure no roles that enable to impersonate and manage all service accounts are used at an organization level	

---

**`gcp-org-member-default-service-account-iam-binding`** | WARNING | `community-rules\terraform\gcp\security\gcp-org-member-default-service-account-iam-binding.yaml`
> Ensure default service account is not used at an organization level

---

**`gcp-org-member-default-service-account-iam-member`** | WARNING | `community-rules\terraform\gcp\security\gcp-org-member-default-service-account-iam-member.yaml`
> Ensure default service account is not used at an organization level

---

**`gcp-postgresql-log-checkpoints`** | WARNING | `community-rules\terraform\gcp\best-practice\gcp-postgresql-log-checkpoints.yaml`
> Ensure PostgreSQL database 'log_checkpoints' flag is set to 'on'

---

**`gcp-postgresql-log-connection`** | WARNING | `community-rules\terraform\gcp\best-practice\gcp-postgresql-log-connection.yaml`
> Ensure PostgreSQL database 'log_connections' flag is set to 'on'

---

**`gcp-postgresql-log-disconnection`** | WARNING | `community-rules\terraform\gcp\best-practice\gcp-postgresql-log-disconnection.yaml`
> Ensure PostgreSQL database 'log_disconnections' flag is set to 'on'

---

**`gcp-postgresql-log-lock-waits`** | WARNING | `community-rules\terraform\gcp\best-practice\gcp-postgresql-log-lock-waits.yaml`
> Ensure PostgreSQL database 'log_lock_waits' flag is set to 'on'

---

**`gcp-postgresql-log-min-duration`** | WARNING | `community-rules\terraform\gcp\best-practice\gcp-postgresql-log-min-duration.yaml`
> Ensure PostgreSQL database 'log_min_duration_statement' flag is set to '-1'

---

**`gcp-postgresql-log-min-message`** | WARNING | `community-rules\terraform\gcp\best-practice\gcp-postgresql-log-min-message.yaml`
> Ensure PostgreSQL database 'log_min_messages' flag is set to a valid value

---

**`gcp-postgresql-log-temp`** | WARNING | `community-rules\terraform\gcp\best-practice\gcp-postgresql-log-temp.yaml`
> Ensure PostgreSQL database 'log_temp_files' flag is set to '0'

---

**`gcp-project-default-network`** | WARNING | `community-rules\terraform\gcp\security\gcp-project-default-network.yaml`
> Ensure that the default network does not exist in a project. Set auto_create_network to `false`.

---

**`gcp-project-member-default-service-account-iam-binding`** | WARNING | `community-rules\terraform\gcp\security\gcp-project-member-default-service-account-iam-binding.yaml`
> Ensure Default Service account is not used at a project level

---

**`gcp-project-member-default-service-account-iam-member`** | WARNING | `community-rules\terraform\gcp\security\gcp-project-member-default-service-account-iam-member.yaml`
> Ensure Default Service account is not used at a project level

---

**`gcp-project-service-account-user-iam-binding`** | WARNING | `community-rules\terraform\gcp\security\gcp-project-service-account-user-iam-binding.yaml`
> Ensure that IAM users are not assigned the Service Account User or Service Account Token Creator roles at project level

---

**`gcp-project-service-account-user-iam-member`** | WARNING | `community-rules\terraform\gcp\security\gcp-project-service-account-user-iam-member.yaml`
> Ensure that IAM users are not assigned the Service Account User or Service Account Token Creator roles at project level

---

**`gcp-pubsub-encrypted-with-cmk`** | WARNING | `community-rules\terraform\gcp\security\gcp-pubsub-encrypted-with-cmk.yaml`
> Ensure PubSub Topics are encrypted with Customer Supplied Encryption Keys (CSEK)

---

**`gcp-pubsub-private-topic-iam-binding`** | WARNING | `community-rules\terraform\gcp\security\gcp-pubsub-private-topic-iam-binding.yaml`
> Ensure that Pub/Sub Topics are not anonymously or publicly accessible

---

**`gcp-pubsub-private-topic-iam-member`** | WARNING | `community-rules\terraform\gcp\security\gcp-pubsub-private-topic-iam-member.yaml`
> Ensure that Pub/Sub Topics are not anonymously or publicly accessible

---

**`gcp-run-private-service-iam-binding`** | WARNING | `community-rules\terraform\gcp\security\gcp-run-private-service-iam-binding.yaml`
> Ensure that GCP Cloud Run services are not anonymously or publicly accessible

---

**`gcp-run-private-service-iam-member`** | WARNING | `community-rules\terraform\gcp\security\gcp-run-private-service-iam-member.yaml`
> Ensure that GCP Cloud Run services are not anonymously or publicly accessible

---

**`gcp-spanner-database-encrypted-with-cmk`** | WARNING | `community-rules\terraform\gcp\security\gcp-spanner-database-encrypted-with-cmk.yaml`
> Ensure Spanner Database is encrypted with Customer Supplied Encryption Keys (CSEK)

---

**`gcp-sql-database-require-ssl`** | WARNING | `community-rules\terraform\gcp\security\gcp-sql-database-require-ssl.yaml`
> Ensure all Cloud SQL database instance requires all incoming connections to use SSL

---

**`gcp-sql-database-ssl-insecure-value-postgres-mysql`** | WARNING | `community-rules\terraform\gcp\security\gcp-sql-database-ssl-insecure-value-postgres-mysql.yaml`
> Ensure all Cloud SQL database instance require incoming connections to use SSL. To enable this for PostgresSQL and MySQL, use `ssl_mode="TRUSTED_CLIENT_CERTIFICATE_REQUIRED"`.

---

**`gcp-sql-database-ssl-insecure-value-sqlserver`** | WARNING | `community-rules\terraform\gcp\security\gcp-sql-database-ssl-insecure-value-sqlserver.yaml`
> Ensure all Cloud SQL database instance require incoming connections to use SSL. For SQL Server, `ssl_mode="ENCRYPTED_ONLY"` is the most secure value that is supported.

---

**`gcp-sql-public-database`** | WARNING | `community-rules\terraform\gcp\security\gcp-sql-public-database.yaml`
> Ensure that Cloud SQL database Instances are not open to the world

---

**`gcp-sqlserver-no-public-ip`** | WARNING | `community-rules\terraform\gcp\security\gcp-sqlserver-no-public-ip.yaml`
> Ensure Cloud SQL database does not have public IP

---

**`gcp-storage-bucket-not-public-iam-binding`** | WARNING | `community-rules\terraform\gcp\security\gcp-storage-bucket-not-public-iam-binding.yaml`
> Ensure that Container Registry repositories are not anonymously or publicly accessible

---

**`gcp-storage-bucket-not-public-iam-member`** | WARNING | `community-rules\terraform\gcp\security\gcp-storage-bucket-not-public-iam-member.yaml`
> Ensure that Container Registry repositories are not anonymously or publicly accessible

---

**`gcp-storage-bucket-uniform-access`** | WARNING | `community-rules\terraform\gcp\security\gcp-storage-bucket-uniform-access.yaml`
> Ensure that Cloud Storage buckets have uniform bucket-level access enabled. Setting `uniform_bucket_level_access` to `true` ensures that access is managed uniformly at the bucket level, which improves security by disabling object-level ACLs.

---

**`gcp-storage-versioning-enabled`** | WARNING | `community-rules\terraform\gcp\best-practice\gcp-storage-versioning-enabled.yaml`
> Ensure Cloud storage has versioning enabled

---

**`gcp-sub-network-logging-enabled`** | WARNING | `community-rules\terraform\gcp\security\gcp-sub-network-logging-enabled.yaml`
> Ensure that VPC Flow Logs is enabled for every subnet in a VPC Network

---

**`gcp-sub-network-private-google-enabled`** | WARNING | `community-rules\terraform\gcp\security\gcp-sub-network-private-google-enabled.yaml`
> Ensure that private_ip_google_access is enabled for Subnet

---

**`gcp-vertexai-dataset-encrypted-with-cmk`** | WARNING | `community-rules\terraform\gcp\security\gcp-vertexai-dataset-encrypted-with-cmk.yaml`
> Ensure Vertex AI datasets uses a CMK (Customer Manager Key)

---

**`gcp-vertexai-metadata-store-encrypted-with-cmk`** | WARNING | `community-rules\terraform\gcp\security\gcp-vertexai-metadata-store-encrypted-with-cmk.yaml`
> Ensure Vertex AI Metadata Store uses a CMK (Customer Manager Key)

---

**`gcp-vertexai-private-instance`** | WARNING | `community-rules\terraform\gcp\security\gcp-vertexai-private-instance.yaml`
> Ensure Vertex AI instances are private

---

**`insecure-load-balancer-tls-version`** | WARNING | `community-rules\terraform\aws\security\insecure-load-balancer-tls-version.yaml`
> Detected an AWS load balancer with an insecure TLS version. TLS versions less than 1.2 are considered insecure because they can be broken. To fix this, set your `ssl_policy` to `"ELBSecurityPolicy-TLS13-1-2-Res-2021-06"`, or include a default action to redirect to HTTPS.

---

**`keyvault-content-type-for-secret`** | INFO | `community-rules\terraform\azure\security\keyvault\keyvault-content-type-for-secret.yaml`
> Key vault Secret should have a content type set

---

**`keyvault-ensure-key-expires`** | INFO | `community-rules\terraform\azure\security\keyvault\keyvault-ensure-key-expires.yaml`
> Ensure that the expiration date is set on all keys

---

**`keyvault-ensure-secret-expires`** | INFO | `community-rules\terraform\azure\security\keyvault\keyvault-ensure-secret-expires.yaml`
> Ensure that the expiration date is set on all secrets

---

**`keyvault-purge-enabled`** | WARNING | `community-rules\terraform\azure\security\keyvault\keyvault-purge-enabled.yaml`
> Key vault should have purge protection enabled

---

**`keyvault-specify-network-acl`** | ERROR | `community-rules\terraform\azure\security\keyvault\keyvault-specify-network-acl.yaml`
> Network ACLs allow you to reduce your exposure to risk by limiting what can access your key vault. The default action of the Network ACL should be set to deny for when IPs are not matched. Azure services can be allowed to bypass.

---

**`lambda-permission-logs-missing-arn-asterisk`** | WARNING | `community-rules\terraform\aws\correctness\lambda-permission-logs-missing-arn-asterisk.yaml`
> The `source_arn` field needs to end with an asterisk, like this: `<log-group-arn>:*` Without this, the `aws_lambda_permission` resource '$NAME' will not be created. Add the asterisk to the end of the arn. x $ARN

---

**`lambda-redundant-field-with-image`** | WARNING | `community-rules\terraform\aws\correctness\lambda-redundant-field-with-image.yaml`
> When using the AWS Lambda "Image" package_type, `runtime` and `handler` are not necessary for Lambda to understand how to run the code. These are built into the container image. Including `runtime` or `handler` with an "Image" `package_type` will result in an error on `terraform apply`. Remove these redundant fields.

---

**`missing-alb-drop-http-headers`** | WARNING | `community-rules\terraform\aws\best-practice\missing-alb-drop-http-headers.yaml`
> Detected a AWS load balancer that is not configured to drop invalid HTTP headers. Add `drop_invalid_header_fields = true` in your resource block.

---

**`missing-api-gateway-cache-cluster`** | WARNING | `community-rules\terraform\aws\best-practice\missing-api-gateway-cache-cluster.yaml`
> Found a AWS API Gateway Stage without cache cluster enabled. Enabling the cache cluster feature enhances responsiveness of your API. Add `cache_cluster_enabled = true` to your resource block.

---

**`missing-athena-workgroup-encryption`** | WARNING | `community-rules\terraform\aws\security\missing-athena-workgroup-encryption.yaml`
> The AWS Athena Workgroup is unencrypted. Encryption protects query results in your workgroup. To enable, add: `encryption_configuration { encryption_option = "SSE_KMS" kms_key_arn =  aws_kms_key.example.arn }` within `result_configuration { }` in your resource block,  where `encryption_option` is your chosen encryption method and `kms_key_arn`  is your KMS key ARN.

---

**`missing-autoscaling-group-tags`** | WARNING | `community-rules\terraform\aws\best-practice\missing-autoscaling-group-tags.yaml`
> There are missing tags for an AWS Auto Scaling group. Tags help track costs, allow for filtering for Auto Scaling groups, help with access control, and aid in organizing AWS resources. Add: `tag {
  key = "key"
  value = "value"
  propagate_at_launch = boolean
}` See https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/autoscaling_group for more details.

---

**`missing-aws-autoscaling-tags`** | WARNING | `community-rules\terraform\aws\best-practice\missing-aws-autoscaling-tags.yaml`
> The AWS Autoscaling Group is not tagged.

---

**`missing-aws-cross-zone-lb`** | WARNING | `community-rules\terraform\aws\best-practice\missing-aws-cross-zone-lb.yaml`
> The AWS cross zone load balancing is not enabled.

---

**`missing-aws-lb-deletion-protection`** | WARNING | `community-rules\terraform\aws\best-practice\missing-aws-lb-deletion-protection.yaml`
> The AWS LoadBalancer deletion protection is not enabled.

---

**`missing-aws-qldb-deletion-protection`** | WARNING | `community-rules\terraform\aws\best-practice\missing-aws-qldb-deletion-protection.yaml`
> The AWS QLDB deletion protection is not enabled.

---

**`missing-cloudwatch-log-group-kms-key`** | WARNING | `community-rules\terraform\aws\best-practice\missing-cloudwatch-log-group-kms-key.yaml`
> The AWS CloudWatch Log group is missing a KMS key. While Log group data is always encrypted, you can optionally use a KMS key instead. Add `kms_key_id = "yourKey"` to your resource block.

---

**`missing-cloudwatch-log-group-retention`** | WARNING | `community-rules\terraform\aws\best-practice\missing-cloudwatch-log-group-retention.yaml`
> The AWS CloudWatch Log group is missing log retention time. By default, logs are retained indefinitely. Add `retention_in_days = <integer>` to your resource block.

---

**`no-iam-admin-privileges`** | WARNING | `community-rules\terraform\lang\security\iam\no-iam-admin-privileges.yaml`
> IAM policies that allow full "*-*" admin privileges violates the principle of least privilege. This allows an attacker to take full control over all AWS account resources. Instead, give each user more fine-grained control with only the privileges they need. $TYPE

---

**`no-iam-creds-exposure`** | WARNING | `community-rules\terraform\lang\security\iam\no-iam-creds-exposure.yaml`
> Ensure IAM policies don't allow credentials exposure. Credentials exposure actions return credentials as part of the API response, and can possibly lead to leaking important credentials. Instead, use another action that doesn't return sensitive data as part of the API response.

---

**`no-iam-data-exfiltration`** | WARNING | `community-rules\terraform\lang\security\iam\no-iam-data-exfiltration.yaml`
> Ensure that IAM policies don't allow data exfiltration actions that are not resource-constrained. This can allow the user to read sensitive data they don't need to read. Instead, make sure that the user granted these privileges are given these permissions on specific resources.

---

**`no-iam-priv-esc-funcs`** | WARNING | `community-rules\terraform\lang\security\iam\no-iam-priv-esc-funcs.yaml`
> Ensure that actions that can result in privilege escalation are not used. These actions could potentially result in an attacker gaining full administrator access of an AWS account. Try not to use these actions.

---

**`no-iam-priv-esc-other-users`** | WARNING | `community-rules\terraform\lang\security\iam\no-iam-priv-esc-other-users.yaml`
> Ensure that IAM policies with permissions on other users don't allow for privilege escalation. This can lead to an attacker gaining full administrator access of AWS accounts. Instead, specify which user the permission should be used on or do not use the listed actions. $RESOURCE

---

**`no-iam-priv-esc-roles`** | WARNING | `community-rules\terraform\lang\security\iam\no-iam-priv-esc-roles.yaml`
> Ensure that groups of actions that include iam:PassRole and could result in privilege escalation are not all allowed for the same user. These actions could result in an attacker gaining full admin access of an AWS account. Try not to use these actions in conjuction.

---

**`no-iam-resource-exposure`** | WARNING | `community-rules\terraform\lang\security\iam\no-iam-resource-exposure.yaml`
> Ensure IAM policies don't allow resource exposure. These actions can expose AWS resources to the public. For example `ecr:SetRepositoryPolicy` could let an attacker retrieve container images. Instead, use another action that doesn't expose AWS resources.

---

**`no-iam-star-actions`** | WARNING | `community-rules\terraform\lang\security\iam\no-iam-star-actions.yaml`
> Ensure that no IAM policies allow "*" as a statement's actions. This allows all actions to be performed on the specified resources, and is a violation of the principle of least privilege. Instead, specify the actions that a certain user or policy is allowed to take.

---

**`rds-insecure-password-storage-in-source-code`** | WARNING | `community-rules\terraform\lang\security\rds-insecure-password-storage-in-source-code.yaml`
> RDS instance or cluster with hardcoded credentials in source code. It is recommended to pass the credentials at runtime, or generate random credentials using the random_password resource.

---

**`rds-public-access`** | WARNING | `community-rules\terraform\lang\security\rds-public-access.yaml`
> RDS instance accessible from the Internet detected.

---

**`reserved-aws-lambda-environment-variable`** | WARNING | `community-rules\terraform\aws\correctness\reserved-aws-lambda-environment-variable.yaml`
> `terraform apply` will fail because the environment variable "$VARIABLE" is a reserved by AWS. Use another name for "$VARIABLE".

---

**`s3-public-read-bucket`** | WARNING | `community-rules\terraform\lang\security\s3-public-read-bucket.yaml`
> S3 bucket with public read access detected.

---

**`s3-public-rw-bucket`** | ERROR | `community-rules\terraform\lang\security\s3-public-rw-bucket.yaml`
> S3 bucket with public read-write access detected.

---

**`s3-unencrypted-bucket`** | INFO | `community-rules\terraform\lang\security\s3-unencrypted-bucket.yaml`
> This rule has been deprecated, as all s3 buckets are encrypted by default with no way to disable it. See https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_server_side_encryption_configuration for more info.

---

**`storage-allow-microsoft-service-bypass`** | WARNING | `community-rules\terraform\azure\security\storage\storage-allow-microsoft-service-bypass.yaml`
> Some Microsoft services that interact with storage accounts operate from networks that can't be granted access through network rules. To help this type of service work as intended, allow the set of trusted Microsoft services to bypass the network rules

---

**`storage-default-action-deny`** | ERROR | `community-rules\terraform\azure\security\storage\storage-default-action-deny.yaml`
> Detected a Storage that was not configured to deny action by default. Add `default_action = "Deny"` in your resource block.

---

**`storage-enforce-https`** | WARNING | `community-rules\terraform\azure\security\storage\storage-enforce-https.yaml`
> Detected a Storage that was not configured to deny action by default. Add `enable_https_traffic_only = true` in your resource block.

---

**`storage-queue-services-logging`** | WARNING | `community-rules\terraform\azure\security\storage\storage-queue-services-logging.yaml`
> Storage Analytics logs detailed information about successful and failed requests to a storage service. This information can be used to monitor individual requests and to diagnose issues with a storage service. Requests are logged on a best-effort basis.

---

**`storage-use-secure-tls-policy`** | ERROR | `community-rules\terraform\azure\security\storage\storage-use-secure-tls-policy.yaml`
> Azure Storage currently supports three versions of the TLS protocol: 1.0, 1.1, and 1.2. Azure Storage uses TLS 1.2 on public HTTPS endpoints, but TLS 1.0 and TLS 1.1 are still supported for backward compatibility. This check will warn if the minimum TLS is not set to TLS1_2.

---

**`subscription-filter-missing-depends`** | WARNING | `community-rules\terraform\aws\correctness\subscription-filter-missing-depends.yaml`
> The `aws_cloudwatch_log_subscription_filter` resource "$NAME" needs a `depends_on` clause on the `aws_lambda_permission`, otherwise Terraform may try to create these out-of-order and fail.

---

**`unrestricted-github-oidc-policy`** | WARNING | `community-rules\terraform\aws\security\unrestricted-github-oidc-policy.yaml`
> `$POLICY` is missing a `condition` block which scopes users of this policy to specific GitHub repositories. Without this, `$POLICY` is open to all users on GitHub. Add a `condition` block on the variable `token.actions.githubusercontent.com:sub` which scopes it to prevent this.

---

**`wildcard-assume-role`** | ERROR | `community-rules\terraform\aws\security\wildcard-assume-role.yaml`
> Detected wildcard access granted to sts:AssumeRole. This means anyone with your AWS account ID and the name of the role can assume the role. Instead, limit to a specific identity in your account, like this: `arn:aws:iam::<account_id>:root`.

---

## Typescript (30 rules)

**`angular-bypasssecuritytrust`** | WARNING | `community-rules\typescript\angular\security\audit\angular-domsanitizer.yaml`
> Detected the use of `$TRUST`. This can introduce a Cross-Site-Scripting (XSS) vulnerability if this comes from user-provided input. If you have to use `$TRUST`, ensure it does not come from user-input or use the appropriate prevention mechanism e.g. input validation or sanitization depending on the context.

---

**`aws-cdk-bucket-enforcessl`** | ERROR | `community-rules\typescript\aws-cdk\security\audit\awscdk-bucket-enforcessl.yml`
> Bucket $X is not set to enforce encryption-in-transit, if not explictly setting this on the bucket policy - the property "enforceSSL" should be set to true

---

**`awscdk-bucket-encryption`** | ERROR | `community-rules\typescript\aws-cdk\security\audit\awscdk-bucket-encryption.yml`
> Add "encryption: $Y.BucketEncryption.KMS_MANAGED" or "encryption: $Y.BucketEncryption.S3_MANAGED" to the bucket props for Bucket construct $X

---

**`awscdk-bucket-grantpublicaccessmethod`** | WARNING | `community-rules\typescript\aws-cdk\security\awscdk-bucket-grantpublicaccessmethod.yml`
> Using the GrantPublicAccess method on bucket contruct $X will make the objects in the bucket world accessible. Verify if this is intentional.

---

**`awscdk-codebuild-project-public`** | WARNING | `community-rules\typescript\aws-cdk\security\awscdk-codebuild-project-public.yml`
> CodeBuild Project $X is set to have a public URL. This will make the build results, logs, artifacts publically accessible, including builds prior to the project being public. Ensure this is acceptable for the project.

---

**`awscdk-sqs-unencryptedqueue`** | WARNING | `community-rules\typescript\aws-cdk\security\audit\awscdk-sqs-unencryptedqueue.yml`
> Queue $X is missing encryption at rest. Add "encryption: $Y.QueueEncryption.KMS" or "encryption: $Y.QueueEncryption.KMS_MANAGED" to the queue props to enable encryption at rest for the queue.

---

**`cors-regex-wildcard`** | WARNING | `community-rules\typescript\lang\security\audit\cors-regex-wildcard.yaml`
> Unescaped '.' character in CORS domain regex $CORS: $PATTERN

---

**`define-styled-components-on-module-level`** | WARNING | `community-rules\typescript\react\best-practice\define-styled-components-on-module-level.yaml`
> By declaring a styled component inside the render method of a react component, you are dynamically creating a new component on every render. This means that React will have to discard and re-calculate that part of the DOM subtree on each subsequent render, instead of just calculating the difference of what changed between them. This leads to performance bottlenecks and unpredictable behavior.

---

**`i18next-key-format`** | WARNING | `community-rules\typescript\react\portability\i18next\i18next-key-format.yaml`
> Translation key '$KEY' should match format 'MODULE.FEATURE.*'

---

**`jsx-label-not-i18n`** | WARNING | `community-rules\typescript\react\portability\i18next\jsx-label-not-i18n.yaml`
> JSX Component label not internationalized: '$MESSAGE'

---

**`jsx-not-internationalized`** | WARNING | `community-rules\typescript\react\portability\i18next\jsx-not-internationalized.yaml`
> JSX element not internationalized: '$MESSAGE'.  You should support different languages in your website or app with internationalization. Instead, use packages such as `i18next` in order to internationalize your elements.

---

**`moment-deprecated`** | INFO | `community-rules\typescript\lang\best-practice\moment-deprecated.yaml`
> Moment is a legacy project in maintenance mode. Consider using libraries that are actively supported, e.g. `dayjs`.

---

**`mui-snackbar-message`** | WARNING | `community-rules\typescript\react\portability\i18next\mui-snackbar-message.yaml`
> React MUI enqueueSnackbar() title is not internationalized: '$MESSAGE'

---

**`nestjs-header-cors-any`** | WARNING | `community-rules\typescript\nestjs\security\audit\nestjs-header-cors-any.yaml`
> Access-Control-Allow-Origin response header is set to "*". This will disable CORS Same Origin Policy restrictions.

---

**`nestjs-header-xss-disabled`** | WARNING | `community-rules\typescript\nestjs\security\audit\nestjs-header-xss-disabled.yaml`
> X-XSS-Protection header is set to 0. This will disable the browser's XSS Filter.

---

**`nestjs-open-redirect`** | WARNING | `community-rules\typescript\nestjs\security\audit\nestjs-open-redirect.yaml`
> Untrusted user input in {url: ...} can result in Open Redirect vulnerability.

---

**`react-dangerouslysetinnerhtml`** | WARNING | `community-rules\typescript\react\security\audit\react-dangerouslysetinnerhtml.yaml`
> Detection of dangerouslySetInnerHTML from non-constant definition. This can inadvertently expose users to cross-site scripting (XSS) attacks if this comes from user-provided input. If you have to use dangerouslySetInnerHTML, consider using a sanitization library such as DOMPurify to sanitize your HTML.

---

**`react-find-dom`** | WARNING | `community-rules\typescript\react\best-practice\react-find-dom.yaml`
> findDOMNode is an escape hatch used to access the underlying DOM node. In most cases, use of this escape hatch is discouraged because it pierces the component abstraction.

---

**`react-href-var`** | WARNING | `community-rules\typescript\react\security\audit\react-href-var.yaml`
> Detected a variable used in an anchor tag with the 'href' attribute. A malicious actor may be able to input the 'javascript:' URI, which could cause cross-site scripting (XSS). It is recommended to disallow 'javascript:' URIs within your application.

---

**`react-insecure-request`** | ERROR | `community-rules\typescript\react\security\react-insecure-request.yaml`
> Unencrypted request over HTTP detected.

---

**`react-jwt-decoded-property`** | INFO | `community-rules\typescript\react\security\audit\react-jwt-decoded-property.yaml`
> Property decoded from JWT token without verifying and cannot be trustworthy.

---

**`react-jwt-in-localstorage`** | INFO | `community-rules\typescript\react\security\audit\react-jwt-in-localstorage.yaml`
> Storing JWT tokens in localStorage known to be a bad practice, consider moving your tokens from localStorage to a HTTP cookie.

---

**`react-legacy-component`** | WARNING | `community-rules\typescript\react\best-practice\react-legacy-component.yaml`
> Legacy component lifecycle was detected - $METHOD.

---

**`react-markdown-insecure-html`** | WARNING | `community-rules\typescript\react\security\react-markdown-insecure-html.yaml`
> Overwriting `transformLinkUri` or `transformImageUri` to something insecure, or turning `allowDangerousHtml` on, or turning `escapeHtml` off, will open the code up to XSS vectors.

---

**`react-props-in-state`** | WARNING | `community-rules\typescript\react\best-practice\react-props-in-state.yaml`
> Copying a prop into state in React -- this is bad practice as all updates to it are ignored. Instead, read props directly in your component and avoid copying props into state.

---

**`react-props-spreading`** | WARNING | `community-rules\typescript\react\best-practice\react-props-spreading.yaml`
> It's best practice to explicitly pass props to an HTML component rather than use the spread operator. The spread operator risks passing invalid HTML props to an HTML element, which can cause console warnings or worse, give malicious actors a way to inject unexpected attributes.

---

**`react-unsanitized-method`** | WARNING | `community-rules\typescript\react\security\audit\react-unsanitized-method.yaml`
> Detection of $HTML from non-constant definition. This can inadvertently expose users to cross-site scripting (XSS) attacks if this comes from user-provided input. If you have to use $HTML, consider using a sanitization library such as DOMPurify to sanitize your HTML.

---

**`react-unsanitized-property`** | WARNING | `community-rules\typescript\react\security\audit\react-unsanitized-property.yaml`
> Detection of $HTML from non-constant definition. This can inadvertently expose users to cross-site scripting (XSS) attacks if this comes from user-provided input. If you have to use $HTML, consider using a sanitization library such as DOMPurify to sanitize your HTML.

---

**`useless-ternary`** | ERROR | `community-rules\typescript\lang\correctness\useless-ternary.yaml`
> It looks like no matter how $CONDITION is evaluated, this expression returns $ANS. This is probably a copy-paste error.

---

**`useselect-label-not-i18n`** | WARNING | `community-rules\typescript\react\portability\i18next\useselect-label-not-i18n.yaml`
> React useSelect() label is not internationalized - '$LABEL'. You should support different langauges in your website or app with internationalization. Instead, use packages such as `i18next` to internationalize your elements.

---

## Yaml (174 rules)

**`allow-privilege-escalation`** | WARNING | `community-rules\yaml\kubernetes\security\allow-privilege-escalation.yaml`
> In Kubernetes, each pod runs in its own isolated environment with its own set of security policies. However, certain container images may contain `setuid` or `setgid` binaries that could allow an attacker to perform privilege escalation and gain access to sensitive resources. To mitigate this risk, it's recommended to add a `securityContext` to the container in the pod, with the parameter `allowPrivilegeEscalation` set to `false`. This will prevent the container from running any privileged processes and limit the impact of any potential attacks. By adding the `allowPrivilegeEscalation` parameter to your the `securityContext`, you can help to ensure that your containerized applications are more secure and less vulnerable to privilege escalation attacks.

---

**`allow-privilege-escalation-no-securitycontext`** | WARNING | `community-rules\yaml\kubernetes\security\allow-privilege-escalation-no-securitycontext.yaml`
> In Kubernetes, each pod runs in its own isolated environment with its own set of security policies. However, certain container images may contain `setuid` or `setgid` binaries that could allow an attacker to perform privilege escalation and gain access to sensitive resources. To mitigate this risk, it's recommended to add a `securityContext` to the container in the pod, with the parameter `allowPrivilegeEscalation` set to `false`. This will prevent the container from running any privileged processes and limit the impact of any potential attacks. By adding a `securityContext` to your Kubernetes pod, you can help to ensure that your containerized applications are more secure and less vulnerable to privilege escalation attacks.

---

**`allow-privilege-escalation-true`** | WARNING | `community-rules\yaml\kubernetes\security\allow-privilege-escalation-true.yaml`
> In Kubernetes, each pod runs in its own isolated environment with its own  set of security policies. However, certain container images may contain  `setuid` or `setgid` binaries that could allow an attacker to perform  privilege escalation and gain access to sensitive resources. To mitigate  this risk, it's recommended to add a `securityContext` to the container in  the pod, with the parameter `allowPrivilegeEscalation` set to `false`.  This will prevent the container from running any privileged processes and  limit the impact of any potential attacks.  In the container `$CONTAINER` this parameter is set to `true` which makes this container much more vulnerable to privelege escalation attacks.

---

**`allowed-unsecure-commands`** | WARNING | `community-rules\yaml\github-actions\security\allowed-unsecure-commands.yaml`
> The environment variable `ACTIONS_ALLOW_UNSECURE_COMMANDS` grants this workflow permissions to use the `set-env` and `add-path` commands. There is a vulnerability in these commands that could result in environment variables being modified by an attacker. Depending on the use of the environment variable, this could enable an attacker to, at worst, modify the system path to run a different command than intended, resulting in arbitrary code execution. This could result in stolen code or secrets. Don't use `ACTIONS_ALLOW_UNSECURE_COMMANDS`. Instead, use Environment Files. See https://github.com/actions/toolkit/blob/main/docs/commands.md#environment-files for more information.

---

**`api-key-in-query-parameter`** | WARNING | `community-rules\yaml\openapi\security\api-key-in-query-parameter.yaml`
> The $SECURITY_SCHEME security scheme passes an API key in a query parameter. API keys should not be passed as query parameters in security schemes.  Pass the API key in the header or body. If using a query parameter is necessary, ensure that the API key is tightly scoped and short lived.

---

**`argo-workflow-parameter-command-injection`** | ERROR | `community-rules\yaml\argo\security\argo-workflow-parameter-command-injection.yaml`
> Using input or workflow parameters in here-scripts can lead to command injection or code injection. Convert the parameters to env variables instead.

---

**`bad-1`** | WARNING | `community-rules\yaml\semgrep\multi-line-message.test.yaml`
> a
b


---

**`bad-2`** | WARNING | `community-rules\yaml\semgrep\multi-line-message.test.yaml`
> a
b

---

**`changes-with-when-never`** | WARNING | `community-rules\yaml\gitlab\correctness\changes-with-when-never.yaml`
> This Gitlab CI YAML will never run on default branches due to a `changes` rule with `when:never`. To fix this, make sure the triggering event is a push event. You can do this with `if: '$CI_PIPELINE_SOURCE == "push"'`. See https://docs.gitlab.com/ee/ci/yaml/index.html#ruleschanges

---

**`curl-eval`** | ERROR | `community-rules\yaml\github-actions\security\curl-eval.yaml`
> Data is being eval'd from a `curl` command. An attacker with control of the server in the `curl` command could inject malicious code into the `eval`, resulting in a system comrpomise. Avoid eval'ing untrusted data if you can. If you must do this, consider checking the SHA sum of the content returned by the server to verify its integrity.

---

**`detect-shai-hulud-backdoor`** | ERROR | `community-rules\yaml\github-actions\security\detect-shai-hulud-backdoor.yaml`
> The Shai-hulud backdoor creates a purposefully vulnerable github action with the name `discussion.yaml`.

---

**`duplicate-id`** | ERROR | `community-rules\yaml\semgrep\duplicate-id.yaml`
> The 'id' field $X was used multiple times. The 'id' field needs to be unique.

---

**`duplicate-pattern`** | ERROR | `community-rules\yaml\semgrep\duplicate-pattern.yaml`
> Two identical pattern clauses were detected. This will cause Semgrep to run the same pattern twice. Remove one of the duplicate pattern clauses.

---

**`empty-message`** | WARNING | `community-rules\yaml\semgrep\empty-message.yaml`
> This rule has an empty message field. Consider adding a message field that communicates why this rule is an issue and how to fix it. This will increase the chance that the finding gets addressed.

---

**`event-binding-payload-with-hyphen`** | WARNING | `community-rules\yaml\argo\correctness\event-binding-payload-with-hyphen.yaml`
> The parameter `$VALUE` to this WorkflowEventBinding includes hyphens, which will, very confusingly, throw an error when Argo Workflows tries to invoke the workflow. Set the payload value to use underscores instead.

---

**`example-1`** | ERROR | `community-rules\yaml\semgrep\metadata-cwe.test.yaml`
> Example

---

**`example-1`** | ERROR | `community-rules\yaml\semgrep\metadata-owasp.test.yaml`
> Example

---

**`example-1`** | ERROR | `community-rules\yaml\semgrep\metadata-references.test.yaml`
> Example

---

**`example-2`** | ERROR | `community-rules\yaml\semgrep\metadata-cwe.test.yaml`
> Example

---

**`example-2`** | ERROR | `community-rules\yaml\semgrep\metadata-owasp.test.yaml`
> Example

---

**`example-2`** | ERROR | `community-rules\yaml\semgrep\metadata-references.test.yaml`
> Example

---

**`example-3`** | ERROR | `community-rules\yaml\semgrep\metadata-cwe.test.yaml`
> Example

---

**`example-3`** | ERROR | `community-rules\yaml\semgrep\metadata-owasp.test.yaml`
> Example

---

**`example-4`** | ERROR | `community-rules\yaml\semgrep\metadata-cwe.test.yaml`
> Example

---

**`example-4`** | ERROR | `community-rules\yaml\semgrep\metadata-cwe.test.yaml`
> Example

---

**`example-4`** | ERROR | `community-rules\yaml\semgrep\metadata-owasp.test.yaml`
> Example

---

**`example-5`** | ERROR | `community-rules\yaml\semgrep\metadata-owasp.test.yaml`
> Example

---

**`example-6`** | ERROR | `community-rules\yaml\semgrep\metadata-owasp.test.yaml`
> Example

---

**`example-allowed`** | ERROR | `community-rules\yaml\semgrep\metadata-cwe-prohibited-or-discouraged.test.yaml`
> Example

---

**`example-prohibited`** | ERROR | `community-rules\yaml\semgrep\metadata-cwe-prohibited-or-discouraged.test.yaml`
> Example

---

**`exposing-docker-socket-hostpath`** | WARNING | `community-rules\yaml\kubernetes\security\exposing-docker-socket-hostpath.yaml`
> Exposing host's Docker socket to containers via a volume. The owner of this socket is root. Giving someone access to it is equivalent to giving unrestricted root access to your host. Remove 'docker.sock' from hostpath to prevent this.

---

**`exposing-docker-socket-volume`** | WARNING | `community-rules\yaml\docker-compose\security\exposing-docker-socket-volume.yaml`
> Exposing host's Docker socket to containers via a volume. The owner of this socket is root. Giving someone access to it is equivalent to giving unrestricted root access to your host. Remove 'docker.sock' from volumes to prevent this.

---

**`express-sandbox-code-injection`** | ERROR | `community-rules\yaml\semgrep\slow-pattern-general-function.test.yaml`
> Make sure that unverified user data can not reach `sandbox`.

---

**`express-sandbox-code-injection`** | ERROR | `community-rules\yaml\semgrep\slow-pattern-general-property.test.yaml`
> Make sure that unverified user data can not reach `sandbox`.

---

**`flask-debugging-enabled`** | WARNING | `community-rules\yaml\kubernetes\security\env\flask-debugging-enabled.yaml`
> Do not set FLASK_ENV to "development" since that sets `debug=True` in Flask. Use "dev" or a similar term instead.

---

**`github-script-injection`** | ERROR | `community-rules\yaml\github-actions\security\github-script-injection.yaml`
> Using variable interpolation `${{...}}` with `github` context data in a `actions/github-script`'s `script:` step could allow an attacker to inject their own code into the runner. This would allow them to steal secrets and code. `github` context data can have arbitrary user input and should be treated as untrusted. Instead, use an intermediate environment variable with `env:` to store the data and use the environment variable in the `run:` script. Be sure to use double-quotes the environment variable, like this: "$ENVVAR".

---

**`good-1`** | WARNING | `community-rules\yaml\semgrep\multi-line-message.test.yaml`
> a b

---

**`half-written-crypto-example`** | WARNING | `community-rules\yaml\semgrep\message-whitespace.test.yaml`
> # ruleid: message-whitespace-check Semgrep found  a match # ruleid: message-whitespace-check I like    big space

---

**`half-written-crypto-example`** | WARNING | `community-rules\yaml\semgrep\rule-missing-deconstructed-value.test.yaml`
> A lav crypto hun

---

**`hostipc-pod`** | WARNING | `community-rules\yaml\kubernetes\security\hostipc-pod.yaml`
> Pod is sharing the host IPC namespace. This allows container processes to communicate with processes on the host which reduces isolation and bypasses container protection models. Remove the 'hostIPC' key to disable this functionality.

---

**`hostnetwork-pod`** | WARNING | `community-rules\yaml\kubernetes\security\hostnetwork-pod.yaml`
> Pod may use the node network namespace. This gives the pod access to the loopback device, services listening on localhost, and could be used to snoop on network activity of other pods on the same node. Remove the 'hostNetwork' key to disable this functionality.

---

**`hostpid-pod`** | WARNING | `community-rules\yaml\kubernetes\security\hostpid-pod.yaml`
> Pod is sharing the host process ID namespace. When paired with ptrace this can be used to escalate privileges outside of the container. Remove the 'hostPID' key to disable this functionality.

---

**`id-request`** | LOW | `community-rules\yaml\semgrep\metadata-likelihood-incorrect-value.test.yaml`
> If an attacker controls the x in require(x) then they can cause code to load that was not intended to run on the server.

---

**`interfile-true-under-metadata-and-no-options`** | WARNING | `community-rules\yaml\semgrep\interfile-true-under-metadata-and-no-options.yaml`
> `interfile: true` should be under the `options` field, not the `metadata` field.

---

**`interfile-true-under-metadata-and-options-already-present`** | WARNING | `community-rules\yaml\semgrep\interfile-true-under-metadata-and-options-already-present.yaml`
> `interfile: true` should be under the `options` field, not the `metadata` field.

---

**`javascript.phantom.security.audit.phantom-injection.phantom-injection`** | WARNING | `community-rules\yaml\semgrep\slow-pattern-top-ellipsis.test.yaml`
> If unverified user data can reach the `phantom` page methods it can result in Server-Side Request Forgery vulnerabilities

---

**`javascript.playwright.security.audit.playwright-evaluate-arg-injection.playwright-evaluate-arg-injection`** | WARNING | `community-rules\yaml\semgrep\slow-pattern-top-ellipsis.test.yaml`
> If unverified user data can reach the `evaluate` method it can result in Server-Side Request Forgery vulnerabilities

---

**`lang-consistency-bash`** | WARNING | `community-rules\yaml\semgrep\consistency\lang-consistency-bash.yaml`
> Found '$X' in language config which diverges from semgrep.dev normalization. Please use 'bash' instead.

---

**`lang-consistency-cpp`** | WARNING | `community-rules\yaml\semgrep\consistency\lang-consistency-cpp.yaml`
> Found '$X' in language config which diverges from semgrep.dev normalization. Please use 'cpp' instead.

---

**`lang-consistency-csharp`** | WARNING | `community-rules\yaml\semgrep\consistency\lang-consistency-csharp.yaml`
> Found '$X' in language config which diverges from semgrep.dev normalization. Please use 'csharp' instead.

---

**`lang-consistency-dockerfile`** | WARNING | `community-rules\yaml\semgrep\consistency\lang-consistency-dockerfile.yaml`
> Found '$X' in language config which diverges from semgrep.dev normalization. Please use 'dockerfile' instead.

---

**`lang-consistency-elixir`** | WARNING | `community-rules\yaml\semgrep\consistency\lang-consistency-elixir.yaml`
> Found '$X' in language config which diverges from semgrep.dev normalization. Please use 'elixir' instead.

---

**`lang-consistency-go`** | WARNING | `community-rules\yaml\semgrep\consistency\lang-consistency-go.yaml`
> Found '$X' in language config which diverges from semgrep.dev normalization. Please use 'go' instead.

---

**`lang-consistency-hcl`** | WARNING | `community-rules\yaml\semgrep\consistency\lang-consistency-hcl.yaml`
> Found '$X' in language config which diverges from semgrep.dev normalization. Please use 'hcl' instead.

---

**`lang-consistency-js`** | WARNING | `community-rules\yaml\semgrep\consistency\lang-consistency-js.yaml`
> Found '$X' in language config which diverges from semgrep.dev normalization. Please use 'js' instead.

---

**`lang-consistency-kotlin`** | WARNING | `community-rules\yaml\semgrep\consistency\lang-consistency-kotlin.yaml`
> Found '$X' in language config which diverges from semgrep.dev normalization. Please use 'kotlin' instead.

---

**`lang-consistency-python`** | WARNING | `community-rules\yaml\semgrep\consistency\lang-consistency-python.yaml`
> Found '$X' in language config which diverges from semgrep.dev normalization. Please use 'python' instead.

---

**`lang-consistency-regex`** | WARNING | `community-rules\yaml\semgrep\consistency\lang-consistency-regex.yaml`
> Found '$X' in language config which diverges from semgrep.dev normalization. Please use 'regex' instead.

---

**`lang-consistency-solidity`** | WARNING | `community-rules\yaml\semgrep\consistency\lang-consistency-solidity.yaml`
> Found '$X' in language config which diverges from semgrep.dev normalization. Please use 'solidity' instead.

---

**`lang-consistency-ts`** | WARNING | `community-rules\yaml\semgrep\consistency\lang-consistency-ts.yaml`
> Found '$X' in language config which diverges from semgrep.dev normalization. Please use 'ts' instead.

---

**`legacy-api-clusterrole-excessive-permissions`** | WARNING | `community-rules\yaml\kubernetes\security\legacy-api-clusterrole-excessive-permissions.yaml`
> Semgrep detected a Kubernetes core API ClusterRole with excessive permissions. Attaching excessive permissions to a ClusterRole associated with the core namespace allows the V1 API to perform arbitrary actions on arbitrary resources attached to the cluster. Prefer explicit allowlists of verbs/resources when configuring the core API namespace. 

---

**`libxml2-xxe-taint`** | ERROR | `community-rules\yaml\semgrep\interfile-true-under-metadata-and-no-options.fixed.test.yaml`
> The application is using an XML parser that has not been safely configured. This might lead to XML External Entity (XXE) vulnerabilities when parsing user-controlled input. An attacker can include document type definitions (DTDs) which can interact with internal or external hosts. XXE can lead to other vulnerabilities, such as Local File Inclusion (LFI), Remote Code Execution (RCE), and Server-side request forgery (SSRF), depending on the application configuration. An attacker can also use DTDs to expand recursively, leading to a Denial-of-Service (DoS) attack, also known as a `Billion Laughs Attack`. The best defense against XXE is to have an XML parser that supports disabling DTDs. Limiting the use of external entities from the start can prevent the parser from being used to process untrusted XML files. Reducing dependencies on external resources is also a good practice for performance reasons. It is difficult to guarantee that even a trusted XML file on your server or during transmission has not been tampered with by a malicious third-party. 

---

**`libxml2-xxe-taint`** | ERROR | `community-rules\yaml\semgrep\interfile-true-under-metadata-and-no-options.test.yaml`
> The application is using an XML parser that has not been safely configured. This might lead to XML External Entity (XXE) vulnerabilities when parsing user-controlled input. An attacker can include document type definitions (DTDs) which can interact with internal or external hosts. XXE can lead to other vulnerabilities, such as Local File Inclusion (LFI), Remote Code Execution (RCE), and Server-side request forgery (SSRF), depending on the application configuration. An attacker can also use DTDs to expand recursively, leading to a Denial-of-Service (DoS) attack, also known as a `Billion Laughs Attack`. The best defense against XXE is to have an XML parser that supports disabling DTDs. Limiting the use of external entities from the start can prevent the parser from being used to process untrusted XML files. Reducing dependencies on external resources is also a good practice for performance reasons. It is difficult to guarantee that even a trusted XML file on your server or during transmission has not been tampered with by a malicious third-party. 

---

**`libxml2-xxe-taint`** | ERROR | `community-rules\yaml\semgrep\interfile-true-under-metadata-and-options-already-present.fixed.test.yaml`
> The application is using an XML parser that has not been safely configured. This might lead to XML External Entity (XXE) vulnerabilities when parsing user-controlled input. An attacker can include document type definitions (DTDs) which can interact with internal or external hosts. XXE can lead to other vulnerabilities, such as Local File Inclusion (LFI), Remote Code Execution (RCE), and Server-side request forgery (SSRF), depending on the application configuration. An attacker can also use DTDs to expand recursively, leading to a Denial-of-Service (DoS) attack, also known as a `Billion Laughs Attack`. The best defense against XXE is to have an XML parser that supports disabling DTDs. Limiting the use of external entities from the start can prevent the parser from being used to process untrusted XML files. Reducing dependencies on external resources is also a good practice for performance reasons. It is difficult to guarantee that even a trusted XML file on your server or during transmission has not been tampered with by a malicious third-party. 

---

**`libxml2-xxe-taint`** | ERROR | `community-rules\yaml\semgrep\interfile-true-under-metadata-and-options-already-present.test.yaml`
> The application is using an XML parser that has not been safely configured. This might lead to XML External Entity (XXE) vulnerabilities when parsing user-controlled input. An attacker can include document type definitions (DTDs) which can interact with internal or external hosts. XXE can lead to other vulnerabilities, such as Local File Inclusion (LFI), Remote Code Execution (RCE), and Server-side request forgery (SSRF), depending on the application configuration. An attacker can also use DTDs to expand recursively, leading to a Denial-of-Service (DoS) attack, also known as a `Billion Laughs Attack`. The best defense against XXE is to have an XML parser that supports disabling DTDs. Limiting the use of external entities from the start can prevent the parser from being used to process untrusted XML files. Reducing dependencies on external resources is also a good practice for performance reasons. It is difficult to guarantee that even a trusted XML file on your server or during transmission has not been tampered with by a malicious third-party. 

---

**`message-whitespace-check`** | WARNING | `community-rules\yaml\semgrep\message-whitespace.yaml`
> It looks like you have an additional space in your rule message, this can look awkward in the finding output, please remove the additional whitespace!

---

**`metadata-category`** | INFO | `community-rules\yaml\semgrep\metadata-category.yaml`
> This Semgrep rule is missing a valid 'category' field in the 'metadata'. 'category' must be one of 'security', 'correctness', 'best-practice', 'performance', 'maintainability', or 'portability'.

---

**`metadata-confidence`** | WARNING | `community-rules\yaml\semgrep\metadata-confidence.yaml`
> This Semgrep rule is missing a valid 'confidence' field in the 'metadata'. which should be either LOW, MEDIUM, or HIGH. For more information visit https://semgrep.dev/docs/contributing/contributing-to-semgrep-rules-repository/

---

**`metadata-confidence-incorrect-value`** | WARNING | `community-rules\yaml\semgrep\metadata-confidence-incorrect-value.yaml`
> Semgrep rule confidence: $VALUE detected, but the value must be LOW, MEDIUM, or HIGH. For more information visit: https://semgrep.dev/docs/contributing/contributing-to-semgrep-rules-repository/

---

**`metadata-cwe`** | ERROR | `community-rules\yaml\semgrep\metadata-cwe.yaml`
> $...CWE The cwe tag in rule metadata should always be in the format "CWE-000: Title".

---

**`metadata-cwe-prohibited-or-discouraged`** | ERROR | `community-rules\yaml\semgrep\metadata-cwe-prohibited-or-discouraged.yaml`
> Vulnerability mapping for this CWE is discouraged or prohibited.

---

**`metadata-deepsemgrep`** | WARNING | `community-rules\yaml\semgrep\metadata-deepsemgrep.yaml`
> We no longer support `deepsemgrep: true`, please use `interfile:true`

---

**`metadata-impact`** | WARNING | `community-rules\yaml\semgrep\metadata-impact.yaml`
> This Semgrep rule is missing a valid 'impact' field in the 'metadata'. which should be either LOW, MEDIUM, or HIGH. For more information visit https://semgrep.dev/docs/contributing/contributing-to-semgrep-rules-repository/

---

**`metadata-impact-incorrect-value`** | WARNING | `community-rules\yaml\semgrep\metadata-impact-incorrect-value.yaml`
> Semgrep rule impact: $VALUE detected, but the value must be LOW, MEDIUM, or HIGH. For more information visit: https://semgrep.dev/docs/contributing/contributing-to-semgrep-rules-repository/

---

**`metadata-incorrect-option`** | INFO | `community-rules\yaml\semgrep\metadata-incorrect-option.yaml`
> It looks like $KEY is not in the default list of expected options, if this is a new key update this rule

---

**`metadata-license`** | ERROR | `community-rules\yaml\semgrep\metadata-license.yaml`
> The license should not be set in rule metadata, it gets added by Semgrep app at the registry level.

---

**`metadata-likelihood`** | WARNING | `community-rules\yaml\semgrep\metadata-likelihood.yaml`
> This Semgrep rule is missing a valid 'likelihood' field in the 'metadata'. which should be either LOW, MEDIUM, or HIGH. For more information visit https://semgrep.dev/docs/contributing/contributing-to-semgrep-rules-repository/

---

**`metadata-likelihood-incorrect-value`** | WARNING | `community-rules\yaml\semgrep\metadata-likelihood-incorrect-value.yaml`
> Semgrep rule likelihood: $VALUE detected, but the value must be LOW, MEDIUM, or HIGH. For more information visit: https://semgrep.dev/docs/contributing/contributing-to-semgrep-rules-repository/

---

**`metadata-owasp`** | ERROR | `community-rules\yaml\semgrep\metadata-owasp.yaml`
> The `owasp` tag in Semgrep rule metadata should start with the format "A00:YYYY", where A00 is the OWASP top ten number and YYYY is the OWASP top ten year.

---

**`metadata-references`** | ERROR | `community-rules\yaml\semgrep\metadata-references.yaml`
> The references in rule metadata should always be a list, even if there's only one.

---

**`metadata-subcategory`** | WARNING | `community-rules\yaml\semgrep\metadata-subcategory.yaml`
> This Semgrep rule is missing a valid 'subcategory' field in the 'metadata'. which should be either audit, vuln, or secure default. For more information visit https://semgrep.dev/docs/contributing/contributing-to-semgrep-rules-repository/

---

**`metadata-subcategory-incorrect-value`** | WARNING | `community-rules\yaml\semgrep\metadata-subcategory-incorrect-value.yaml`
> Semgrep rule likelihood: $VALUE detected, but the value must be vuln, audit, or secure default. For more information visit: https://semgrep.dev/docs/contributing/contributing-to-semgrep-rules-repository/

---

**`metadata-technology`** | INFO | `community-rules\yaml\semgrep\metadata-technology.yaml`
> This Semgrep rule is missing a 'technology' field in the 'metadata'. Consider adding a list of technologies based on the rule's associated library or framework, or another piece of relevant information.

---

**`missing-deconstructed-value`** | WARNING | `community-rules\yaml\semgrep\rule-missing-deconstructed-value.yaml`
> Looks like this value is deconstructing a const/var/let you need to use all three `const {...} =` `var {...} =` and `let {...} =` to provide accurate coverage consider adding the missing patterns in a `pattern-inside` for better coverage.

---

**`missing-language-field`** | WARNING | `community-rules\yaml\semgrep\missing-language-field.yaml`
> Please include a 'languages' field for your rule!

---

**`missing-message-field`** | WARNING | `community-rules\yaml\semgrep\missing-message-field.yaml`
> This rule does not have a message. Semgrep requires that rules have a message. Include a message to explain what the rule does. Consider writing a message that explains why this is an issue and how to fix it.

---

**`multi-line-message`** | WARNING | `community-rules\yaml\semgrep\multi-line-message.yaml`
> This rule has a multi-line message field, which may display poorly in a terminal. Consider ensuring it is on one line. For example, use `message: >-`, not `message: |`.

---

**`no-fractional-cpu-limits`** | WARNING | `community-rules\yaml\kubernetes\best-practice\no-fractional-cpu-limits.yaml`
> When you set a fractional CPU limit on a container, the CPU cycles available will be throttled, even though most nodes can handle processes alternating between using 100% of the CPU.

---

**`no-new-privileges`** | WARNING | `community-rules\yaml\docker-compose\security\no-new-privileges.yaml`
> Service '$SERVICE' allows for privilege escalation via setuid or setgid binaries. Add 'no-new-privileges:true' in 'security_opt' to prevent this.

---

**`ok-request`** | LOW | `community-rules\yaml\semgrep\metadata-likelihood-incorrect-value.test.yaml`
> If an attacker controls the x in require(x) then they can cause code to load that was not intended to run on the server.

---

**`openai-consequential-action-false`** | WARNING | `community-rules\yaml\openapi\security\openai-consequential-action-false.yaml`
> Found 'x-openai-isConsequential: false' in a state-changing HTTP method: $METHOD $PATH. This Action configuration will enable the 'Always Allow' option for state-changing HTTP methods, such as POST, PUT, PATCH, or DELETE. The risk of a user selecting the 'Always Allow' button is that the agent could perform unintended actions on behalf of the user. When working with sensitive functionality, it is always best to include a Human In The Loop (HITL) type of control. Consider the trade-off between security  and user friction and then make a risk-based decision about this function.

---

**`other-rule`** | INFO | `community-rules\yaml\semgrep\missing-language-field.test.yaml`
> 

---

**`other-rule`** | INFO | `community-rules\yaml\semgrep\missing-message-field.test.yaml`
> 

---

**`other-rule-2`** | INFO | `community-rules\yaml\semgrep\missing-message-field.test.yaml`
> 

---

**`privileged-container`** | WARNING | `community-rules\yaml\kubernetes\security\privileged-container.yaml`
> Container or pod is running in privileged mode. This grants the container the equivalent of root capabilities on the host machine. This can lead to container escapes, privilege escalation, and other security concerns. Remove the 'privileged' key to disable this capability.

---

**`privileged-service`** | WARNING | `community-rules\yaml\docker-compose\security\privileged-service.yaml`
> Service '$SERVICE' is running in privileged mode. This grants the container the equivalent of root capabilities on the host machine. This can lead to container escapes, privilege escalation, and other security concerns. Remove the 'privileged' key to disable this capability.

---

**`pull-request-target-code-checkout`** | WARNING | `community-rules\yaml\github-actions\security\pull-request-target-code-checkout.yaml`
> This GitHub Actions workflow file uses `pull_request_target` and checks out code from the incoming pull request. When using `pull_request_target`, the Action runs in the context of the target repository, which includes access to all repository secrets. Normally, this is safe because the Action only runs code from the target repository, not the incoming PR. However, by checking out the incoming PR code, you're now using the incoming code for the rest of the action. You may be inadvertently executing arbitrary code from the incoming PR with access to repository secrets, which would let an attacker steal repository secrets. This normally happens by running build scripts (e.g., `npm build` and `make`) or dependency installation scripts (e.g., `python setup.py install`). Audit your workflow file to make sure no code from the incoming PR is executed. Please see https://securitylab.github.com/research/github-actions-preventing-pwn-requests/ for additional mitigations.

---

**`require-request`** | LOW | `community-rules\yaml\semgrep\metadata-confidence-incorrect-value.test.yaml`
> If an attacker controls the x in require(x) then they can cause code to load that was not intended to run on the server.

---

**`require-request`** | LOW | `community-rules\yaml\semgrep\metadata-confidence-incorrect-value.test.yaml`
> If an attacker controls the x in require(x) then they can cause code to load that was not intended to run on the server.

---

**`require-request`** | LOW | `community-rules\yaml\semgrep\metadata-confidence.test.yaml`
> If an attacker controls the x in require(x) then they can cause code to load that was not intended to run on the server.

---

**`require-request`** | LOW | `community-rules\yaml\semgrep\metadata-confidence.test.yaml`
> If an attacker controls the x in require(x) then they can cause code to load that was not intended to run on the server.

---

**`require-request`** | LOW | `community-rules\yaml\semgrep\metadata-deepsemgrep.test.yaml`
> If an attacker controls the x in require(x) then they can cause code to load that was not intended to run on the server.

---

**`require-request`** | LOW | `community-rules\yaml\semgrep\metadata-deepsemgrep.test.yaml`
> If an attacker controls the x in require(x) then they can cause code to load that was not intended to run on the server.

---

**`require-request`** | LOW | `community-rules\yaml\semgrep\metadata-impact-incorrect-value.test.yaml`
> If an attacker controls the x in require(x) then they can cause code to load that was not intended to run on the server.

---

**`require-request`** | LOW | `community-rules\yaml\semgrep\metadata-impact-incorrect-value.test.yaml`
> If an attacker controls the x in require(x) then they can cause code to load that was not intended to run on the server.

---

**`require-request`** | LOW | `community-rules\yaml\semgrep\metadata-impact.test.yaml`
> If an attacker controls the x in require(x) then they can cause code to load that was not intended to run on the server.

---

**`require-request`** | LOW | `community-rules\yaml\semgrep\metadata-impact.test.yaml`
> If an attacker controls the x in require(x) then they can cause code to load that was not intended to run on the server.

---

**`require-request`** | LOW | `community-rules\yaml\semgrep\metadata-license.test.yaml`
> If an attacker controls the x in require(x) then they can cause code to load that was not intended to run on the server.

---

**`require-request`** | LOW | `community-rules\yaml\semgrep\metadata-license.test.yaml`
> If an attacker controls the x in require(x) then they can cause code to load that was not intended to run on the server.

---

**`require-request`** | LOW | `community-rules\yaml\semgrep\metadata-likelihood.test.yaml`
> If an attacker controls the x in require(x) then they can cause code to load that was not intended to run on the server.

---

**`require-request`** | LOW | `community-rules\yaml\semgrep\metadata-likelihood.test.yaml`
> If an attacker controls the x in require(x) then they can cause code to load that was not intended to run on the server.

---

**`require-request`** | LOW | `community-rules\yaml\semgrep\metadata-subcategory-incorrect-value.test.yaml`
> If an attacker controls the x in require(x) then they can cause code to load that was not intended to run on the server.

---

**`require-request`** | LOW | `community-rules\yaml\semgrep\metadata-subcategory-incorrect-value.test.yaml`
> If an attacker controls the x in require(x) then they can cause code to load that was not intended to run on the server.

---

**`require-request`** | LOW | `community-rules\yaml\semgrep\metadata-subcategory.test.yaml`
> If an attacker controls the x in require(x) then they can cause code to load that was not intended to run on the server.

---

**`require-request`** | LOW | `community-rules\yaml\semgrep\metadata-subcategory.test.yaml`
> If an attacker controls the x in require(x) then they can cause code to load that was not intended to run on the server.

---

**`run-as-non-root`** | INFO | `community-rules\yaml\kubernetes\security\run-as-non-root.yaml`
> When running containers in Kubernetes, it's important to ensure that they  are properly secured to prevent privilege escalation attacks.  One potential vulnerability is when a container is allowed to run  applications as the root user, which could allow an attacker to gain  access to sensitive resources. To mitigate this risk, it's recommended to  add a `securityContext` to the container, with the parameter `runAsNonRoot`  set to `true`. This will ensure that the container runs as a non-root user,  limiting the damage that could be caused by any potential attacks. By  adding a `securityContext` to the container in your Kubernetes pod, you can  help to ensure that your containerized applications are more secure and  less vulnerable to privilege escalation attacks.

---

**`run-as-non-root-container-level`** | INFO | `community-rules\yaml\kubernetes\security\run-as-non-root-container-level.yaml`
> When running containers in Kubernetes, it's important to ensure that they are properly secured to prevent privilege escalation attacks. One potential vulnerability is when a container is allowed to run applications as the root user, which could allow an attacker to gain access to sensitive resources. To mitigate this risk, it's recommended to add a `securityContext` to the container, with the parameter `runAsNonRoot` set to `true`. This will ensure that the container runs as a non-root user, limiting the damage that could be caused by any potential attacks. By adding a `securityContext` to the container in your Kubernetes pod, you can help to ensure that your containerized applications are more secure and less vulnerable to privilege escalation attacks.

---

**`run-as-non-root-container-level-missing-security-context`** | INFO | `community-rules\yaml\kubernetes\security\run-as-non-root-container-level-missing-security-context.yaml`
> When running containers in Kubernetes, it's important to ensure that they are properly secured to prevent privilege escalation attacks. One potential vulnerability is when a container is allowed to run applications as the root user, which could allow an attacker to gain access to sensitive resources. To mitigate this risk, it's recommended to add a `securityContext` to the container, with the parameter `runAsNonRoot` set to `true`. This will ensure that the container runs as a non-root user, limiting the damage that could be caused by any potential attacks. By adding a `securityContext` to the container in your Kubernetes pod, you can help to ensure that your containerized applications are more secure and less vulnerable to privilege escalation attacks.

---

**`run-as-non-root-security-context-pod-level`** | INFO | `community-rules\yaml\kubernetes\security\run-as-non-root-security-context-pod-level.yaml`
> When running containers in Kubernetes, it's important to ensure that they are properly secured to prevent privilege escalation attacks. One potential vulnerability is when a container is allowed to run applications as the root user, which could allow an attacker to gain access to sensitive resources. To mitigate this risk, it's recommended to add a `securityContext` to the container, with the parameter `runAsNonRoot` set to `true`. This will ensure that the container runs as a non-root user, limiting the damage that could be caused by any potential attacks. By adding a `securityContext` to the container in your Kubernetes pod, you can help to ensure that your containerized applications are more secure and less vulnerable to privilege escalation attacks.

---

**`run-as-non-root-unsafe-value`** | INFO | `community-rules\yaml\kubernetes\security\run-as-non-root-unsafe-value.yaml`
> When running containers in Kubernetes, it's important to ensure that they  are properly secured to prevent privilege escalation attacks.  One potential vulnerability is when a container is allowed to run  applications as the root user, which could allow an attacker to gain  access to sensitive resources. To mitigate this risk, it's recommended to  add a `securityContext` to the container, with the parameter `runAsNonRoot`  set to `true`. This will ensure that the container runs as a non-root user,  limiting the damage that could be caused by any potential attacks. By  adding a `securityContext` to the container in your Kubernetes pod, you can  help to ensure that your containerized applications are more secure and  less vulnerable to privilege escalation attacks.

---

**`run-shell-injection`** | ERROR | `community-rules\yaml\github-actions\security\run-shell-injection.yaml`
> Using variable interpolation `${{...}}` with `github` context data in a `run:` step could allow an attacker to inject their own code into the runner. This would allow them to steal secrets and code. `github` context data can have arbitrary user input and should be treated as untrusted. Instead, use an intermediate environment variable with `env:` to store the data and use the environment variable in the `run:` script. Be sure to use double-quotes the environment variable, like this: "$ENVVAR".

---

**`seccomp-confinement-disabled`** | WARNING | `community-rules\yaml\docker-compose\security\seccomp-confinement-disabled.yaml`
> Service '$SERVICE' is explicitly disabling seccomp confinement. This runs the service in an unrestricted state. Remove 'seccomp:unconfined' to prevent this.

---

**`seccomp-confinement-disabled`** | WARNING | `community-rules\yaml\kubernetes\security\seccomp-confinement-disabled.yaml`
> Container is explicitly disabling seccomp confinement. This runs the service in an unrestricted state. Remove 'seccompProfile: unconfined' to prevent this.

---

**`secrets-in-config-file`** | WARNING | `community-rules\yaml\kubernetes\security\secrets-in-config-file.yaml`
> Secrets ($VALUE) should not be stored in infrastructure as code files. Use an alternative such as Bitnami Sealed Secrets or KSOPS to encrypt Kubernetes Secrets. 

---

**`selinux-separation-disabled`** | WARNING | `community-rules\yaml\docker-compose\security\selinux-separation-disabled.yaml`
> Service '$SERVICE' is explicitly disabling SELinux separation. This runs the service as an unconfined type. Remove 'label:disable' to prevent this.

---

**`semgrep-github-action-push-without-branches`** | WARNING | `community-rules\yaml\github-actions\semgrep-configuration\semgrep-github-action-push-without-branches.yml`
> The 'branches' field (in the push event configuration) contains no branches. This causes all branches to be scanned and may result in unneccessary duplicate findings across the entire codebase.

---

**`skip-tls-verify-cluster`** | WARNING | `community-rules\yaml\kubernetes\security\skip-tls-verify-cluster.yaml`
> Cluster is disabling TLS certificate verification when communicating with the server. This makes your HTTPS connections insecure. Remove the 'insecure-skip-tls-verify: true' key to secure communication.

---

**`skip-tls-verify-service`** | WARNING | `community-rules\yaml\kubernetes\security\skip-tls-verify-service.yaml`
> Service is disabling TLS certificate verification when communicating with the server. This makes your HTTPS connections insecure. Remove the 'insecureSkipTLSVerify: true' key to secure communication.

---

**`slow-pattern-general-func`** | WARNING | `community-rules\yaml\semgrep\slow-pattern-general-function.yaml`
> Using patterns like `function (...) {...}` is too general it will probably slow down the rule performance.

---

**`slow-pattern-general-property`** | WARNING | `community-rules\yaml\semgrep\slow-pattern-general-property.yaml`
> Using patterns like `$X.$Y` may be too general and may slow down the rule performance.

---

**`slow-pattern-single-metavariable`** | WARNING | `community-rules\yaml\semgrep\slow-pattern-single-metavariable.yaml`
> Using a single metavariable as a pattern drastically slows down the rule performance because it will match every expression in a file. Instead, try to match something specific such as a function name, or anchor on a statement that may occur above or below the pattern. The more specific you can be, the faster the pattern will run.

---

**`slow-pattern-top-ellipsis`** | WARNING | `community-rules\yaml\semgrep\slow-pattern-top-ellipsis.yaml`
> Using the ellipsis operator `...` at the top of the pattern drastically slows down the rule performance.

---

**`subprocess-run`** | WARNING | `community-rules\yaml\semgrep\metadata-category.test.yaml`
> bad stuff

---

**`subprocess-run`** | WARNING | `community-rules\yaml\semgrep\metadata-technology.test.yaml`
> bad stuff

---

**`subprocess-run-2`** | WARNING | `community-rules\yaml\semgrep\metadata-category.test.yaml`
> bad stuff

---

**`subprocess-run-2`** | WARNING | `community-rules\yaml\semgrep\metadata-technology.test.yaml`
> bad stuff

---

**`swift-user-defaults`** | WARNING | `community-rules\yaml\semgrep\metadata-incorrect-option.test.yaml`
> Potentially sensitive data was observed to be stored in UserDefaults, which is not adequate protection of sensitive information. For data of a sensitive nature, applications should leverage the Keychain.

---

**`third-party-action-not-pinned-to-commit-sha`** | WARNING | `community-rules\yaml\github-actions\security\third-party-action-not-pinned-to-commit-sha.yml`
> An action sourced from a third-party repository on GitHub is not pinned to a full length commit SHA. Pinning an action to a full length commit SHA is currently the only way to use an action as an immutable release. Pinning to a particular SHA helps mitigate the risk of a bad actor adding a backdoor to the action's repository, as they would need to generate a SHA-1 collision for a valid Git object payload.

---

**`typescript.react.best-practice.react-props-in-state.react-props-in-state`** | WARNING | `community-rules\yaml\semgrep\slow-pattern-single-metavariable.test.yaml`
> It is a bad practice to stop the data flow in rendering by copying props into state.

---

**`unchecked-subprocess-call`** | WARNING | `community-rules\yaml\semgrep\duplicate-id.test.yaml`
> 

---

**`unchecked-subprocess-call`** | WARNING | `community-rules\yaml\semgrep\duplicate-id.test.yaml`
> 

---

**`unchecked-subprocess-call`** | WARNING | `community-rules\yaml\semgrep\duplicate-pattern.test.yaml`
> This is not checking the return value of this subprocess call; if it fails no exception will be raised. Consider subprocess.check_call() instead

---

**`unchecked-subprocess-call`** | WARNING | `community-rules\yaml\semgrep\empty-message.test.yaml`
> 

---

**`unchecked-subprocess-call`** | WARNING | `community-rules\yaml\semgrep\metadata-category.test.yaml`
> bad stuff

---

**`unchecked-subprocess-call`** | WARNING | `community-rules\yaml\semgrep\metadata-technology.test.yaml`
> bad stuff

---

**`unchecked-subprocess-call`** | WARNING | `community-rules\yaml\semgrep\missing-language-field.test.yaml`
> 

---

**`unchecked-subprocess-call`** | WARNING | `community-rules\yaml\semgrep\missing-message-field.test.yaml`
> No description

---

**`unchecked-subprocess-call`** | WARNING | `community-rules\yaml\semgrep\unsatisfiable.test.yaml`
> blah

---

**`unchecked-subprocess-call-1`** | WARNING | `community-rules\yaml\semgrep\duplicate-id.test.yaml`
> 

---

**`unchecked-subprocess-call-2`** | WARNING | `community-rules\yaml\semgrep\duplicate-id.test.yaml`
> 

---

**`unchecked-subprocess-call-3`** | WARNING | `community-rules\yaml\semgrep\duplicate-id.test.yaml`
> 

---

**`unchecked-subprocess-call1`** | WARNING | `community-rules\yaml\semgrep\unnecessary-parent.test.yaml`
> test

---

**`unchecked-subprocess-call2`** | WARNING | `community-rules\yaml\semgrep\unnecessary-parent.test.yaml`
> test

---

**`unchecked-subprocess-call3`** | WARNING | `community-rules\yaml\semgrep\unnecessary-parent.test.yaml`
> test

---

**`unchecked-subprocess-call4`** | WARNING | `community-rules\yaml\semgrep\unnecessary-parent.test.yaml`
> test

---

**`unchecked-subprocess-call5`** | WARNING | `community-rules\yaml\semgrep\unnecessary-parent.test.yaml`
> test

---

**`unchecked-subprocess-call6`** | WARNING | `community-rules\yaml\semgrep\unnecessary-parent.test.yaml`
> test

---

**`unchecked-subprocess-call7`** | WARNING | `community-rules\yaml\semgrep\unnecessary-parent.test.yaml`
> test

---

**`unchecked-subprocess-call8`** | WARNING | `community-rules\yaml\semgrep\unnecessary-parent.test.yaml`
> test

---

**`unknown`** | UNKNOWN | `community-rules\yaml\kubernetes\security\legacy-api-clusterrole-excessive-permissions.test.yaml`
> No description

---

**`unknown`** | UNKNOWN | `community-rules\yaml\kubernetes\security\legacy-api-clusterrole-excessive-permissions.test.yaml`
> No description

---

**`unknown`** | UNKNOWN | `community-rules\yaml\kubernetes\security\legacy-api-clusterrole-excessive-permissions.test.yaml`
> No description

---

**`unknown`** | UNKNOWN | `community-rules\yaml\kubernetes\security\legacy-api-clusterrole-excessive-permissions.test.yaml`
> No description

---

**`unknown`** | UNKNOWN | `community-rules\yaml\kubernetes\security\legacy-api-clusterrole-excessive-permissions.test.yaml`
> No description

---

**`unknown`** | UNKNOWN | `community-rules\yaml\kubernetes\security\legacy-api-clusterrole-excessive-permissions.test.yaml`
> No description

---

**`unnecessary-parent-operator`** | WARNING | `community-rules\yaml\semgrep\unnecessary-parent.yaml`
> Unnecessary parent operator. Remove one to fix.

---

**`unsafe-add-mask-workflow-command`** | WARNING | `community-rules\yaml\github-actions\security\audit\unsafe-add-mask-workflow-command.yaml`
> GitHub Actions provides the **'add-mask'** workflow command to mask sensitive data in the workflow logs. If **'add-mask'** is not used or if workflow commands have been stopped, sensitive data can leaked into the workflow logs. An attacker could simply copy the workflow to another branch and add the following payload `echo "::stop-commands::$stopMarker"` to stop workflow command processing ([described here](https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#stopping-and-starting-workflow-commands)), which will cause the secret token to be exposed despite the **'add-mask'** usage. For more information, please refer to the [GitHub documentation](https://github.com/actions/toolkit/blob/main/docs/commands.md#register-a-secret).

---

**`unsatisfiable-rule`** | ERROR | `community-rules\yaml\semgrep\unsatisfiable.yaml`
> You can not use 'pattern' $A and 'pattern-not' $A together; this will always be empty.

---

**`use-of-basic-authentication`** | ERROR | `community-rules\yaml\openapi\security\use-of-basic-authentication.yaml`
> Basic authentication is considered weak and should be avoided.  Use a different authentication scheme, such of OAuth2, OpenID Connect, or mTLS.

---

**`workflow-run-target-code-checkout`** | WARNING | `community-rules\yaml\github-actions\security\workflow-run-target-code-checkout.yaml`
> This GitHub Actions workflow file uses `workflow_run` and checks out code from the incoming pull request. When using `workflow_run`, the Action runs in the context of the target repository, which includes access to all repository secrets. Normally, this is safe because the Action only runs code from the target repository, not the incoming PR. However, by checking out the incoming PR code, you're now using the incoming code for the rest of the action. You may be inadvertently executing arbitrary code from the incoming PR with access to repository secrets, which would let an attacker steal repository secrets. This normally happens by running build scripts (e.g., `npm build` and `make`) or dependency installation scripts (e.g., `python setup.py install`). Audit your workflow file to make sure no code from the incoming PR is executed. Please see https://securitylab.github.com/research/github-actions-preventing-pwn-requests/ for additional mitigations.

---

**`writable-filesystem-container`** | WARNING | `community-rules\yaml\kubernetes\security\writable-filesystem-container.yaml`
> Container $CONTAINER is running with a writable root filesystem. This may allow malicious applications to download and run additional payloads, or modify container files. If an application inside a container has to save something temporarily consider using a tmpfs. Add 'readOnlyRootFilesystem: true' to this container to prevent this.

---

**`writable-filesystem-service`** | WARNING | `community-rules\yaml\docker-compose\security\writable-filesystem-service.yaml`
> Service '$SERVICE' is running with a writable root filesystem. This may allow malicious applications to download and run additional payloads, or modify container files. If an application inside a container has to save something temporarily consider using a tmpfs. Add 'read_only: true' to this service to prevent this.

---

**`yaml-key-indentation-check`** | WARNING | `community-rules\yaml\semgrep\key-indentation.yaml`
> It looks like you have an YAML indentation issue -- instead of writing `$KEY`,  put a space between the hyphen and what comes after! Otherwise, it reads  as a single string. 

---

**`yaml-key-indentation-check-example`** | WARNING | `community-rules\yaml\semgrep\key-indentation.test.yaml`
> There should be a finding here, because the YAML fuses the hyphen and the key together! 

---

