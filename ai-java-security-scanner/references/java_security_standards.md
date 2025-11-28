# JAVA安全编码审计规范

**文件密级：内部使用**

康龙化成(成都)临床研究服务有限公司
JAVA安全编码审计规范（V1.0）

> [本文件中出现的任何文字叙述、文档格式、插图、照片、方法、过程等内容，除另有特别注明，版权均属康龙化成（成都）临床研究服务有限公司所有，受到有关产权及版权法保护。任何个人、机构未经康龙化成（成都）临床研究服务有限公司的书面授权许可，不得以任何方式复制或引用本文件的任何片断。]

## 目录

1. [目的](#目的)
2. [范围](#范围)
3. [术语解释](#术语解释)
4. [常见JAVA安全漏洞](#常见java安全漏洞)
   - 4.1 [目录穿越漏洞](#41-目录穿越漏洞)
   - 4.2 [URL跳转漏洞](#42-url跳转漏洞)
   - 4.3 [SQL注入漏洞](#43-sql注入漏洞)
   - 4.4 [XSS漏洞](#44-xss漏洞)
   - 4.5 [XXE漏洞](#45-xxe漏洞)
   - 4.6 [任意文件上传漏洞](#46-任意文件上传漏洞)
   - 4.7 [Java反序列化漏洞](#47-java反序列化漏洞)
   - 4.8 [命令注入漏洞](#48-命令注入漏洞)
   - 4.9 [SpEL注入漏洞](#49-spel注入漏洞)
   - 4.10 [SSRF漏洞](#410-ssrf漏洞)
   - 4.11 [敏感信息泄露](#411-敏感信息泄露)
   - 4.12 [权限控制漏洞](#412-权限控制漏洞)
   - 4.13 [加密机制失效漏洞](#413-加密机制失效漏洞)
   - 4.14 [Threadlocal内存泄漏](#414-threadlocal内存泄漏)

## 目的

本规范的制定旨在为软件开发生命周期中的开发、测试及安全审计人员提供统一、明确的安全编码与审计依据。随着网络攻击手段的日益演进，应用系统的安全性已成为保障业务连续性与数据资产安全的核心。为此，本规范以国际公认的OWASP Top 10安全风险为核心基准，结合Java语言特性，系统梳理了常见安全漏洞的编码规范、审计方法及修复方案。

其核心目的在于：
- 为开发人员提供明确的安全编码指引，通过理解漏洞成因与修复方案，在编码阶段主动规避风险，减少安全漏洞的引入
- 为测试与审计人员提供系统化方法，使其能高效定位问题代码并验证修复效果

最终，推动团队在软件开发全生命周期中系统化地识别、规避与修复潜在安全风险，从本质上提升Java应用程序的安全性与可靠性。

## 范围

本规范适用于康龙临床所有采用java语言开发的应用系统。

## 术语解释

| 名称 | 定义 |
|------|------|
| OWASP | Open Web Application Security Project，开放式Web应用程序安全项目 |

## 常见JAVA安全漏洞

本章节以OWASP Top 10安全风险为核心基准，展开JAVA常见的安全漏洞，每个漏洞通过"漏洞描述"、"漏洞代码及审计过程"、"漏洞修复方案"三位一体的结构进行展开：通过清晰的描述阐明漏洞成因与危害；借助典型代码案例与审计要点，指导快速定位与验证问题；并提供安全漏洞的统一修复方案。

**说明：** 最终修复方案可根据实际业务场景进行调整。

---

## 4.1 目录穿越漏洞

### 4.1.1 漏洞描述

目录穿越(遍历)漏洞在 Web 应用程序中也是一种较为常见的漏洞，其往往出现在需要用户提供路径或文件名时，如文件下载。在访问者提供需要下载的文件后，Web 应用程序没有去检验文件名中是否存在"../"等特殊字符，没有对访问的文件进行限制，导致目录穿越，读取到本不应读取到的内容。

目录穿越漏洞产生的本质是路径可控，例如，Web应用程序的正常功能允许用户通过 filename 下载www/file/file.txt文件，但是如果没有控制好 filename参数传入的值，就有可能通过../../../etc/passwd 这种方式进行目录穿越，下载到非预期的/etc/passwd 文件，导致获取敏感信息、任意文件下载。

### 4.1.2 漏洞代码及审计过程

**漏洞代码示例：**
```java
public void getImageId(HttpServletResponse rp, String img) {
    String filePath = System.getProperty("user.dir") + img;
    File imageFile = new File(filePath);
    if(imageFile.exists()) {
        FileInputStream fis = null;
        OutputStream os = null;
        try {
            fis = new FileInputStream(imageFile);
            os = rp.getOutputStream();
            int count = 0;
            byte[] buffer = new byte[1024*8];
            while ((count = fis.read(buffer)) != -1) {
                os.write(buffer, 0, count);
                os.flush();
            }
        } catch (FileNotFoundException e) {
            // 异常处理
        }
    }
}
```

**审计要点：**
1. 检查文件路径参数是否直接拼接用户输入
2. 验证是否有路径穿越防护机制
3. 确认文件访问权限控制是否完善

### 4.1.3 漏洞修复方案

**安全修复代码：**
```java
public void getImageId(HttpServletResponse rp, String img) {
    // 限制访问目录
    String baseDir = System.getProperty("user.dir") + "/uploads/";

    // 规范化路径，防止目录穿越
    Path path = Paths.get(baseDir, img).normalize();

    // 验证路径是否在允许的目录内
    if (!path.startsWith(baseDir)) {
        throw new SecurityException("Access denied: Path traversal attempt");
    }

    File imageFile = path.toFile();
    if(imageFile.exists() && imageFile.isFile()) {
        // 文件读取处理
    }
}
```

---

## 4.2 URL跳转漏洞

### 4.2.1 漏洞描述

URL跳转漏洞又称开放重定向漏洞，是指Web应用程序将用户重定向到恶意网站，攻击者可以构造恶意链接，诱导用户点击后跳转到钓鱼网站，从而窃取用户敏感信息。

### 4.2.2 漏洞代码及审计过程

**漏洞代码示例：**
```java
@RequestMapping("/redirect")
public String redirect(@RequestParam String url) {
    return "redirect:" + url;
}
```

### 4.2.3 漏洞修复方案

**安全修复代码：**
```java
@RequestMapping("/redirect")
public String redirect(@RequestParam String url) {
    // 白名单验证
    List<String> allowedDomains = Arrays.asList(
        "example.com", "www.example.com", "secure.example.com"
    );

    try {
        URL redirectUrl = new URL(url);
        String domain = redirectUrl.getHost();

        if (allowedDomains.contains(domain)) {
            return "redirect:" + url;
        } else {
            throw new SecurityException("Redirect not allowed");
        }
    } catch (MalformedURLException e) {
        throw new SecurityException("Invalid URL");
    }
}
```

---

## 4.3 SQL注入漏洞

### 4.3.1 漏洞描述

SQL注入是一种代码注入技术，攻击者通过在应用程序的输入字段中插入恶意SQL代码，欺骗数据库服务器执行非预期的SQL语句，从而导致数据泄露、数据篡改或数据库服务器被控制。

### 4.3.2 漏洞代码及审计过程

**漏洞代码示例：**
```java
public User authenticate(String username, String password) {
    String query = "SELECT * FROM users WHERE username = '" +
                   username + "' AND password = '" + password + "'";
    Statement stmt = connection.createStatement();
    ResultSet rs = stmt.executeQuery(query);
    // 处理结果
}
```

### 4.3.3 漏洞修复方案

**安全修复代码：**
```java
public User authenticate(String username, String password) {
    String query = "SELECT * FROM users WHERE username = ? AND password = ?";
    PreparedStatement pstmt = connection.prepareStatement(query);
    pstmt.setString(1, username);
    pstmt.setString(2, password);
    ResultSet rs = pstmt.executeQuery();
    // 处理结果
}
```

---

## 4.4 XSS漏洞

### 4.4.1 漏洞描述

跨站脚本攻击（XSS）是一种客户端攻击，攻击者通过在Web页面中注入恶意脚本，当其他用户访问该页面时，恶意脚本会在用户浏览器中执行，从而窃取用户信息或执行恶意操作。

### 4.4.2 漏洞代码及审计过程

**漏洞代码示例：**
```java
@RequestMapping("/comment")
public String addComment(@RequestParam String comment, Model model) {
    model.addAttribute("comment", comment);
    return "comment";
}
```

### 4.4.3 漏洞修复方案

**安全修复代码：**
```java
@RequestMapping("/comment")
public String addComment(@RequestParam String comment, Model model) {
    // HTML转义
    String escapedComment = StringEscapeUtils.escapeHtml4(comment);
    model.addAttribute("comment", escapedComment);
    return "comment";
}
```

---

## 4.5 XXE漏洞

### 4.5.1 漏洞描述

XML外部实体（XXE）攻击是一种利用XML解析器功能的攻击方式，攻击者可以通过恶意XML文档访问服务器上的文件、执行SSRF攻击或拒绝服务攻击。

### 4.5.2 漏洞代码及审计过程

**漏洞代码示例：**
```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(new File("user_input.xml"));
```

### 4.5.3 漏洞修复方案

**安全修复代码：**
```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
// 禁用外部实体
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);

DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(new File("user_input.xml"));
```

---

## 4.6 任意文件上传漏洞

### 4.6.1 漏洞描述

任意文件上传漏洞是指Web应用程序允许用户上传文件，但没有对文件类型、大小或内容进行适当验证，导致攻击者可以上传恶意文件，如Web Shell、病毒等。

### 4.6.2 漏洞代码及审计过程

**漏洞代码示例：**
```java
@PostMapping("/upload")
public String handleUpload(@RequestParam MultipartFile file) {
    String fileName = file.getOriginalFilename();
    File dest = new File("/uploads/" + fileName);
    file.transferTo(dest);
    return "success";
}
```

### 4.6.3 漏洞修复方案

**安全修复代码：**
```java
@PostMapping("/upload")
public String handleUpload(@RequestParam MultipartFile file) {
    String fileName = file.getOriginalFilename();

    // 文件名验证
    if (!isValidFileName(fileName)) {
        throw new SecurityException("Invalid file name");
    }

    // 文件类型验证
    String contentType = file.getContentType();
    if (!ALLOWED_CONTENT_TYPES.contains(contentType)) {
        throw new SecurityException("File type not allowed");
    }

    // 生成安全文件名
    String safeFileName = generateSafeFileName(fileName);
    File dest = new File(UPLOAD_DIR, safeFileName);

    file.transferTo(dest);
    return "success";
}
```

---

## 4.7 Java反序列化漏洞

### 4.7.1 漏洞描述

Java反序列化漏洞是指当应用程序接受不受信任的数据并进行反序列化时，攻击者可以构造恶意的序列化数据，在反序列化过程中执行任意代码，导致远程代码执行。

### 4.7.2 漏洞代码及审计过程

**漏洞代码示例：**
```java
public Object deserializeObject(byte[] data) {
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
    return ois.readObject();
}
```

### 4.7.3 漏洞修复方案

**安全修复代码：**
```java
public Object deserializeObject(byte[] data) {
    try {
        // 使用安全的反序列化
        ObjectInputStream ois = new SerialKiller(new ByteArrayInputStream(data), "serialkiller.conf");
        return ois.readObject();
    } catch (InvalidClassException e) {
        throw new SecurityException("Blocked deserialization attempt");
    }
}
```

---

## 4.8 命令注入漏洞

### 4.8.1 漏洞描述

命令注入漏洞是指应用程序在构造系统命令时使用用户输入，没有进行适当的过滤和验证，导致攻击者可以注入恶意命令，在服务器上执行任意系统命令。

### 4.8.2 漏洞代码及审计过程

**漏洞代码示例：**
```java
public String executeCommand(String userInput) {
    String command = "ls " + userInput;
    Process process = Runtime.getRuntime().exec(command);
    // 处理输出
}
```

### 4.8.3 漏洞修复方案

**安全修复代码：**
```java
public String executeCommand(String userInput) {
    // 白名单验证
    if (!userInput.matches("[a-zA-Z0-9._-]+")) {
        throw new SecurityException("Invalid input");
    }

    // 使用参数化命令执行
    String[] command = {"ls", userInput};
    Process process = Runtime.getRuntime().exec(command);
    // 处理输出
}
```

---

## 4.9 SpEL注入漏洞

### 4.9.1 漏洞描述

Spring Expression Language（SpEL）注入漏洞是指应用程序使用用户输入构造SpEL表达式，没有进行适当的验证，导致攻击者可以注入恶意表达式，执行任意代码或访问敏感信息。

### 4.9.2 漏洞代码及审计过程

**漏洞代码示例：**
```java
public String processExpression(String expression) {
    ExpressionParser parser = new SpelExpressionParser();
    Expression exp = parser.parseExpression(expression);
    return exp.getValue().toString();
}
```

### 4.9.3 漏洞修复方案

**安全修复代码：**
```java
public String processExpression(String expression) {
    // 使用SimpleEvaluationContext限制功能
    ExpressionParser parser = new SpelExpressionParser();
    EvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
    Expression exp = parser.parseExpression(expression);
    return exp.getValue(context, String.class);
}
```

---

## 4.10 SSRF漏洞

### 4.10.1 漏洞描述

服务端请求伪造（SSRF）漏洞是指攻击者可以迫使服务器向攻击者指定的内部或外部资源发起请求，从而探测内网、访问内部服务或窃取敏感信息。

### 4.10.2 漏洞代码及审计过程

**漏洞代码示例：**
```java
public String fetchUrl(String url) {
    URL targetUrl = new URL(url);
    HttpURLConnection connection = (HttpURLConnection) targetUrl.openConnection();
    // 读取响应
}
```

### 4.10.3 漏洞修复方案

**安全修复代码：**
```java
public String fetchUrl(String url) {
    URL targetUrl = new URL(url);
    String protocol = targetUrl.getProtocol();
    String host = targetUrl.getHost();

    // 协议白名单
    if (!Arrays.asList("http", "https").contains(protocol)) {
        throw new SecurityException("Protocol not allowed");
    }

    // IP地址黑名单检查
    if (isInternalAddress(host)) {
        throw new SecurityException("Internal access not allowed");
    }

    HttpURLConnection connection = (HttpURLConnection) targetUrl.openConnection();
    // 设置超时和限制
    connection.setConnectTimeout(5000);
    connection.setReadTimeout(5000);
    // 读取响应
}
```

---

## 4.11 敏感信息泄露

### 4.11.1 漏洞描述

敏感信息泄露是指应用程序在错误处理、日志记录或响应中暴露了敏感信息，如密码、密钥、令牌、系统路径等，为攻击者提供了有价值的信息。

### 4.11.2 漏洞代码及审计过程

**漏洞代码示例：**
```java
try {
    // 业务逻辑
} catch (Exception e) {
    e.printStackTrace(); // 直接打印异常堆栈
    return "Error: " + e.getMessage();
}
```

### 4.11.3 漏洞修复方案

**安全修复代码：**
```java
try {
    // 业务逻辑
} catch (Exception e) {
    // 记录详细的错误信息到日志
    logger.error("Business operation failed", e);
    // 返回通用的错误信息给用户
    return "An error occurred. Please try again later.";
}
```

---

## 4.12 权限控制漏洞

### 4.12.1 漏洞描述

权限控制漏洞是指应用程序没有正确实施访问控制机制，允许用户访问他们无权访问的功能或数据，包括垂直权限提升（普通用户获得管理员权限）和水平权限提升（访问其他用户的数据）。

### 4.12.2 漏洞代码及审计过程

**漏洞代码示例：**
```java
@RequestMapping("/admin/data")
public String getAdminData() {
    // 没有权限检查
    return adminService.get sensitiveData();
}
```

### 4.12.3 漏洞修复方案

**安全修复代码：**
```java
@PreAuthorize("hasRole('ADMIN')")
@RequestMapping("/admin/data")
public String getAdminData() {
    return adminService.getSensitiveData();
}

// 或者手动检查权限
@RequestMapping("/user/profile/{userId}")
public String getUserProfile(@PathVariable String userId) {
    // 检查用户是否有权限访问该用户资料
    if (!currentUser.canAccessUser(userId)) {
        throw new AccessDeniedException("Access denied");
    }
    return userService.getUserProfile(userId);
}
```

---

## 4.13 加密机制失效漏洞

### 4.13.1 漏洞描述

加密机制失效漏洞是指应用程序使用了弱加密算法、错误的密钥管理或不安全的随机数生成，导致加密保护形同虚设，攻击者可以轻易破解加密数据。

### 4.13.2 漏洞代码及审计过程

**漏洞代码示例：**
```java
// 使用弱加密算法
MessageDigest md5 = MessageDigest.getInstance("MD5");
byte[] hash = md5.digest(data.getBytes());

// 使用不安全的随机数生成器
Random random = new Random(); // 基于时间，可预测
```

### 4.13.3 漏洞修复方案

**安全修复代码：**
```java
// 使用强加密算法
MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
byte[] hash = sha256.digest(data.getBytes());

// 使用安全的随机数生成器
SecureRandom secureRandom = SecureRandom.getInstanceStrong();
```

---

## 4.14 ThreadLocal内存泄漏

### 4.14.1 漏洞描述

ThreadLocal内存泄漏是指在使用ThreadLocal时，没有正确清理线程本地变量，特别是在线程池环境下，导致内存泄漏和潜在的安全问题。

### 4.14.2 漏洞代码及审计过程

**漏洞代码示例：**
```java
public class UserContextHolder {
    private static final ThreadLocal<User> userContext = new ThreadLocal<>();

    public static void setUser(User user) {
        userContext.set(user);
    }

    // 没有remove方法，可能导致内存泄漏
}
```

### 4.14.3 漏洞修复方案

**安全修复代码：**
```java
public class UserContextHolder {
    private static final ThreadLocal<User> userContext = new ThreadLocal<>();

    public static void setUser(User user) {
        userContext.set(user);
    }

    public static void clear() {
        userContext.remove(); // 必须清理
    }

    // 使用try-with-resources模式
    public static void executeWithContext(User user, Runnable task) {
        try {
            setUser(user);
            task.run();
        } finally {
            clear(); // 确保清理
        }
    }
}
```