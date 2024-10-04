
# Operating Systems Security - Notes

---

## 1. Access Control and Authentication

### 1.1 Access Control

Access Control is a fundamental security feature in operating systems, ensuring that only authorized users can access certain resources. It involves managing permissions and policies that dictate who can perform actions on system objects (files, processes, etc.).

#### Types of Access Control:

- **Discretionary Access Control (DAC)**:
    In DAC, the owner of a resource decides who can access it and what operations (read, write, execute) are permitted. Users can delegate access to others at their discretion.
    
    Example: Unix file permissions, where the file owner can assign read (`r`), write (`w`), and execute (`x`) permissions to the owner, group, and others.

- **Mandatory Access Control (MAC)**:
    Under MAC, the OS enforces access control policies based on predefined rules, and users have no ability to alter these rules. MAC is often used in environments where security is critical (e.g., government systems).
    
    Example: Security levels in classified government systems where information can only be accessed by users with the required clearance level.

- **Role-Based Access Control (RBAC)**:
    Access is assigned based on the roles within an organization. A user can be assigned one or more roles, and each role has specific permissions associated with it.
    
    Example: A system administrator role may have access to all system settings, while a regular user role has limited access to files and applications.

### 1.2 Authentication

Authentication is the process of verifying the identity of a user before granting them access to the system. It ensures that only legitimate users can log into the system.

#### Methods of Authentication:

- **Password-Based Authentication**:
    The most common form of authentication, where a user provides a password to prove their identity.
    
    _Security Tip_: Passwords should be stored as hashes rather than plain text. Hashing converts the password into a fixed-size string of characters, making it harder for attackers to retrieve the original password if the hash is stolen.

- **Two-Factor Authentication (2FA)**:
    Increases security by requiring two separate forms of authentication, typically something the user knows (password) and something the user has (OTP, security token, or mobile phone).
    
    Example: After entering a password, the system sends a one-time passcode (OTP) to the user's phone that must be entered to complete the login.

- **Biometric Authentication**:
    Uses unique biological characteristics, such as fingerprints, facial recognition, or retina scans, to authenticate users.
    
    Example: Many smartphones now use fingerprint or facial recognition technology to unlock the device.

---

## 2. Secure OS Design and Implementation

### 2.1 Principles of Secure OS Design

A secure operating system is designed with core security principles in mind to prevent exploitation and minimize vulnerabilities.

#### Key Security Principles:

- **Least Privilege**:
    Users and processes should operate with the minimum set of permissions needed to perform their tasks. This reduces the potential damage that can be caused if a user or application is compromised.

- **Separation of Privilege**:
    Different privileges should be granted based on different conditions. For example, administrative tasks may require authentication from multiple sources or roles.

- **Economy of Mechanism**:
    The system's security mechanisms should be as simple as possible. Complex mechanisms can introduce bugs and vulnerabilities, so simplicity leads to easier verification and a more secure design.

- **Complete Mediation**:
    Every request to access a resource must be checked against security policies. This ensures that there are no "back doors" or unprotected paths to access critical system resources.

---

### 2.2 Techniques for Secure Implementation

- **Kernel Security**:
    The kernel is the core part of the operating system that controls system operations and manages hardware. It is crucial to protect the kernel from vulnerabilities like buffer overflow attacks, which could allow attackers to execute arbitrary code with high-level privileges.

- **Security Policies and Modules**:
    - **SELinux (Security-Enhanced Linux)**: A Linux security module that enforces mandatory access control policies, limiting how processes interact with the system and each other. It provides fine-grained control over which resources each process can access.
    - **AppArmor**: Another Linux security module that restricts the capabilities of individual programs by defining profiles, limiting what resources the programs can access.

- **Secure Boot**:
    Ensures that only trusted software is loaded during the startup process of the system. It prevents unauthorized or malicious operating systems or bootloaders from being executed, protecting the system from attacks at the most fundamental level.

---

## 3. Malware and Defense Mechanisms

### 3.1 Types of Malware

Malware is malicious software designed to damage, disrupt, or gain unauthorized access to systems. Understanding the different types of malware is essential to defending against them.

- **Virus**:
    A virus attaches itself to legitimate programs or files and spreads when those files are executed. It can cause damage to files, delete data, or corrupt system functions.

- **Worm**:
    Unlike a virus, a worm does not need to attach itself to a file. It spreads automatically across networks, exploiting vulnerabilities to infect systems without user intervention.

- **Trojan Horse**:
    A Trojan Horse disguises itself as legitimate software to trick users into installing it. Once installed, it can create a backdoor for attackers to access the system.

- **Ransomware**:
    Ransomware encrypts a user's files and demands a ransom in exchange for the decryption key. It is a serious threat that can lock users out of important data until they pay a fee, often in cryptocurrency.

- **Rootkit**:
    A rootkit is a set of tools that allows an attacker to gain and maintain administrative access to a system while remaining hidden from the user and security software.

---

### 3.2 Malware Detection Techniques

- **Signature-Based Detection**:
    Antivirus programs use known signatures of malware (specific patterns of code) to detect and remove it. This method is effective for known malware but ineffective against new, previously unseen malware (zero-day attacks).

- **Heuristic-Based Detection**:
    This method looks for suspicious behavior patterns rather than relying on known signatures. It is useful for detecting new or modified versions of malware, making it more versatile than signature-based detection.

- **Behavioral Detection**:
    This method monitors a system for abnormal activities, such as unusual network traffic or unexpected file changes. It is particularly useful in detecting ongoing attacks or unauthorized access.

---

### 3.3 Defense Mechanisms

- **Antivirus Software**:
    Antivirus programs scan files and system processes for known malware signatures and remove or quarantine them. Some antivirus software also uses heuristic and behavioral analysis to detect new threats.

- **Firewalls**:
    Firewalls control incoming and outgoing network traffic based on predetermined security rules. They block unauthorized access to the system from the network, acting as the first line of defense against external attacks.

- **Intrusion Detection and Prevention Systems (IDPS)**:
    - **Intrusion Detection System (IDS)**: Detects unauthorized activities or attacks in real-time by monitoring network traffic or system logs. It alerts administrators when suspicious activity is detected.
    
    - **Intrusion Prevention System (IPS)**: Blocks malicious traffic in real-time, preventing an attack from reaching its target.

- **Patch Management**:
    Regular updates to the operating system and applications fix security vulnerabilities and improve system defenses. Unpatched systems are vulnerable to exploits targeting known weaknesses.

- **Sandboxing**:
    Running untrusted programs in isolated environments (sandboxes) prevents them from affecting the rest of the system if they are malicious. If malware is present, it can only cause damage within the isolated sandbox environment.

---
