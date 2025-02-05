# Malicious IP Addresses

These are the IP addresses identified as malicious by our firewall and intrusion detection systems. All the IP addresses listed here originate from French sources and have been involved in a range of targeted cyberattacks against our web servers.

## Summary

The attacks were flagged by our security infrastructure, leveraging a variety of advanced detection techniques. Each of these IP addresses was actively involved in exploiting vulnerabilities in services and devices, leading to potential breaches or service disruptions. The identified malicious activities include unauthorized attempts to exploit known software vulnerabilities, as well as malware attacks aimed at gaining unauthorized access or executing remote code.

## Malware and Exploits Detected:

- **OpenSSL Heartbleed Attack (CVE-2014-0160)**: An infamous vulnerability in the OpenSSL cryptographic software library, which allows attackers to steal information protected by SSL/TLS encryption.
- **NETGEAR DGN1000 CGI Unauthenticated Remote Code Execution**: A vulnerability in NETGEAR routers that allows remote attackers to execute arbitrary code without authentication.
- **AndroxGh0st Malware**: A potent malware variant that is often used in advanced persistent threats, allowing for remote command execution, data theft, and system control.
- **Zyxel zhttpd Webserver Command Injection**: A vulnerability in Zyxel's zhttpd webserver that permits remote attackers to execute arbitrary system commands, leading to complete system compromise.
- **Apache.HTTP.Server.cgi-bin.Path.Traversal**: The vulnerability is due to a path normalisation error in Apache HTTP Server. Successful exploitation can potentially lead to information disclosure.

## Purpose of this List

The primary objective of this repository is to share the list of IP addresses involved in these attacks, which can be used by other security teams or network administrators to bolster their defensive strategies. By blocking these IP addresses or monitoring their activity, organizations can better protect their web applications and infrastructure.

**Note**: This list is updated periodically based on new threats detected by our firewall.

## Recommendations:

If any of these IP addresses are detected in your logs, we recommend:
1. Blocking these IP addresses at the network level (e.g., firewall, IDS/IPS).
2. Monitoring your logs and systems for any signs of compromise if these IPs were involved in previous activity.
3. Applying patches or updates to the software and devices mentioned above, especially if they have known vulnerabilities.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

The use of this list is at your own risk. While every effort has been made to ensure the accuracy of the information provided, we cannot guarantee that all IPs are still active or involved in malicious activities at the time of consultation.
