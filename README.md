> I will document this as a single attack, even though it involves two types of brute force attacks.
> 

# Root Password Brute Force attack :

it started when i noticed an alert on my wazuh dashboard, because wazuh already had a rule that alerts against this attack method  `5763 - SSHD brute force trying to get access to the system`

and i only has to write an active response for when this rule is triggered 

## Wazuh : Adding the block below to the configuration
`/var/ossec/etc/ossec.conf`

```xml
<ossec_config>
  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>5763</rules_id>
    <timeout>14400</timeout>
  </active-response>
</ossec_config>
```

and this should be enough to block the ips that will try to brute force ssh connection.

---

btw if your wazuh rules does not contain the rule specified at the beginning hers how you can emulate its behaviour.

Add the following to a custom rules file, such as `/var/ossec/rules/local_rules.xml`:

```xml
<group name="sshd, brute_force, authentication">
  <rule id="5763" level="10">
    <decoded_as>json</decoded_as>
    <field name="system.auth.program">sshd</field>
    <match>Failed password</match>
    <description>SSHD brute force attempt detected</description>
    <options>no_full_log</options>
    <frequency>3</frequency>
    <timeframe>60</timeframe>
    <group>authentication_failed, sshd</group>
    <fired_times>3</fired_times>
    <tags>
      <tag>ssh</tag>
      <tag>brute_force</tag>
    </tags>
  </rule>
</group>
```

---

## FAIL2BAN:

and i have also search for a proactive way to be able to automatically block the threat of a ssh brute force attack without getting a SIEM alert and i’ve found a wonderful tool named  `fail2ban`
you can look at the web and get to know it more cz it’s a very useful and very practical
and hers the rule you need to set for it to be able to deny any brutes force attempts via ssh on your machine.

Adjust the configuration in `/etc/fail2ban/jail.local`:

```
[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 5
bantime = 14400
```

NOTE : you wont fine this file name if your haven't used it before so just create it and write your conf there, and make sure not to modify the `/etc/fail2ban/jail.conf` .

## Snort:

To configure Snort to detect SSH password brute-force attacks, you need to write and deploy custom rules that identify patterns of repeated login attempts over a short period. Below are detailed steps for setting up Snort to detect such attacks.

---

Add this rule to the **local.rules** file, typically located at `/etc/snort/rules/local.rules`:

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt"; flow:to_server,established; content:"Failed password"; nocase; detection_filter:track by_src, count 5, seconds 60; sid:1000020; rev:1;)
```

NOTE : you can switch from monitoring to actively responding by changing they rule from 
**alert to reject or deny** 

**Deny** is similar to **reject** in that it blocks the offending traffic.
However, the key difference is that **deny** drops the packet silently. Unlike **reject**, it does not send a **TCP RST** or **ICMP port unreachable** message to the sender. The attacker will experience a timeout, as though the packet was lost in the network.

**Comparing Rule Types**

| **Rule Type** | **Action** | **Best Use Case** |
| --- | --- | --- |
| **`alert`** | Logs and alerts but doesn't block. | Monitoring and logging activities. |
| **`reject`** | Logs, alerts, and blocks with a response. | Actively prevent attacks but reveal detection. |
| **`deny`** | Logs, alerts, and silently blocks. | Stealthy blocking without feedback. |

---

# SSH User Brute Force:

## Using Wazuh:

after we detected the password brute force attack and blocked it they tried to brute force users as well but we’ve been able to detect that as well thanks to the rule `5700 - SSHD Attempt to login using a non-existent user`

```xml
  <rule id="5710" level="5">
    <if_sid>5700</if_sid>
    <match>illegal user|invalid user</match>
    <description>sshd: Attempt to login using a non-existent user</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>invalid_login,authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,pci_dss_10.6.1,gpg13_7.1,gdpr_IV_35.7.d,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,nist_800_53_AU.6,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule
```

and we’ve responded by just adding this rule id to the active response rule we’ve created earlier and now Wazuh can defend automatically against both attacks in the same way
 

```xml
<ossec_config>
  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>5763,5700</rules_id>
    <timeout>14400</timeout>
  </active-response>
</ossec_config>
```

## Using Snort:

using snort you can also detect the same attack by deploying this rule to the snort configuration file 

Create a rule that searches for the phrase **"Invalid user"** in traffic destined for the SSH port (`22`), at  `/etc/snort/rules/local.rules`:

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SSH Login Attempt with Non-Existent User"; flow:to_server,established; content:"Invalid user"; nocase; sid:1000021; rev:1;)
```

Additionally, you can leverage **deny** or **reject** rules in your security configuration to actively respond to such alerts in real-time. These rules allow you to automatically block or drop connections from malicious sources as soon as the system identifies suspicious activity. Alternatively, you have the flexibility to create and deploy your own scripts or custom code to handle these responses, enabling tailored solutions for your environment.

This explanation was relatively brief because brute force attacks are straightforward to detect and defend against, given their predictable patterns and the availability of robust tools designed to mitigate such threats effectively.
