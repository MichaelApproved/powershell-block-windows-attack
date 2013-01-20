Powershell to block windows brute force attack attempts
=======================

This Powershell script will block the IP addresses of those who repeatedly enter the wrong Windows account credentials (username/password). It’ll scan old security events, look for 10 failed attempts in the last 24 hours and then add them to an existing “BlockAttackers” Windows firewall rule.

You can schedule this script to run on a fixed schedule (every few minutes, hours, once a day, etc.) or you can schedule it to run when a failed login attempt happens. I like to run it after every failed login attempt so it stops the attacker right away.

To schedule based on failed login attempt:

1. Use a trigger that begins the task “On an event”
2. Select “Security” as the log.
3. Enter 4625 as the “Event ID”

A good tip is to create the "BlockAttackers" rule that blocks the IP addresses but **do not enable it at first**. Then, run this script once manually so it can populate the "RemoteAddresses" field with actual IP addresses that should be blocked. Take a look at those IP addresses to make sure nothing critical has been added and then enable the firewall rule.

**!!! Do not enable the firewall rule without having at least 1 IP address in the RemoteAddresses or the rule could block all traffic to your server.**

This script builds on an existing [Serverfault.com answer by remunda](http://serverfault.com/a/397637/155102) but it goes a little further and accounts for the "BlockAttackers" rule not having any IPs entered yet (which returns a "*" as a string). It also writes a comment to a log file to let you know when the IP was added to the rule.

If you’d like to contribute, a good place to start would be to the logging. It’d be great if the script could add an event log that an IP has been blocked, instead of just writing to a log file.
