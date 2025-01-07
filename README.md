For this assignment, I collaborated with Scapy, Piazza, Stackoverflow, and ChatGPT.

A few articles/websites that were also helpful were:
https://resources.infosecinstitute.com/topics/hacking/port-scanning-using-scapy/.

https://www.uv.mx/personal/angelperez/files/2018/10/scanning_texto.pdf

I consulted with Stackoverflow and ChatGPT to understand what types of codes to add
for each specific scan. While Stackoverflow and ChatGPT helped me understand what
codes to add, I made sure the codes were detailed so I could understand each line.
For instance, I made sure to add specific flags for the Xmas and Fin scans so I
could understand the characteristics of each scan.

I spent approximately 10 hours working on this assignment. The majority of the time
was spent understanding what codes to implement and checking if it worked.
Additionally, I spent a lot of time checking for usernames and passwords sent in-
the-clear via HTTP Basic Authentication, FTP, and IMAP.
The dependencies I used for this code were scapy, argparse, and base64.
For the most part, I was able to run all the scans. I struggled the most in
checking for usernames and passwords sent in-the-clear via HTTP Basic, since
set2.pcap uses port 8000 and set3.pcap uses port 80. I also noticed that after I
fixed the code, one username-password set in set2.pcap was not showing in my scan,
which was pret:$string76Minimal. This can be a limitation to scanning incidents, in
the sense that some credentials may be overlooked.

I think the heuristics used in this assignment are moderate in detecting the
specified incidents. There are some limitations as I mentioned earlier with missing
some credentials in the set2.pcap scan. Additionally, since we are seeing a lot of
duplicates when running the scans, there could be some false positives in the mix.
There's also the possibility of overlooking other suspicious or malicious activity
in these scans. While these scans can detect incidents, it does not tell you much
detail about the attacker. There are some opportunities to implement
additional processes to get better results. While the current approach targets
specific criteria, such as TCP flags or looking into specific words ("USER",
"HTTP", etc.), broader benchmarks could be used in identifying incidents. Adding
real-time data like when these attacks occurred, checking what scans were conducted
first, and checking how many attempts were made, are some ways to set (new)
patterns and understand an attacker's behaviors. Similar to Lab 3 in hacking into a
honeypot, it would be interesting to do something similar for these types of scan,
such as being able to detect the attackers' location, their IP address, how many
attempts were made, what time ranges these scans occurred the most, etc.

In detecting these scans, I would try to print out the incidents
without duplicates to keep my analysis simpler and avoid any possible false
positives. Additionally, I would try to work on making the HTTP scan on ports 80
and 8000 simpler and concise. I will look more into why that credential I
mentioned earlier was missed in the set2.pcap scan as well. Moreover, I would look
more into network traffic and see if there are any other vulnerabilities.
