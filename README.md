# --- How To Investigate PCAPs in an SOC ---
For this lab, I wanted to envision myself in a scenario where I am working in a SOC, and a client asks me to investigate a 
suspicious PCAP. What would I do? What questions will I ask? What answers will I provide?

Most importantly: **How will my escalation/response to the client look?**

Here is the scenario in more detail: 

![Image 1](https://github.com/quadicyber/PCAP-Investigation/assets/104177919/3980b285-60ee-48cc-ac04-464be7996caa)

An internal host should not be scanning another host unless it is an authorized host being used for vulnerability scanning.

*(For this lab I will be using a Windows 10 VM with Wireshark installed on it.)*

--- 
Upon opening Wireshark and looking at the Capture File Properties, I noticed that the total time elapsed of the packet capture 
was around 15 minutes. I can use this information to verify with the client, saying something along the lines of **"The PCAP
you provided me is within a 15 minute time frame, is that correct?"** 

![Image 2](https://github.com/quadicyber/PCAP-Investigation/assets/104177919/4f27e34c-2d19-4ede-a1d5-027405453f5a)

I then took a look at the Protocol Hierarchy Statistics, and I noted that protocols such as **SSH, SMB, DNS** and **HTTP** were in use. Why these?
All of these protocols have the potential for lateral movement opportunities, as well as HTTP being a cleartext protocol.

![Image 3](https://github.com/quadicyber/PCAP-Investigation/assets/104177919/c37bcff7-bd74-419e-8c66-fe47c4a9e7d1)

I then took a look at the IPv4 tab in Conversations, and sorted it by bytes. I kept tabs on the the top 2 conversations, 
starting with **10.251.96.4 -> 10.251.96.5**, and also **172.20.10.7 -> 172.20.10.2.** 

Upon looking at the TCP tab in Conversations, I noticed something odd: The source IP **10.251.96.4:41675** appears to be hitting 
a lot of ports going toward the destination IP **10.251.96.5.** The ports should be the same, so this is indicative of port
scanning activity. I also noticed that on **Ports 80 and 22**, instead of the 118 bytes seen in other conversations, these ports
were 184 bytes in size, likely because of the destination IP responding with SYN-ACK packets. It is likely that **Ports 22** and
**80** on IP **10.251.96.5** are open. 

![Image 4](https://github.com/quadicyber/PCAP-Investigation/assets/104177919/6ffea590-89a9-436f-947a-d133dcbf2226)


--- 

![Image 5](https://github.com/quadicyber/PCAP-Investigation/assets/104177919/3c5972e0-1f42-4cfd-bc69-1a10b6e1515c)


This capture in particular also caught my attention, as **10.251.96.5** called back to **10.251.96.4** on **Port 4422**, leading me to 
think it could possibly be some kind of program.

Since both **10.251.96.5** and **172.20.10.2** have port 80 open, at this point I am thinking they may be a web server of some kind,
but I needed to verify that thought.

So I followed the TCP stream from the first HTTP packet in the PCAP *(Packet 14)*, and I was able to see that IP **172.20.10.2** is 
an Ubuntu Server.

![Image 6](https://github.com/quadicyber/PCAP-Investigation/assets/104177919/3cb2e78b-4527-465f-92b5-e39d64fec8d9)


*Packet 38* is a POST request, and upon looking at the HTTP stream I can see a login with the username *admin* and the password
*Admin%401234*. (%40 decoding is the @ symbol, so the password is *Admin@1234*.

![Image 7](https://github.com/quadicyber/PCAP-Investigation/assets/104177919/ec9bfefc-858f-4900-84ea-c4fb02107f37)

--- 

The first port scan attempt is on *Packet 117*, which happened on **February 7, 2021 at 16:33:06 PM**, from IP
**10.251.96.4 -> 10.251.96.5,** and all of the red packets are resets. There are also a couple of [SYN, ACK] packets at packet
134 and 151, on **Ports 80 and 22** respectively. The last scan was on *Packet 2165*, and lasted not even one second, so the port
scan happened very fast.

![Image 8](https://github.com/quadicyber/PCAP-Investigation/assets/104177919/354de360-a8fd-437e-8352-020606f62c8b)

I also noticed in one GET request in *Packet 2215* that the user-agent was **gobuster/3.0.1**, which is a tool that can 
crawl directories.

I queried Wireshark for HTTP response code 200 and Source IP **10.251.96.5** to see all the instances where the web server 
replied. When I did this, I took a look at the length column and noticed that most were between
500 - 900, but there were a couple of anomalies on *Packets 7725* and *13894* where the length field was very large in 
comparison.

![Image 9](https://github.com/quadicyber/PCAP-Investigation/assets/104177919/d1960dc1-9f06-47ea-92ef-6da99b554f49)
  
Upon looking at the HTTP stream for *Packet 7725*, the server responsed with a lot of php info, including the version info. This can be used
by the attacker to look for an exploit to try and take advantage of. This user-agent was GoBuster, contrasted with the second
packet I took a look at *(Packet 13894)*, where the user-agent was Mozilla 5.0, so perhaps someone manually accessed that 
directory.

I noted that GoBuster finished around **16:34:06**, about 60 seconds after the first port scan attempt. I also note that there
appears to be an uploads directory on the Ubuntu Server, evidenced by *Packet 13914.* 

![Image 10](https://github.com/quadicyber/PCAP-Investigation/assets/104177919/b3fa52d4-a5b4-4ac7-a13c-698d2847b3da)

---

On *Packet 13979* there appears to be a successful upload attempt. The user-agent is **sqlmap/1.4.7** which is a tool that 
performs automated SQL attacks. 

![Image 11](https://github.com/quadicyber/PCAP-Investigation/assets/104177919/1b45d6ad-9f96-4629-b289-e08c22b3be2b)

*Packet 14060* clearly shows some form of encoded SQL attack. 

![Image 12](https://github.com/quadicyber/PCAP-Investigation/assets/104177919/0c903e54-885b-41fa-a1dc-4d4ac54d249d)
 
Upon decoding, it reads: 

![Image 13](https://github.com/quadicyber/PCAP-Investigation/assets/104177919/7265e4e2-bff0-413e-8119-193f76f2435e)


It even includes a test to see if there is any cross-site-scripting. The objective is to open up a shell to read the
**/etc/passwd** directory, evidenced by the *cat* command.

*Packet 15978* marks the end of the SQL map attack, which was at **16:37:28.** I can see that the attacker uploaded a file named
*dbfunction.php* in *Packet 16102*, which occurred at **16:40:39.** They referred to the *upload.php* via *editprofile.php*. 

---

I tried to visualize this from the attacker's POV, and I am thinking that they clicked on *Edit Profile* and there must be
an upload button, and started uploading the *dbfunction.php* file, and it was successfully uploaded. 

![Image 14](https://github.com/quadicyber/PCAP-Investigation/assets/104177919/0a2a75ea-5513-4f3c-bee7-2584224f2f4f)


There is a whoami command in *Packet 16144* at **16:40:56**, followed by another encoded command in *Packet 16201* at **16:42:35.** 
After decoding, it turns out the attacker is using Python with an import, and some kind of connection to **10.251.96.4** on **Port 
4422**, and they want to call a subprocess of *bin/sh -i* 

![Image 15](https://github.com/quadicyber/PCAP-Investigation/assets/104177919/693e3320-f5cf-4d82-a518-7cd7df1a2a1b)

The next logical step is to see if there was any callback towards that IP on **Port 4422**, and there was as evidenced by a trio
of packets completing the TCP handshake at **16:42:35.**

![Image 16](https://github.com/quadicyber/PCAP-Investigation/assets/104177919/6a315ef1-f0d9-4eaa-86f4-6f7900136d61)

Looking at the TCP stream I definitely saw a successful web shell where the attacker has hands-on keyboard access to the web
server, evidenced by **bash -i, cd**, and other discovery commands.

![Image 17](https://github.com/quadicyber/PCAP-Investigation/assets/104177919/44d96944-ab17-43d5-94c7-9d2b07a83389)

--- 

## ---Final Notes --- 

For the IP **10.251.96.5**, the username is *www-data* and the hostname is *bob-appserver*.
Port scan activity started and ended on **2021-02-07 16:33:06** from source IP **10.251.96.4:41675** to destination IP 
**10.251.96.5** (**Ports 22** and **80** were opened). **Ports 1 - 1024** were scanned.
- **Gobuster 3.0.1** was used by **10.251.96.4** starting at **2021-02-07 16:34:05** and ending at **2021-02-07 16:34:06.**
- **sqlmap 1.4.7** was also used, starting at **2021-02-07 16:36:17** and ending at **2021-02-07 16:37:28.**

A web shell function named *dbfunction.php* was successfully uploaded at **2021-02-07 16:40:39** from source IP **10.251.96.4** to
destination IP **10.251.96.5.**
- The attacker ran the commands **id, whoami,** and a python script for callback via the web shell. 

A successful callback was established via a TCP reverse shell starting at **2021-02-07 16:42:35** from IP **10.251.96.5** to 
**10.251.96.5:4422.**
- Commands run from the webserver via the TCP reverse shell include: **bash -i. whoami, cd, ls, python**, and **rm db**

The last observed activity from **10.251.96.4** was on **2021-02-07 16:45:56.** 

Now to answer the main question that I asked myself at the beginning of this lab, here is what my response to the client would be
after investigation, formatted in an email.

---

![Image 18](https://github.com/quadicyber/PCAP-Investigation/assets/104177919/cdfe693c-305d-4494-8e36-57d5e63e4142)
