# How to get started with Wireshark

This walk through constitutes a short Wireshark demo to show TCP and UDP in action.

### Introduction <a href="#ember58" id="ember58"></a>

Using Packet Tracer’s simulation mode you can analyze packets to some extent, but not at the same level as Wireshark. Packet Tracer is a network simulator but Wireshark is a packet capture program that lets you analyze network traffic. Wireshark is useful for education and training and is also a very useful network analysis and troubleshooting tool.

Although there is a lot you can learn about Wireshark, it’s quite easy to get started using it.

Up here you can see the packets as they are sent or received by the network interface you are capturing traffic from:

<figure><img src="../../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

If you click on a packet you can see more details.

Note that this kind of software is called packet capture software. Packet is just a general term we use, it does not mean it only captures the Layer 3 PDU.

As you can see here, the entire frame is indeed captured.

\>Frame 1 here is not a L2 frame as we know it but rather the Physical Layer metadata

\>Ethernet II is the Layer 2 frame

\>Internet Protocol v4 is the Layer 3 network packet

\>Transmission Control Protocol (TCP) is the Layer 4 segment

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

At the end of this demonstration you will be asked to do a few basic tasks to try out in Wireshark, so you will need to download Wireshark if you want to do them.

To download Wireshark, go to wireshark.org. It’s totally free.

Download Wireshark: [https://www.wireshark.org/download.html](https://www.google.com/url?q=https://www.wireshark.org/download.html\&sa=D\&source=editors\&ust=1682055106447789\&usg=AOvVaw2-hb4fq_4CieVOaJUpnrqA)

### Wireshark demo <a href="#ember75" id="ember75"></a>

This is a walk through of an actual analysis of some of the traffic being sent and received by the network interface of a PC.

Open Wireshark and then head over to YouTube and play a video for a brief while (e.g., 45 seconds). We will look at how Wireshark captures the traffic being sent and received by the network interface of a PC.

When the capture starts you will see there is already a lot of network traffic going through the interface. When you start watching the video you will see some more traffic.

### Wireshark analysis <a href="#ember79" id="ember79"></a>

In fact, a lot of traffic went passing by when the video was played. Let’s analyze some of it.

<figure><img src="../../.gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>

Note that in Wireshark you are able to filter output. There are many ways you can do so.

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption><p>Source: Troubleshooting slow networks with Wireshark // wireshark filters // Wireshark performance - YouTube video</p></figcaption></figure>

Wireshark are decent people. They will let you know when you enter the wrong syntax for a filter. For example, to filter by IP address use ip.addr == ip address in dotted decimal (i.e., use two equal signs, not only one - the red code signals that the syntax is wrong).

<figure><img src="../../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

Here are some operators you can use to construct a filter. The top row and bottom row symbols are identical operators (they mean/do the same thing in a filter string):

<figure><img src="../../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

This tutorial is not about how to master Wireshark. Here we focus on getting a basic understanding of how Wireshark works.

If you want to learn how to use Wireshark at an advanced/professional level, check out the training resources at the end of this demo.

Back to our Wireshark analysis discussion.

Again, there are many ways you can filter output. Just notice that we filtered by the TCP port number, using the display filter: tcp.port==62652.

In the first message under Protocol in the output, you can see that TCP is the Layer 4 protocol being used.

Under Info you can see the source and destination ports. From 62652 to 443 in the first message, and reversed in the second message, which is the reply.

62652 is the random source port our PC selected from the ephemeral port range.

443 is the TCP port used by HTTPS (Hypertext Transfer Protocol Secure) to access webpages.

Look here, do you recognize this series of messages? SYN, SYN-ACK, followed by ACK.

<figure><img src="../../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

That’s the TCP 3-way handshake.

So, in these first three messages our PC and the remote server established a TCP connection.

You can also see the sequence number, acknowledgment number, and window length.

<figure><img src="../../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

We learned in the previous lesson on TCP and UDP ([Comparing TCP to UDP](https://itnetworkingskills.wordpress.com/2023/04/06/compare-tcp-udp/)) that the initial sequence number is randomly selected. So you may be thinking it is a big coincidence that 0 was randomly selected as the sequence number.

In Wireshark it is displayed as 0 here to make it easier to look at and understand, but that’s not the actual sequence number.

When we look further at the details of the segment you will see the real sequence number.

So sequence number 0 is acknowledged with 1, there’s the forward acknowledgment. Then our PC sends sequence number 1. Once again, these are not the real sequence numbers, Wireshark just displays them like this to make it easier to look at and analyze the data exchange.

Then there is the actual exchange of data here. Notice that most of these display SSL in the protocol column.

<figure><img src="../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

SSL is what gives the security to HTTPS, Hypertext Transfer Protocol Secure. TCP is still being used, but Wireshark displays SSL in the column here.

Finally, you can see the exchange of FINs and ACKs to terminate the connection at the end.

<figure><img src="../../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

You probably noticed that the flags are a little different than as introduced in the [TCP and UDP lesson](https://itnetworkingskills.wordpress.com/2023/04/06/compare-tcp-udp/) - there is an extra ACK in the first and third messages. There are some nuances to the connection termination process which you don’t need to worry about at the CCNA level. But remember the basic FIN, ACK, FIN, ACK sequence.

### TCP SYN message <a href="#ember112" id="ember112"></a>

Now let’s briefly look inside one of those segments.

This is the very first SYN message at the beginning of the three-way handshake. First up, notice that the segment is of course encapsulated in an Ethernet frame and IP packet.

<figure><img src="../../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

We’re just looking deeper than we did before, but don’t forget about Layers 2 and 3.

Notice the sequence number here.

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

Notice that 0 is the relative sequence number. Wireshark does this to make it easier to analyze the traffic. Below you can see the real sequence number. As you can probably imagine, it is much harder to analyze when using sequence and acknowledgment numbers like 1 billion 224 million 315 thousand 781.

Because this is a SYN message, under the flags section you can see that the SYN bit is set, it’s 1.

<figure><img src="../../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

All of the other flags are not set, they are 0.

Finally, you can see the TCP window size down below, i.e., “Window size value: 64240”.

### UDP message <a href="#ember124" id="ember124"></a>

Before wrapping up this brief demonstration let’s look at a UDP segment.

<figure><img src="../../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

First up, notice under Protocol, DNS (Domain Name System). This is a DNS message from our PC to a DNS server.

So, what will the destination port be? As you can see, our PC selected a random source port from the ephemeral range, and used 53 as the destination port, because that’s the port number DNS uses.

Within the segment you can indeed see that a DNS message is encapsulated inside. This is a DNS query message. We will learn more about DNS later in the course.

### Getting started with Wireshark exercise <a href="#ember130" id="ember130"></a>

Here is a practice exercise for you to get familiar with Wireshark. Look inside some packet captures and see some of the things we studied in the TCP and UDP lesson.

1\) Download Wireshark from wireshark.org.

2\) Use it to capture network traffic sent and received by your PC.

3\) Visit some websites while Wireshark is running.

4\) Stop the Wireshark capture.

5\) Check out the packet captures, and find a TCP three-way handshake, a TCP connection establishment.

6\) Then find a TCP four-way handshake, a TCP connection termination.

### Resources for getting started with Wireshark/network troubleshooting <a href="#ember138" id="ember138"></a>

[1) 01 - Network Troubleshooting from Scratch | Learn Wireshark @ SF22US - SharkFest'22 US: July 9-14, Kansas City, MO - Presentation by Jasper Bongertz](https://www.youtube.com/watch?v=4hMT0kcW39g)

[2) Wireshark Training - Scroll down to User's Guide](https://www.wireshark.org/docs/)

[3) Getting Started With Wireshark - Initial Setup (video by Chris Greer)](https://www.youtube.com/watch?v=FHO8SdKighY)

[4) Getting Started with Wireshark: The Ultimate Hands-On Course (by Chris Greer and David Bombal)](https://www.udemy.com/course/wireshark-ultimate-hands-on-course/)

### References <a href="#ember143" id="ember143"></a>

[Free CCNA | Wireshark Demo (TCP/UDP) | Day 30 Lab | CCNA 200-301 Complete Course](https://www.youtube.com/watch?v=pJKFahkqMU8\&list=PLxbwE86jKRgMpuZuLBivzlM8s2Dk5lXBQ\&index=58)

[Troubleshooting slow networks with Wireshark // wireshark filters // Wireshark performance (video by Chris Greer and David Bombal)](https://www.youtube.com/watch?v=aEss3CG49iI)

### Other references/resources <a href="#ember146" id="ember146"></a>

[TCP Deep Dive - Wireshark (playlist by David Bombal)](https://www.youtube.com/playlist?list=PLhfrWIlLOoKMO9-7NxYN3TxCdcDecwOtj)

[Wireshark and Ethical hacking course (free course by David Bombal)](https://www.youtube.com/playlist?list=PLhfrWIlLOoKMBv50Y8NH6Dtfge_MrHYnl)

[Wireshark For Pentester: A Beginner’s Guide (by Raj Chandel, April 13, 2021)](https://www.hackingarticles.in/wireshark-for-pentesters-a-beginners-guide/)
