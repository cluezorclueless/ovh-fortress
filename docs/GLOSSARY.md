# Glossary

All the terms in this repo, explained with one picture: my server is an apartment
building, the internet is the street, and every packet of data is a visitor.

| Term | Plain English | In the building |
|---|---|---|
| Server / VPS | A computer I rent that is always on, in a data center | The apartment building |
| Packet | One small chunk of data sent over the internet | One visitor walking up |
| DDoS | Sending a huge crowd of fake traffic to overload a target | A mob blocking the front door so real guests cannot get in |
| Stresser | A paid service that sells DDoS attacks | A company that rents out mobs |
| Packets per second (pps) | How many visitors arrive each second | People through the door per second |
| Mbit/s | How much data arrives each second | How much stuff the crowd is carrying |
| OVH | The company I rent the server from | The city that owns the road and the walls |
| Edge firewall | OVH's filter at the edge of its network | A barricade on the road into town |
| Kernel | The core of the operating system | The building's management office |
| XDP / eBPF | A way to run small safe programs inside the kernel, at the very first moment a packet arrives | A bouncer standing right at the door, before anyone reaches the lobby |
| nftables | The Linux firewall | The front desk with the guest list |
| Connection tracking | The system remembering who is already in a conversation with the server | The front desk remembering who has checked in |
| Stateless | Looks at each packet alone, with no memory | A bouncer who judges each visitor on sight |
| Stateful | Remembers earlier packets | A front desk that knows who went upstairs earlier |
| Token bucket | A rate limit: each source gets a small allowance that refills slowly | Each visitor gets a few tickets, and the tickets refill slowly |
| UDP | Fast, no-handshake traffic, used for voice and games | A courier who drops a note and leaves |
| TCP | Careful traffic with a handshake, used for web pages and SSH | A courier who rings the bell and waits for you to answer |
| SYN | The first "hello" in a TCP handshake | Ringing the bell |
| ACK | "Got it" in a TCP conversation | The "okay, I heard you" reply |
| NULL packet | A TCP packet with no flags set, which no real software sends | A visitor in a blank mask with no name tag |
| Spoofed source | A packet that lies about who sent it | A visitor with a fake ID |
| Bogon | An address that should never appear from the public internet | A visitor claiming to live in a house that doesn't exist |
| Bait port | A fake open port that real users never touch | The fake unlocked side door with a camera |
| Tailscale | A private network between my own devices | A private tunnel only my family can use |
| Exit node | A device that sends my internet traffic out for me | My own car that drives me to the outside world |
| WireGuard | The technology Tailscale uses for its encrypted tunnel | The sealed tube that tunnel travels in |
| DHCP | How a computer gets its network address when it connects | Getting a room key when you check in |
| Generic mode XDP | The slower version of XDP my server's network card allows | The bouncer standing just inside the lobby instead of at the street |
| Rollback | An automatic undo | A timer that unlocks the door again if the new rules lock me out |
| Replay test | Firing recorded fake traffic at the filter to see what it does | A fire drill |
