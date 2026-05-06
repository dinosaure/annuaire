# `pagejaune` & `pageblanche`, the `annuaire` project

Annuaire is a project comprising two unikernels designed to provide a domain
name resolution service that is (almost) independent of other recursive DNS
resolvers. The aim is to be able to resolve domain names whilst maintaining
full control over the means of communication. To achieve this, Annuaire offers
two distinct services:
- what is known as a recursive DNS resolver. In other words, it attempts to
  resolve domain names using the root servers. It performs DNSSEC validation (if
  the option is enabled) and even attempts TLS connections to primary and
  secondary DNS servers if they support it (this option is not recommended as,
  at this stage, few primary and secondary servers offer TLS connections).
- A _stub_ DNS resolver, which "relays" DNS queries to other servers (which
  we'll call _name servers_) but has a caching system for the responses. The
  user can query this resolver via UDP, TCP, and TCP+TLS if they wish.

The idea is to deploy these two unikernels, with the user utilising the stub
DNS resolver and the latter utilising the second unikernel: the recursive DNS
resolver, as well as a second recursive DNS resolver such as that of
[uncensoreddns.org][uncensoreddns.org] or [9.9.9.9][9_9_9_9]:
```
                ┌───┐            
                │ 🯅 │            
                └─┬─┘            
                  │ UDP | TCP | TCP/TLS
                  ▼               
           ┌─────────────┐        
           │             │        
           │ pageblanche │        
           │             │        
        ┌──┴─────────────┴──┐     
        │                   │     
        │ TCP/TLS           │ UDP | TCP | TCP/TLS    
        ▼                   ▼     
  ┌───────────┐        ┌─────────┐
  │           │        │         │
  │ pagejaune │        │ 9.9.9.9 │
  │           │        │         │
  └───────────┘        └─────────┘ 
        │ UDP (with possibly DNSSEC)
        ▼
```

The user can configure the stub DNS resolver to use multiple name servers.
During configuration, the user can choose which communication method to use
between the stub DNS resolver and the specified name servers. By default, we
use [uncensoreddns.org][uncensoreddns.org] via a TCP+TLS connection (known as
[DoT][DNS-over-TLS]).

There is the special case of the recursive DNS resolver, with which the DNS
stub resolver can communicate **securely** using a certificate generated _on the
fly_ from a password (and which regenerates itself at a time interval specified
by the user): that is to say, if you enter this password into the stub DNS
resolver, it will be able to deterministically regenerate a means of
communicating securely with the recursive DNS resolver based on information the
latter publishes.

## How to practise this _pirouette_ at home?

Annuaire primarily requires [OPAM][opam-install] and OCaml. We recommend that
you install them on your system and set up an OCaml 5.4.0 switch:
```shell
$ bash -c "sh <(curl -fsSL https://opam.ocaml.org/install.sh)"
$ opam init
$ opam switch create 5.4.0
$ opam pin add -y git+https://github.com/dinosaure/annuaire.git
```

Next, you should have [Solo5][solo5], our _tender_ for unikernels, as well as
`pagejaune.hvt` (the recursive DNS resolver) and `pageblanche.hvt` (the stub DNS
resolver):
```shell
$ which solo5-hvt
/home/<user>/.opam/5.4.0/bin/solo5-hvt
$ file $(opam var bin)/pagejaune.hvt
pagejaune.hvt: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), 
  statically linked, interpreter /nonexistent/solo5/, for OpenBSD, stripped
$ file $(opam var bin)/pageblanche.hvt
pageblanche.hvt: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), 
  statically linked, interpreter /nonexistent/solo5/, for OpenBSD, stripped
```

Solo5 is also available from our cooperative's apt repository:
```shell
$ curl -fsSL https://apt.robur.coop/gpg.pub | \
  gpg --dearmor > /etc/apt/trusted.gpg.d/apt.robur.coop.gpg
$ echo "deb [signed-by=/etc/apt/trusted.gpg.d/apt.robur.coop.gpg] https://apt.robur.coop ubuntu-20.04 main"
$ apt update
$ apt install solo5
```

Finally, we need to create the virtual devices required for the unikernels. To
do this, we will create a bridge, two tap interfaces for the network, and an
empty list of IP addresses to block.
```shell
$ sudo ip link add name service type bridge
$ sudo ip addr add 10.0.0.1/24 dev service
$ sudo ip tuntap add name tap0 mode tap
$ sudo ip tuntap add name tap1 mode tap
$ sudo ip link set tap0 master service
$ sudo ip link set tap1 master service
$ sudo ip link set service up
$ sudo ip link set tap0 up
$ sudo ip link set tap1 up
$ eval $(opam env)
$ annuaire.ban ban.img
```

One final step specific to your computer is to allow the unikernels to
communicate with the Internet. To do this on Linux, you can configure your
firewall as follows:
```shell
$ sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o wlan0 -j MASQUERADE
$ sudo iptables -A FORWARD -i service -o wlan0 -j ACCEPT
$ sudo iptables -A FORWARD -i wlan0 -o service -m state --state RELATED,ESTABLISHED -j ACCEPT
```

We can now launch the unikernels! The first unikernel will be our recursive DNS
resolver, for which we will specify a seed (this will be our secret):
```shell
$ solo5-hvt --net:service=tap0 -- $(opam var bin)/pagejaune.hvt \
  --ipv4=10.0.0.2/24 --ipv4-gateway=10.0.0.1 \
  --domain foo.local \
  --dnssec --qname-minimisation \
  --tls-lifetime 1h --seed foo=
```

Next, we’ll launch our second unikernel, which will act as our stub DNS
resolver:
```shell
$ solo5-hvt --net:service=tap1 --block:ban=ban.img -- $(opam var bin)/pageblanche.hvt \
  --ipv4=10.0.0.3/24 --ipv4-gateway=10.0.0.1 \
  --domain bar.local
  --pagejaune '10.0.0.2!foo.local!foo='
  --seed bar=
```

You can now resolve domain names using `dig`:
```shell
$ dig robur.coop +short @10.0.0.3
193.30.40.138
```

Now, it’s important to understand that communication between `pageblance` and
`pagejaune` is always encrypted using a [P256 key][p256] that is renewed every
hour (as specified using `--tls-lifetime`). `pageblanche` is capable of
deterministically regenerating the key as long as it knows the seed (here,
`foo=`).

The user can also reconstruct the key as long as they have the seed (the
password). In addition, `pageblanche` also offers a secure connection using a
key generated _on the fly_ (using the seed `bar=` as in the example). It is
then possible to pre-compute the public key fingerprint to verify the
connection with `pageblanche`:
```shell
$ annuaire.gen --domain bar.local --seed bar= 10.0.0.3
guY82cR+GQBU/GHXb/hsRwePlbYi+PeVwfZ9o1hRHBM=
$ kdig +short +tls +tls-pin=$(annuaire.gen --domain bar.local --seed bar= 10.0.0.3) \
  @10.0.0.3 robur.coop
193.30.40.138
```

The advantage of having two unikernels is that `pageblanche` will query not
only `pagejaune` but also (by default) [uncensoreddns.org][uncensoreeddns] (via
DoT). We take the response from whichever one answers the fastest. It’s worth
noting that even if `pagejaune` might respond more slowly than the other
recursive DNS resolver, it populates its cache so that the next request is
answered almost instantly. In addition, `pagejaune` is given 500 ms before we
try your other recursive DNS resolver.

[opam-install]: https://opam.ocaml.org/doc/Install.html
[solo5]: https://github.com/solo5/solo5
