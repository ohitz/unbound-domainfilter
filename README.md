# unbound-domainfilter

DNS filtering extension for the unbound DNS resolver. At start, it reads the
two files /etc/unbound/blacklist and /etc/unbound/whitelist, which contain a
host name on every line.

For every query sent to unbound, the extension checks if the name is in the
whitelist or in the blacklist. If it is in the whitelist, processing continues
as usual (i.e. unbound will resolve it). If it is in the blacklist, unbound
stops resolution and returns the IP address configured in intercept_address.

The whitelist and blacklist matching is done with every domain part of the
requested name. So, if www.domain.com is requested, the extension checks
whether www.domain.com, domain.com or .com is listed.

Install and configure:

- copy dns_filter.py to /etc/unbound/dns_filter.py

- if needed, change intercept_address

- change unbound.conf as follows:

```
  server:
    module-config: "python validator iterator"
  python:
    python-script: "/etc/unbound/dns_filter.py"
```

- create /etc/unbound/blacklist and /etc/unbound/whitelist as you desire

- restart unbound

