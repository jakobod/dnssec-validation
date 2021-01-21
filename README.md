# dnssec-validation
Some python scripts for verifying the chain of trust for a given domain

# Validation of zones
These steps are conducted when a zone should be validated:

1. Check the existence of the zone.
```sh
QUERY SOA -> check the correctness of the response. e.g. is the SOA response intended for the queried Zone?
```
2. Query the authoritative NS for the zone.
```
e.g. QUERY NS -> QUERY A for NS
```

3. QUERY DNSKEY and DS
```sh
e.g. DNSKEY from NS + DS from parent NS
```

4. VALIDATE...
5. Repeat until the leaf-zone has been reached

# TODO

- distinguish between 'not deployed', 'deployed + not validated', and 'deployed + validated', maybe more?
- Find a domain list that contains subdomains too -> longer chains.

##### What is the question that I am trying to answer?
- Is DNSSEC standard conforming if it is deployed?
    - Using KSK and ZSK?
- How many TLDs deploy DNSSEC?
- 




# Links for reference
- https://www.cloudflare.com/dns/dnssec/how-dnssec-works/
- https://github.com/prateekroy/CSE534/blob/master/HW1/dnssec.py
