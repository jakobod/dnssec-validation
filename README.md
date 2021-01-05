# dnssec-validation
Some python scripts for verifying the chain of trust for a given domain


###### steps for the validation of the chain for www.example.com.
```sh
Request: www.example.com A (DO) -> example.com.
Answer:  www.example.com <A> + RRSIG(<A>) <- 
   
Request: example.com DNSKEY (DO) -> example.com.
Answer:  example.com <DNSKEY> + RRSIG(<DNSKEY>) <-

DS (Delegation signer) contains the hashed DNSKEY from child (example.com)
Request: example.com DS (DO) -> com.
Answer:  example.com <DS> + RRSIG(<DS>) <-

DNSKEY is used to create RRSIG(<DS>) and required to validate it
Request: com DNSKEY (DO) -> com.
Answer:  com <DNSKEY> + RRSIG(<DNSKEY>) <-
```


# TODO

- distinguish between 'not deployed', 'deployed + not validated', and 'deployed + validated', maybe more?
- Fix caching of validated domains
    - Add domains to validated only set if complete chain could be validated!
- Validate chain downwards
- Find domain list containing also subdomains -> longer chains.

##### For the presentation

- What is the question that I am trying to answer?


# Links for reference
- https://www.cloudflare.com/dns/dnssec/how-dnssec-works/
- https://github.com/prateekroy/CSE534/blob/master/HW1/dnssec.py
