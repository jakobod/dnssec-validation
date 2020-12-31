# dnssec-validation
Some python scripts for verifying the chain of trust for a given domain


# steps for the validation of the chain for www.example.com.

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
