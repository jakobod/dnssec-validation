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


# Proof of nonexistence for specific records
When a specific record is queried that does not exist, a NSEC3 response is returned (when setting the DNSSEC flag of course).
This record can be used to check for the existence of the specific record!

###### Example

`sina.com.cn` is a domain that is NOT DNSSEC secured. Hence a query for the DS record to the NS of `com.cn` returns a NSEC3 response that proves the nonexistence of the requested record.
In this case, the provided hashes both **do not** match the hash for `sina.com.cn` thus, the proof of nonexistence has been made!

```sh
❯ dig +dnssec DS sina.com.cn @203.119.25.1

; <<>> DiG 9.10.6 <<>> +dnssec DS sina.com.cn @203.119.25.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 8998
;; flags: qr aa rd; QUERY: 1, ANSWER: 0, AUTHORITY: 6, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags: do; udp: 4096
;; QUESTION SECTION:
;sina.com.cn.			IN	DS

;; AUTHORITY SECTION:
GICE14DNTMDN31G43AUGVRKTKALVB8QC.com.cn. 21600 IN NSEC3	1 1 10 AEF123AB GKM1KHVFSNSLUTJUBF7JHHPG9F17BRFQ  NS SOA RRSIG DNSKEY NSEC3PARAM
GICE14DNTMDN31G43AUGVRKTKALVB8QC.com.cn. 21600 IN RRSIG	NSEC3 8 3 21600 20210220022234 20210121013539 43326 com.cn. ToFl+N9yvh7v0FKxItIfj9bTcOnjXm/LDhkfBeTOoKXwYPByNfywkKQ4 sxrMfNu/METE8Fl1APpHtXLdKD6scwMi4r8lYCiMIsCOHUN5iwCR+Yho 4fK1TYF8oPP0Ll0+MfjYTJAuU15pOf76YO+yu1C63ubO36pfuBgqMAia DcI=
com.cn.			21600	IN	SOA	a.dns.cn. root.cnnic.cn. 2027325278 7200 3600 2419200 21600
com.cn.			21600	IN	RRSIG	SOA 8 2 86400 20210221122211 20210122112211 43326 com.cn. FpsIqS53QaayhYt0hfVfh/1LT+3WX0IFjDrYrXJ/zujiorbz7kjqr3WR raKm4qNZrHeeEcVjKPvjv8m+7dlcZpYTMSp4R2WoVcI5BdUdB+fZlNu/ QmbGH4VkqDQaPMj17ZCov6gGJeNwGO+g+UKu9hoDgwAeJ3e22gP55H7i jZs=
TDU124P7EGELLSS91RPV7H8S4DKOE2EH.com.cn. 21600 IN NSEC3	1 1 10 AEF123AB UDL9N57ITL4KHVVPPJ5OI1T82JOE3N2V  NS DS RRSIG
TDU124P7EGELLSS91RPV7H8S4DKOE2EH.com.cn. 21600 IN RRSIG	NSEC3 8 3 21600 20210220005534 20210121002555 43326 com.cn. TmpgC0JdVNwh4xCdwTSYhb+C2Ls9riiRxG0kNuJRkwgp20n+QOK8vigZ knYHQozrRSHJNHIMbKaJljV98vPKUxNf7aZwaIba49uQlV2KvToJbCWV UQ2Ia7Gs3KnZuuS9ts/+LsBE+Iya/24ZPooO25LDwVQtR2vY6InAyFw7 +rQ=

;; Query time: 330 msec
;; SERVER: 203.119.25.1#53(203.119.25.1)
;; WHEN: Fri Jan 22 13:22:14 CET 2021
;; MSG SIZE  rcvd: 758
```


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
