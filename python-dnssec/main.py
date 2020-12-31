import dnssec
import time
import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype


def main():
    domain = 'jakob-otto.de.'
    splits = dnssec.split(domain)
    print(splits)
    dnskey_rrset, dnskey_rrsig = dnssec.get_dnskey(domain)
    ds_rrset, ds_rrsig = dnssec.get_ds(domain, 'de')
    if dnssec.validate_ds(domain, dnskey_rrset[0], ds_rrset[0]):
        print('validated')
    else:
        print('NOT validated')

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f'{type(e)}: {e}')
