import dnssec
import time


def print_loop(first):
    print('###################################################################')
    print(f'first: {first}')


def main():
    domain = 'iana.org'
    splits = dnssec.split(domain)

    first = splits.pop()
    if first != '.':
        first += '.'
    while True:
        try:
            second = splits.pop()
            if second != '.':
                second += '.'
        except IndexError as e:
            break
        print_loop(first)
        
        dnskey_rrset, dnskey_rrsig = dnssec.get_dnskey(first)
        print('got DNSKEY')
        if not dnssec.validate_rrsigset(dnskey_rrset, dnskey_rrsig, first):
            raise Exception('Cant validate DNSKEY RRSET')
        print('verified DNSKEY')

        ds_rrset, ds_rrsig = dnssec.get_ds(first, second)
        print('got DS')
        # if not dnssec.validate_rrsigset(ds_rrset, ds_rrsig, first):
        #     raise Exception('Cant validate DS RRSET')
        if not dnssec.validate_ds(first, dnskey_rrset, ds_rrset):
            raise Exception('Cant validate DS with key')

        print('verified DS')
        first = second
    # 
    print_loop(first)
    dnskey_rrset, dnskey_rrsig = dnssec.get_dnskey(first)
    print('got DNSKEY')
    if not dnssec.validate_rrsigset(dnskey_rrset, dnskey_rrsig, first):
        raise Exception('Cant validate DNSKEY RRSET')
    print('verified root DNSKEY')


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f'{type(e)}: {e}')
