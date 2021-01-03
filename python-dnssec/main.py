import dnssec
import time


def main():
    domain = 'jakob-otto.de'
    dnssec.validate_chain(domain)


if __name__ == '__main__':
    try:
        t1 = time.time()
        main()
        t2 = time.time()
        duration = t2 - t1
        print(f'Complete chain validated in {duration} seconds')
    except Exception as e:
        print(f'{type(e)}: {e}')
