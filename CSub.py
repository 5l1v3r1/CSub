import requests
import time
import urllib3
import sys

'''software version'''
version = 0.1

'''take in target/output values'''
def parse_args():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--domain', type=str, required=True, help='Target Domain.')
    parser.add_argument('-o', '--output', type=str, required=False, help='Output to file.')
    return parser.parse_args()


'''banner for start of program'''
def banner():
    global version
    print('\nName: CSub')
    print(f'Version: {version}')
    print('Copyright: Arham Khan (Cyber Security)')
    print('\n\n  ____ ____        _     ')
    print(' / ___/ ___| _   _| |__  ')
    print('| |   \___ \| | | |    \ ')
    print('| |___ ___) | |_| | |_) |')
    print(' \____|____/ \__,_|_.__/ by Arham\n\n ')



    time.sleep(1)


#parse host from scheme, to use for certificate transparency abuse
def parse_url(url):
    try:
        host = urllib3.util.url.parse_url(url).host
    except Exception as e:
        print('\n[*] Invalid domain, try again..\n')
        sys.exit(1)
    return host

def write_subs_to_file(subdomain, output_file):
    with open(output_file, 'a') as fp:
        fp.write(subdomain + '\n')
        fp.close()


def main():
    banner()
    subdomains = []

    args = parse_args()
    target = parse_url(args.domain)
    output = args.output

    req = requests.get(f'https://crt.sh/?q=%.{target}&output=json')

    if req.status_code != 200:
        print('\n[*] Information not available!\n')
        sys.exit(1)

    for (key,value) in enumerate(req.json()):
        subdomains.append(value['name_value'])

    print(f"\n[!] ****** TARGET: {target} ****** [!] \n")


    subs = sorted(set(subdomains))

    for s in subs:
        print(f'[*] {s}\n')
        if output is not None:
            write_subs_to_file(s, output)

    print("\n\n[**] CSub is complete, all subdomains have been found.\n\n")


if __name__=='__main__':
    main()
