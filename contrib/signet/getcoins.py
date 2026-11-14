#!/usr/bin/env python3
# Copyright (c) 2020-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import argparse
import io
import requests
import subprocess
import sys
import xml.etree.ElementTree

# braille unicode block
BASE = 0x2800
BIT_PER_PIXEL = [
    [0x01, 0x08],
    [0x02, 0x10],
    [0x04, 0x20],
    [0x40, 0x80],
]
BW = 2
BH = 4

# imagemagick or compatible fork (used for converting SVG)
CONVERT = 'convert'

class PPMImage:
    '''
    Load a PPM image (Pillow-ish API).
    '''
    def __init__(self, f):
        if f.readline() != b'P6\n':
            raise ValueError('Invalid ppm format: header')
        line = f.readline()
        (width, height) = (int(x) for x in line.rstrip().split(b' '))
        if f.readline() != b'255\n':
            raise ValueError('Invalid ppm format: color depth')
        data = f.read(width * height * 3)
        stride = width * 3
        self.size = (width, height)
        self._grid = [[tuple(data[stride * y + 3 * x:stride * y + 3 * (x + 1)]) for x in range(width)] for y in range(height)]

    def getpixel(self, pos):
        return self._grid[pos[1]][pos[0]]

def print_image(img, threshold=128):
    '''Print black-and-white image to terminal in braille unicode characters.'''
    x_blocks = (img.size[0] + BW - 1) // BW
    y_blocks = (img.size[1] + BH - 1) // BH

    for yb in range(y_blocks):
        line = []
        for xb in range(x_blocks):
            ch = BASE
            for y in range(BH):
                for x in range(BW):
                    try:
                        val = img.getpixel((xb * BW + x, yb * BH + y))
                    except IndexError:
                        pass
                    else:
                        if val[0] < threshold:
                            ch |= BIT_PER_PIXEL[y][x]
            line.append(chr(ch))
        print(''.join(line))

parser = argparse.ArgumentParser(description='Script to get coins from a faucet.', epilog='You may need to start with double-dash (--) when providing nito-cli arguments.')
parser.add_argument('-c', '--cmd', dest='cmd', default='nito-cli', help='nito-cli command to use')
parser.add_argument('-f', '--faucet', dest='faucet', required=True, help='URL of a faucet for your Nito Signet challenge')
parser.add_argument('-g', '--captcha', dest='captcha', default='', help='URL of the faucet captcha, or empty if no captcha is needed')
parser.add_argument('-a', '--addr', dest='addr', default='', help='Nito address to which the faucet should send')
parser.add_argument('-p', '--password', dest='password', default='', help='Faucet password, if any')
parser.add_argument('-n', '--amount', dest='amount', default='0.001', help='Amount to request (0.001-0.1, default is 0.001)')
parser.add_argument('-i', '--imagemagick', dest='imagemagick', default=CONVERT, help='Path to imagemagick convert utility')
parser.add_argument('nito_cli_args', nargs='*', help='Arguments to pass on to nito-cli (default: -signet)')

args = parser.parse_args()

if args.nito_cli_args == []:
    args.nito_cli_args = ['-signet']


def nito_cli(rpc_command_and_params):
    argv = [args.cmd] + args.nito_cli_args + rpc_command_and_params
    try:
        return subprocess.check_output(argv).strip().decode()
    except FileNotFoundError:
        raise SystemExit(f"The binary {args.cmd} could not be found")
    except subprocess.CalledProcessError:
        cmdline = ' '.join(argv)
        raise SystemExit(f"-----\nError while calling {cmdline} (see output above).")


if args.addr == '':
    # get address for receiving coins
    args.addr = nito_cli(['getnewaddress', 'faucet', 'bech32'])

data = {'address': args.addr, 'password': args.password, 'amount': args.amount}

# Store cookies
session = requests.Session()

if args.captcha != '': # Retrieve a captcha
    try:
        res = session.get(args.captcha)
        res.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise SystemExit(f"Unexpected error when contacting faucet: {e}")

    # Size limitation
    svg = xml.etree.ElementTree.fromstring(res.content)
    if svg.attrib.get('width') != '150' or svg.attrib.get('height') != '50':
        raise SystemExit("Captcha size doesn't match expected dimensions 150x50")

    # Convert SVG image to PPM, and load it
    try:
        rv = subprocess.run([args.imagemagick, 'svg:-', '-depth', '8', 'ppm:-'], input=res.content, check=True, capture_output=True)
    except FileNotFoundError:
        raise SystemExit(f"The binary {args.imagemagick} could not be found. Please make sure ImageMagick (or a compatible fork) is installed and that the correct path is specified.")

    img = PPMImage(io.BytesIO(rv.stdout))

    # Terminal interaction
    print_image(img)
    print(f"Captcha from URL {args.captcha}")
    data['captcha'] = input('Enter captcha: ')

try:
    res = session.post(args.faucet, data=data)
except Exception:
    raise SystemExit(f"Unexpected error when contacting faucet: {sys.exc_info()[0]}")

# Display the output as per the returned status code
if res:
    # When the return code is in between 200 and 400 i.e. successful
    print(res.text)
elif res.status_code == 404:
    print('The specified faucet URL does not exist. Please check for any server issues/typo.')
elif res.status_code == 429:
    print('The faucet rate limit was reached. Follow the retry policy published by its operator.')
else:
    print(f'Returned Error Code {res.status_code}\n{res.text}\n')
    print('Please check the provided arguments for their validity and/or any possible typo.')
