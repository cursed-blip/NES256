from __future__ import annotations
import os
import sys
import argparse
import base64
import nes256

def main():
    parser = argparse.ArgumentParser(description='NES256 - AES-inspired cipher')
    subparsers = parser.add_subparsers(dest='command', required=True)

    encrypt_parser = subparsers.add_parser('encrypt')
    encrypt_parser.add_argument('-k', '--key', required=True)
    encrypt_parser.add_argument('-m', '--message')
    encrypt_parser.add_argument('-f', '--file')
    encrypt_parser.add_argument('-a', '--aad', default='')

    decrypt_parser = subparsers.add_parser('decrypt')
    decrypt_parser.add_argument('-k', '--key', required=True)
    decrypt_parser.add_argument('-m', '--message')
    decrypt_parser.add_argument('-f', '--file')
    decrypt_parser.add_argument('-a', '--aad', default='')

    args = parser.parse_args()
    key = base64.b64decode(args.key)

    if args.command == 'encrypt':
        if args.message:
            print(nes256.encrypt(args.message, key, aad=args.aad.encode()))
        elif args.file:
            with open(args.file, 'rb') as f:
                print(nes256.encrypt(f.read(), key, aad=args.aad.encode()))
        else:
            print('Provide --message or --file')

    elif args.command == 'decrypt':
        if args.message:
            print(nes256.decrypt(args.message, key, aad=args.aad.encode()).decode(errors='ignore'))
        elif args.file:
            with open(args.file, 'r', encoding='utf-8') as f:
                print(nes256.decrypt(f.read(), key, aad=args.aad.encode()).decode(errors='ignore'))
        else:
            print('Provide --message or --file')

if __name__ == '__main__':
    main()
