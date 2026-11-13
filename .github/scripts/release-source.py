#!/usr/bin/env python3
"""Resolve a release tag to a full commit already present on trusted main."""
import argparse
import os
from pathlib import Path
import re
import subprocess

TAG = r'v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?'


def resolve_tag(repository, tag):
    if not re.fullmatch(TAG, tag):
        raise ValueError('release tag must be a version such as v1.2.3')
    try:
        source = subprocess.check_output(['git', '-C', str(repository), 'rev-parse', '--verify',
                                          f'refs/tags/{tag}^{{commit}}'], text=True, stderr=subprocess.DEVNULL).strip()
        if not re.fullmatch(r'[0-9a-f]{40}', source):
            raise ValueError('tag did not resolve to a full commit SHA')
        subprocess.run(['git', '-C', str(repository), 'merge-base', '--is-ancestor', source,
                        'refs/remotes/origin/main'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as error:
        raise ValueError('release tag must exist and point to a commit on origin/main') from error
    return {'tag': tag, 'source_sha': source}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tag', required=True)
    args = parser.parse_args()
    try:
        outputs = resolve_tag(Path('.'), args.tag)
    except ValueError as error:
        parser.exit(1, f'::error::{error}\n')
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as stream:
        for key, value in outputs.items():
            stream.write(f'{key}={value}\n')


if __name__ == '__main__':
    main()
