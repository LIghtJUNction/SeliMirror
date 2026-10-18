#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
import copy
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from check_release import properties, check_entry_names, check_zip, create_zip

GOOD = (b'id=selimirror\nname=SeliMirror\nversion=v0.1.0\nversionCode=100\n'
        b'author=contributors\ndescription=KPM companion\n')

class ValidateRelease(unittest.TestCase):
    def test_valid_properties(self):
        result=properties(GOOD)
        self.assertEqual(result['versionCode'],'100')
        self.assertEqual(result['id'],'selimirror')

    def test_duplicate_key(self):
        with self.assertRaises(ValueError):
            properties(GOOD+b'id=other\n')

    def test_bad_version_code(self):
        for bad in ('0','-1','1x','2147483648','1.0'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                properties(GOOD.replace(b'versionCode=100',f'versionCode={bad}'.encode()))

    def test_missing_key(self):
        with self.assertRaises(ValueError):
            properties(GOOD.replace(b'author=contributors\n',b''))

    def test_zip_paths(self):
        for bad in ('../policy','x/../y','/root','x//y','x\\y','x/./y'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                check_entry_names(('module.prop',bad))
        with self.assertRaises(ValueError):
            check_entry_names(('module.prop','module.prop'))

    def test_zip_integrity(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'module.zip'
            create_zip(p)
            result,kpm=check_zip(p)
            self.assertEqual(result['versionCode'],'100')
            self.assertEqual(kpm['metadata']['name'],'selimirror')
            with zipfile.ZipFile(p) as z:
                self.assertEqual(z.namelist()[0],'FILES.sha256')
                self.assertEqual(z.read('module.prop'),(Path(__file__).resolve().parents[1]/'module/module.prop').read_bytes())

if __name__=='__main__':
    unittest.main()
