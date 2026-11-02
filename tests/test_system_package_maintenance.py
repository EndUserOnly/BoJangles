from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch
import hashlib,json,zipfile
from bojangles.maintenance import checks
from bojangles import package_layout
from bojangles.renderer import installed
from bojangles import upgrade

class SystemMaintenanceTests(TestCase):
    def test_system_authority_ignores_unrelated_private_python_and_command(self):
        with TemporaryDirectory() as td:
            root=Path(td);home=root/'home';home.mkdir()
            store=root/'system/releases';area=store/'public-release-20261028'
            command=area/'native-command/app/bojangles.bin';command.parent.mkdir(parents=True);command.write_bytes(b'compiled-fixture')
            wheel=area/'application/bojangles-0.1.0-py3-none-any.whl';wheel.parent.mkdir()
            with zipfile.ZipFile(wheel,'w') as archive:archive.writestr('bojangles/test.py',b'packaged source')
            (area/'product-manifest.json').write_text(json.dumps({'candidate':'public-release-20261028','application':{'sha256':hashlib.sha256(wheel.read_bytes()).hexdigest()},'native_command':{'path':'native-command/app/bojangles.bin','sha256':hashlib.sha256(command.read_bytes()).hexdigest()}}))
            # A private command should neither be required nor selected by the system check.
            private=home/'.local/bin/bojangles';private.parent.mkdir(parents=True);private.write_bytes(b'unrelated private version')
            with patch.object(package_layout,'release_store',return_value=store),patch.object(package_layout,'SYSTEM_RELEASE_STORE',store),patch.object(installed,'_read_wpe_release_state',return_value={'active':'public-release-20261028'}),patch.object(installed,'_verify_wpe_release_candidate'),patch.object(upgrade,'_verify_native_bundle'):
                result=checks.check(home)
            self.assertEqual(result['failures'],[])
            self.assertEqual(private.read_bytes(),b'unrelated private version')
            self.assertEqual(result['blocking_requests_checked'],144)
