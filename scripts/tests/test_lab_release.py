"""Synthetic handoff contracts only; no actual release/LAB/signature is proved."""
import copy
import importlib.util
import io
import json
import subprocess
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('verifier', ROOT/'scripts/verify-lab-release.py')
V = importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(V)
SOURCE, PRODUCER, HANDOFF = 'a'*40, 'b'*40, 'c'*40


def raw(value):
    return (json.dumps(value, sort_keys=True) + '\n').encode()


class LabReleaseTests(unittest.TestCase):
    def setUp(self):
        # Simulate tracked regular source paths; no Git invocation in fixtures.
        inventory = patch.object(V, 'tracked_source_paths', side_effect=lambda repo, _source: {
            file.relative_to(repo).as_posix(): ('100644', 'blob') for file in repo.rglob('*') if file.is_file()})
        inventory.start();self.addCleanup(inventory.stop)

    def fixture(self):
        temporary = tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        repo = Path(temporary.name)
        for name, body in {'Cargo.toml': b'[workspace.package]\nversion="1.0.0"\n',
                           'Cargo.lock': b'synthetic lock\n', 'rust-toolchain.toml': b'[toolchain]\nchannel="synthetic"\n',
                           'fixtures/abi/v1/capabilities.json': raw({'core_version': '0.0.5', 'abi_version': 1,
                               'config_schema_version': 1, 'capabilities_schema_version': 1,
                               'routing': {'uid_package_split': False}}),
                           'sbom/foxcore-aarch64-linux-android.cdx.json': b'{}\n',
                           'sbom/workspace-all-targets.cdx.json': b'{}\n'}.items():
            p = repo/name;p.parent.mkdir(parents=True, exist_ok=True);p.write_bytes(body)
        required = (ROOT/'scripts/lab-release-required-scope.json').read_bytes()
        scope = V.document(required)
        source_paths = V.COMPILED_FIXED | {'crates/fixture/Cargo.toml', 'crates/fixture/build.rs',
                                          'crates/fixture/src/lib.rs', 'vendor/rustls/Cargo.toml',
                                          'vendor/rustls/build.rs', 'vendor/rustls/src/lib.rs',
                                          'fixtures/abi/v1/capabilities.json'} | {
                                              'fingerprints/profile-' + str(i) + '.json' for i in range(9)}
        for name in source_paths:
            file = repo/name
            if not file.exists():
                file.parent.mkdir(parents=True, exist_ok=True);file.write_bytes(b'synthetic compiled input\n')
        inputs = raw({'schema': 1, 'producer_commit': PRODUCER,
                      'files': {name: V.digest((repo/name).read_bytes()) for name in source_paths}})
        files = {'metadata/compiled-inputs.json': inputs, 'payload/Cargo.lock': (repo/'Cargo.lock').read_bytes(),
                 'payload/abi-gate.log': b'abi-gate: PASS\n',
                 'payload/capabilities.json': (repo/'fixtures/abi/v1/capabilities.json').read_bytes()}
        for name in ('foxcore-aarch64-linux-android.cdx.json', 'workspace-all-targets.cdx.json'):
            files['payload/sbom/'+name] = (repo/'sbom'/name).read_bytes()
        libs = []
        for abi in scope['releaseAbis']:
            header = bytearray(64);header[:6] = b'\x7fELF' + bytes((V.ANDROID_ELF_TYPES[abi][0], 1));header[16:18] = (3).to_bytes(2, 'little');header[18:20] = V.ANDROID_ELF_TYPES[abi][1].to_bytes(2, 'little');body = bytes(header) + b'synthetic JNI ' + abi.encode();files['payload/jniLibs/'+abi+'/libfoxhole_native.so'] = body
            libs.append({'abi': abi, 'sha256': V.digest(body), 'bytes': len(body)})
        capabilities = V.document(files['payload/capabilities.json'])
        capabilities['core_version'] = '1.0.0';capabilities['routing']['uid_package_split'] = True
        files['payload/capabilities.json'] = raw(capabilities)
        origin = {'schema': 1, 'kind': 'qualified-current-android-capabilities', 'producer_commit': PRODUCER,
                  'producer_dirty': False, 'compiled_source_sha256': V.source_fingerprint(V.document(inputs)['files']),
                  'native_input_manifest_sha256': '1'*64, 'native_producer_receipt_sha256': '2'*64,
                  'android_probe_receipt_sha256': '3'*64, 'source_derivation_sha256': '4'*64,
                  'capabilities_sha256': V.digest(files['payload/capabilities.json']), 'target_os': 'android',
                  'features': 'shipped', 'android_delivery_profile': 'android4',
                  'abis': scope['releaseAbis'], 'core_version': '1.0.0', 'libraries': libs}
        files['payload/capabilities-provenance.json'] = raw(origin)
        files['payload/MANIFEST.json'] = raw({'git': {'commit': PRODUCER, 'dirty': False},
                                            'core_version': '1.0.0', 'libs': libs,
                                            'build_inputs': {'cargo_lock_sha256': V.digest(files['payload/Cargo.lock']),
                                                'current_capabilities_sha256': V.digest(files['payload/capabilities.json']),
                                                'capabilities_provenance_sha256': V.digest(files['payload/capabilities-provenance.json'])}})
        checks = {}
        for i, (name, definition) in enumerate(scope['scopes'].items()):
            path = 'evidence/'+str(i)+'.json';files[path] = raw({'synthetic_scope': name})
            checks[name] = {'status': 'PASS', 'mode': 'retained-exact-input', 'definition_sha256': definition,
                            'evidence_path': path, 'evidence_sha256': V.digest(files[path])}
        files['metadata/LAB-GATE.json'] = raw({'schema': 1, 'producer_commit': PRODUCER,
                                              'compiled_inputs_sha256': V.digest(inputs),
                                              'scope_sha256': V.digest(required), 'checks': checks})
        compiler = bytearray(64);compiler[:6] = b'\x7fELF\x02\x01';compiler[18:20] = (62).to_bytes(2, 'little')
        files[V.COMPILER] = bytes(compiler)
        files['metadata/compiler-producer.json'] = raw({'schema': 1, 'source_commit': PRODUCER,
                                                       'compiled_inputs_sha256': V.digest(inputs),
                                                       'target': 'x86_64-unknown-linux-gnu', 'binary_sha256': V.digest(compiler),
                                                       'bytes': len(compiler), 'exit_code': 0})
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w:gz') as tar:
            for name, body in files.items():
                member = tarfile.TarInfo(name);member.size = len(body);tar.addfile(member, io.BytesIO(body))
        data = archive.getvalue()
        handoff = {'schema': 1, 'kind': 'owner-approved-core-lab-release', 'source_commit': SOURCE,
                   'producer_commit': PRODUCER, 'version': '1.0.0', 'release_tag': 'v1.0.0',
                   'release_asset': 'core.tar.gz', 'staging_tag': 'lab-synthetic', 'staging_asset': 'candidate.tar.gz',
                   'archive_sha256': V.digest(data), 'archive_bytes': len(data),
                   'compiled_inputs_sha256': V.digest(inputs), 'scope_sha256': V.digest(required),
                   'files': {name: {'sha256': V.digest(body), 'bytes': len(body),
                                    'mode': 0o755 if name == V.COMPILER else 0o644} for name, body in files.items()}}
        return repo, required, handoff, files, data

    def test_positive_synthetic_signed_selection_and_closed_payload(self):
        repo, required, handoff, files, data = self.fixture();calls = []
        with patch.object(V.subprocess, 'check_output', side_effect=[SOURCE+'\n', raw(handoff)]):
            selected = V.signed_handoff(repo, SOURCE, HANDOFF, V.digest(raw(handoff)), calls.append)
        self.assertEqual([SOURCE, HANDOFF], calls)
        V.select(selected, repo, SOURCE, required)
        V.verify_payload(selected, V.archive_files(data, selected), repo, required)

    def test_wrong_signature_source_or_handoff_hash_is_rejected(self):
        repo, required, handoff, files, data = self.fixture()
        def reject_signature(_):
            raise ValueError('synthetic signature rejected')
        with self.assertRaisesRegex(ValueError, 'signature'):
            V.signed_handoff(repo, SOURCE, HANDOFF, V.digest(raw(handoff)), reject_signature)
        with patch.object(V.subprocess, 'check_output', side_effect=[SOURCE+'\n', raw(handoff)]), self.assertRaisesRegex(ValueError, 'handoff bytes'):
            V.signed_handoff(repo, SOURCE, HANDOFF, '0'*64, lambda _: None)
        bad = copy.deepcopy(handoff);bad['source_commit'] = '0'*40
        with self.assertRaisesRegex(ValueError, 'release source'):
            V.select(bad, repo, SOURCE, required)

    def test_wrong_archive_hash_or_compiled_equivalence_is_rejected(self):
        repo, required, handoff, files, data = self.fixture()
        with self.assertRaisesRegex(ValueError, 'archive bytes'):
            V.archive_files(data+b'changed', handoff)
        (repo/'Cargo.lock').write_bytes(b'changed source')
        with self.assertRaisesRegex(ValueError, 'compiled source equivalence'):
            V.verify_payload(handoff, files, repo, required)

    def test_missing_full_gate_scope_and_missing_compiler_are_rejected(self):
        repo, required, handoff, files, data = self.fixture()
        broken = dict(files);gate = V.document(broken['metadata/LAB-GATE.json']);gate['checks'].pop(next(iter(gate['checks'])))
        broken['metadata/LAB-GATE.json'] = raw(gate)
        with self.assertRaisesRegex(ValueError, 'full gate scope'):
            V.verify_payload(handoff, broken, repo, required)
        broken = dict(files);broken.pop(V.COMPILER)
        with self.assertRaises(KeyError):
            V.verify_payload(handoff, broken, repo, required)

    def test_old_producer_cannot_be_relabelled_as_current(self):
        repo, required, handoff, files, data = self.fixture()
        handoff['producer_commit'] = '0'*40
        with self.assertRaisesRegex(ValueError, 'compiled producer'):
            V.verify_payload(handoff, files, repo, required)

    def test_omitted_rust_vendor_build_and_feature_inputs_are_rejected_even_rehashed(self):
        repo, required, handoff, files, data = self.fixture()
        for missing in ('crates/fixture/src/lib.rs', 'vendor/rustls/src/lib.rs',
                        'crates/fixture/build.rs', '.cargo/config.toml',
                        'config/foxcore-android-delivery.json', 'crates/fixture/Cargo.toml'):
            bad = dict(files);inputs = V.document(files['metadata/compiled-inputs.json'])
            inputs['files'].pop(missing);body = raw(inputs);bad['metadata/compiled-inputs.json'] = body
            modified = dict(handoff);modified['compiled_inputs_sha256'] = V.digest(body)
            with self.subTest(missing=missing), self.assertRaisesRegex(ValueError, 'declared compiled source closure'):
                V.verify_payload(modified, bad, repo, required)

    def test_current_four_abi_policy_is_accepted_and_partial_policy_or_payload_is_rejected(self):
        repo, required, handoff, files, data = self.fixture()
        scope = V.required_scope(required)
        self.assertEqual(['arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64'], scope['releaseAbis'])
        self.assertEqual(scope['releaseAbis'], scope['fullGateAndroidABIs'])
        bad = copy.deepcopy(scope);bad['releaseAbis'] = ['arm64-v8a', 'armeabi-v7a']
        with self.assertRaisesRegex(ValueError, 'release ABI policy'):
            V.required_scope(raw(bad))
        bad = copy.deepcopy(scope);bad['fullGateAndroidABIs'] += ['armeabi-v7a', 'x86']
        with self.assertRaisesRegex(ValueError, 'full-gate ABI policy'):
            V.required_scope(raw(bad))
        broken = dict(files);manifest = V.document(files['payload/MANIFEST.json'])
        manifest['libs'][0]['abi'] = 'armeabi-v7a';broken['payload/MANIFEST.json'] = raw(manifest)
        with self.assertRaisesRegex(ValueError, 'release ABI policy'):
            V.verify_payload(handoff, broken, repo, required)

    def test_historical_four_abi_hash_cannot_qualify_current_android_scope(self):
        repo, required, handoff, files, data = self.fixture()
        scope = V.document(required)
        scope['scopes']['android-release'] = scope['historicalFourAbiDefinitionSha256']
        with self.assertRaisesRegex(ValueError, 'Android check definition'):
            V.required_scope(raw(scope))

    def test_old_frozen_fixture_cannot_be_current_capabilities(self):
        repo, required, handoff, files, _data = self.fixture()
        old = (repo/'fixtures/abi/v1/capabilities.json').read_bytes()
        origin = V.document(files['payload/capabilities-provenance.json']);origin['capabilities_sha256'] = V.digest(old)
        manifest = V.document(files['payload/MANIFEST.json'])
        with self.assertRaisesRegex(ValueError, 'current capabilities version'):
            V.current_capabilities(old, raw(origin), old, '1.0.0', PRODUCER, manifest['libs'], origin['compiled_source_sha256'])

    def test_host_platform_cannot_qualify_android_even_with_matching_hashes(self):
        repo, required, handoff, files, _data = self.fixture()
        host = V.document(files['payload/capabilities.json']);host['routing']['uid_package_split'] = False
        origin = V.document(files['payload/capabilities-provenance.json']);origin['capabilities_sha256'] = V.digest(raw(host))
        manifest = V.document(files['payload/MANIFEST.json'])
        with self.assertRaisesRegex(ValueError, 'Android capabilities platform'):
            V.current_capabilities(raw(host), raw(origin), (repo/'fixtures/abi/v1/capabilities.json').read_bytes(),
                                   '1.0.0', PRODUCER, manifest['libs'], origin['compiled_source_sha256'])

    def test_current_capabilities_hash_provenance_and_abi_regressions_fail_closed(self):
        repo, required, handoff, files, _data = self.fixture()
        origin = V.document(files['payload/capabilities-provenance.json']);manifest = V.document(files['payload/MANIFEST.json'])
        args = ((repo/'fixtures/abi/v1/capabilities.json').read_bytes(), '1.0.0', PRODUCER, manifest['libs'], origin['compiled_source_sha256'])
        with self.assertRaisesRegex(ValueError, 'unexpected document fields'):
            V.current_capabilities(files['payload/capabilities.json'], b'{}', *args)
        with self.assertRaisesRegex(ValueError, 'current capabilities bytes'):
            V.current_capabilities(files['payload/capabilities.json']+b' ', raw(origin), *args)
        changed = V.document(files['payload/capabilities.json']);changed['abi_version'] = 2
        origin['capabilities_sha256'] = V.digest(raw(changed))
        with self.assertRaisesRegex(ValueError, 'ABI invariant'):
            V.current_capabilities(raw(changed), raw(origin), *args)

    def test_changed_capabilities_artifact_hash_is_rejected(self):
        repo, required, handoff, files, _data = self.fixture()
        files['payload/capabilities.json'] += b' '
        with self.assertRaisesRegex(ValueError, 'capabilities artifact hash'):
            V.verify_payload(handoff, files, repo, required)

    def test_record_without_current_capabilities_stops_before_build_or_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)/'must-not-be-created'
            result = subprocess.run(['bash', str(ROOT/'scripts/rollback-artifact.sh'), 'record', str(output),
                                     '--libs', str(Path(temporary)/'unused-libraries')], capture_output=True, timeout=5)
            self.assertNotEqual(0, result.returncode)
            self.assertIn(b'explicit current Android capabilities', result.stderr)
            self.assertFalse(output.exists())


    def test_old_two_abi_definition_and_rehashed_profile_retag_are_rejected(self):
        repo, required, handoff, files, _data = self.fixture()
        scope = V.document(required)
        old = copy.deepcopy(scope);old['releaseAbis'] = ['arm64-v8a', 'x86_64']
        with self.assertRaisesRegex(ValueError, 'release ABI policy'):V.required_scope(raw(old))
        for profile in ('android64', 'legacy4'):
            bad = copy.deepcopy(scope);bad['androidReleaseDefinition']['androidDeliveryProfile'] = profile
            bad['scopes']['android-release'] = V.digest(json.dumps(bad['androidReleaseDefinition'], sort_keys=True, separators=(',', ':')).encode())
            with self.subTest(profile=profile), self.assertRaisesRegex(ValueError, 'delivery definition'):V.required_scope(raw(bad))

    def test_required_checks_cannot_be_dropped_even_with_new_hash(self):
        _repo, required, _handoff, _files, _data = self.fixture();scope = V.document(required)
        scope['androidReleaseDefinition']['requiredChecks'].remove('all-four-JNI-artifacts')
        scope['scopes']['android-release'] = V.digest(json.dumps(scope['androidReleaseDefinition'], sort_keys=True, separators=(',', ':')).encode())
        with self.assertRaisesRegex(ValueError, 'required checks'):V.required_scope(raw(scope))

    def test_current_four_abi_caps_reject_old_two_library_origin(self):
        repo, _required, _handoff, files, _data = self.fixture();origin = V.document(files['payload/capabilities-provenance.json']);libs = V.document(files['payload/MANIFEST.json'])['libs']
        origin['abis'] = ['arm64-v8a', 'x86_64'];origin['libraries'] = [r for r in libs if r['abi'] in origin['abis']]
        with self.assertRaisesRegex(ValueError, 'ABI origin'):V.current_capabilities(files['payload/capabilities.json'], raw(origin), (repo/'fixtures/abi/v1/capabilities.json').read_bytes(), '1.0.0', PRODUCER, libs, origin['compiled_source_sha256'])

    def test_wrong_machine_cannot_be_rehashed_into_a_valid_abi(self):
        repo, required, handoff, files, _data = self.fixture();bad = dict(files);manifest = V.document(bad['payload/MANIFEST.json']);row = next(r for r in manifest['libs'] if r['abi'] == 'armeabi-v7a');name = 'payload/jniLibs/armeabi-v7a/libfoxhole_native.so';body = bytearray(bad[name]);body[18:20] = (62).to_bytes(2, 'little');bad[name] = bytes(body);row['sha256'] = V.digest(body);bad['payload/MANIFEST.json'] = raw(manifest)
        with self.assertRaisesRegex(ValueError, 'ABI/class/machine'):V.verify_payload(handoff, bad, repo, required)

    def test_default_config_and_formal_scope_are_both_explicit_four(self):
        config = V.document((ROOT/'config/foxcore-android-delivery.json').read_bytes());scope = V.required_scope((ROOT/'scripts/lab-release-required-scope.json').read_bytes())
        self.assertEqual('android4', config['androidDeliveryProfile']);self.assertEqual(scope['releaseAbis'], config['abis']);self.assertEqual(scope['androidReleaseDefinition']['rustTargets'], config['targets'])


    def test_rehashed_wrong_record_command_is_rejected(self):
        _repo, required, _handoff, _files, _data = self.fixture();scope = V.document(required)
        scope['androidReleaseDefinition']['commands'][1] = 'echo "$FOXCORE_CURRENT_CAPABILITIES" "$FOXCORE_CURRENT_CAPABILITIES_SHA256" "$FOXCORE_CURRENT_CAPABILITIES_PROVENANCE" "$FOXCORE_CURRENT_CAPABILITIES_PROVENANCE_SHA256"'
        scope['scopes']['android-release'] = V.digest(json.dumps(scope['androidReleaseDefinition'], sort_keys=True, separators=(',', ':')).encode())
        with self.assertRaisesRegex(ValueError, 'normal record command'):
            V.required_scope(raw(scope))


if __name__ == '__main__':
    unittest.main()


