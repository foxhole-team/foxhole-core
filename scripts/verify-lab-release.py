#!/usr/bin/env python3
"""Verify an existing owner-signed LAB handoff and immutable release bytes.

No downloaded code is executed. A green source-only workflow is never evidence.
"""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tomllib

HANDOFF_PATH = 'metadata/lab-release-handoff.json'
COMPILER = 'payload/tools/linux-x86_64/foxcore-dns-compile'
MAX_ARCHIVE = 512 * 1024**2
MAX_EXPANDED = 1024 * 1024**2
REQUIRED_SCOPES = {'gate', 'features', 'android-release', 'supply-chain', 'abi', 'fuzz-harness', 'miri', 'sentinel-native'} | {
    'fuzz:' + name for name in ('netstack_packet', 'flow_key_from_packet', 'dns_message', 'wireguard_message',
                               'socks_codec', 'http_codec', 'reality_records', 'share_link', 'shadowtls_server_stream')}
ANDROID_RELEASE_ABIS = ['arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64']
ANDROID_RELEASE_TARGETS = ['aarch64-linux-android', 'armv7-linux-androideabi', 'i686-linux-android', 'x86_64-linux-android']
ANDROID_RELEASE_CHECKS = ['exact-compiled-inputs-and-producer', 'all-four-JNI-artifacts', 'ELF-LOAD-RELRO-page-and-export-gates', 'ABI-gate-PASS', 'Cargo.lock-and-capabilities-match', 'all-four-ABI-current-capabilities-origin', 'both-SBOMs-match', 'immutable-manifest-and-payload-hashes']
ANDROID_RELEASE_RECORD_COMMAND = 'scripts/rollback-artifact.sh record target/foxcore-release-candidate --libs target/android-jni --capabilities "$FOXCORE_CURRENT_CAPABILITIES" --capabilities-sha256 "$FOXCORE_CURRENT_CAPABILITIES_SHA256" --capabilities-provenance "$FOXCORE_CURRENT_CAPABILITIES_PROVENANCE" --capabilities-provenance-sha256 "$FOXCORE_CURRENT_CAPABILITIES_PROVENANCE_SHA256"'
ANDROID_ELF_TYPES = {'arm64-v8a': (2, 183), 'armeabi-v7a': (1, 40), 'x86': (1, 3), 'x86_64': (2, 62)}

COMPILED_FIXED = {'.cargo/config.toml', 'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml',
                  'scripts/android-build.sh', 'scripts/android-elf-gate.sh', 'scripts/android-path-leaks.py',
                  'config/foxcore-android-delivery.json', 'config/source-forks/rustls-0.23.46.json',
                  'config/source-forks/rustls-0.23.46.upstream-files.json',
                  'config/source-forks/rustls-0.23.46.NOTICE.md', 'patches/rustls-0.23.46-chrome151.patch'}
COMPILED_ROOTS = ('crates/', 'fingerprints/', 'fixtures/', 'vendor/rustls/')


def need(value, message):
    if not value:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def document(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def exact(value, keys):
    need(isinstance(value, dict) and set(value) == set(keys), 'unexpected document fields')


def safe_path(value):
    need(isinstance(value, str) and 0 < len(value) < 512, 'invalid path')
    p = PurePosixPath(value)
    need(not p.is_absolute() and str(p) == value and all(x not in ('.', '..') for x in p.parts), 'unsafe path')
    return p


def sha(value):
    need(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'full SHA-256 required')


def commit(value):
    need(isinstance(value, str) and re.fullmatch('[0-9a-f]{40}', value), 'full commit required')


def source_fingerprint(files):
    return digest(json.dumps(files, sort_keys=True, separators=(',', ':')).encode())


def current_capabilities(raw, provenance_raw, baseline_raw, version, producer, libs, compiled_fingerprint):
    """Current Android output is distinct from the frozen ABI-v1 baseline.

    The signed handoff binds these bytes and the reviewed native/probe/source
    origins. A host document cannot qualify Android's platform capabilities.
    """
    caps, origin = document(raw), document(provenance_raw)
    commit(producer)
    exact(origin, ('schema', 'kind', 'producer_commit', 'producer_dirty', 'compiled_source_sha256',
                   'native_input_manifest_sha256', 'native_producer_receipt_sha256', 'android_probe_receipt_sha256',
                   'source_derivation_sha256', 'capabilities_sha256', 'target_os', 'features',
                   'android_delivery_profile', 'abis', 'core_version', 'libraries'))
    need(origin['schema'] == 1 and origin['kind'] == 'qualified-current-android-capabilities', 'current capabilities provenance required')
    for key in ('compiled_source_sha256', 'native_input_manifest_sha256', 'native_producer_receipt_sha256',
                'android_probe_receipt_sha256', 'source_derivation_sha256', 'capabilities_sha256'):
        sha(origin[key])
    need(origin['producer_commit'] == producer and origin['producer_dirty'] is False, 'capabilities producer differs')
    need(origin['compiled_source_sha256'] == compiled_fingerprint, 'capabilities compiled source differs')
    need(origin['capabilities_sha256'] == digest(raw), 'current capabilities bytes differ')
    need(origin['core_version'] == caps.get('core_version') == version, 'current capabilities version differs')
    need(origin['target_os'] == 'android' and origin['android_delivery_profile'] == 'android4'
         and origin['features'] == 'shipped', 'Android capabilities profile required')
    need(origin['abis'] == ANDROID_RELEASE_ABIS and sorted(row['abi'] for row in libs) == origin['abis'], 'capabilities ABI origin differs')
    need(origin['libraries'] == libs, 'capabilities native libraries differ')
    need(isinstance(caps.get('routing'), dict) and caps['routing'].get('uid_package_split') is True, 'Android capabilities platform differs')
    baseline = document(baseline_raw)
    for key in ('abi_version', 'config_schema_version', 'capabilities_schema_version'):
        need(type(caps.get(key)) is int and caps[key] == baseline.get(key), 'capabilities ABI invariant differs')
    spec = importlib.util.spec_from_file_location('frozen_abi_capability_comparison', Path(__file__).with_name('abi-compare-json.py'))
    comparison = importlib.util.module_from_spec(spec);spec.loader.exec_module(comparison)
    problems, _notes = comparison.compare(baseline, caps)
    need(not problems, 'current capabilities break frozen ABI baseline: ' + '; '.join(problems))
    return caps, origin


def required_scope(raw):
    scope = document(raw)
    need(scope['schema'] == 1 and scope['kind'] == 'core-full-lab-gate-required-scope', 'wrong required scope kind')
    need(set(scope['scopes']) == REQUIRED_SCOPES and scope['fuzzSecondsPerTarget'] == 120, 'required full-gate checks were removed')
    current_abis = ANDROID_RELEASE_ABIS
    need(scope['releaseAbis'] == current_abis, 'release ABI policy differs')
    need(scope['fullGateAndroidABIs'] == current_abis and scope['deferredAbis'] == [], 'full-gate ABI policy differs')
    definition = scope['androidReleaseDefinition']
    need(definition['abis'] == current_abis and definition['androidDeliveryProfile'] == 'android4', 'Android delivery definition differs')
    need(definition['rustTargets'] == ANDROID_RELEASE_TARGETS, 'Android target definition differs')
    need(definition['environment']['FOXCORE_ANDROID_ABIS'] == ' '.join(current_abis), 'Android ABI environment differs')
    need(definition['schema'] == 1 and definition['scope'] == 'android-release', 'Android check definition identity differs')
    need(definition['requiredChecks'] == ANDROID_RELEASE_CHECKS, 'Android required checks differ')
    need(definition['commands'][0] == 'scripts/android-build.sh' and definition['commands'][2] == 'scripts/rollback-artifact.sh verify target/foxcore-release-candidate', 'Android normal build/verify commands differ')
    needed_inputs = ['FOXCORE_CURRENT_CAPABILITIES', 'FOXCORE_CURRENT_CAPABILITIES_SHA256', 'FOXCORE_CURRENT_CAPABILITIES_PROVENANCE', 'FOXCORE_CURRENT_CAPABILITIES_PROVENANCE_SHA256']
    need(definition['requiredEnvironmentInputs'] == needed_inputs, 'Explicit current capabilities inputs required')
    need(definition['commands'][1] == ANDROID_RELEASE_RECORD_COMMAND, 'Android normal record command differs')
    need(definition['environment']['FOXCORE_JNI_OUTPUT'] == 'target/android-jni', 'Android normal output differs')
    expected_definition = digest(json.dumps(definition, sort_keys=True, separators=(',', ':')).encode())
    need(scope['scopes']['android-release'] == expected_definition, 'Android check definition differs')
    need(scope['historicalFourAbiScopeIsCurrentEvidence'] is False and scope['historicalFourAbiDefinitionSha256'] != expected_definition, 'historical 32-bit evidence cannot qualify current scope')
    need(scope['previousAndroid64ScopeIsCurrentEvidence'] is False and scope['previousAndroid64DefinitionSha256'] != expected_definition, 'old two-ABI evidence cannot qualify android4')
    sha(scope['previousAndroid64DefinitionSha256'])
    for value in scope['scopes'].values():
        sha(value)
    return scope


def tracked_source_paths(repo, source):
    """Inventory the intended checkout, not an owner worktree or artifact list."""
    commit(source)
    raw = subprocess.check_output(['git', 'ls-tree', '-r', '-z', '--full-tree', source], cwd=repo, timeout=10)
    need(len(raw) <= 8 * 1024**2, 'tracked source inventory too large')
    paths = {}
    for item in raw.split(b'\0'):
        if not item:
            continue
        header, name = item.split(b'\t', 1)
        mode, kind, _object = header.decode('ascii').split()
        name = name.decode('utf-8');safe_path(name)
        need(name not in paths, 'duplicate tracked source')
        paths[name] = (mode, kind)
    return paths


def compiled_source_paths(repo, source):
    """Existing 522-input builder selector: fixed12 plus the four full roots.

    All extensions are selected under the roots, including build.rs, crate
    manifests, fixtures and vendored code. No artifact-supplied path list can
    reduce the intended checkout's closure. The count is derived, not frozen.
    """
    tracked = tracked_source_paths(repo, source)
    need(COMPILED_FIXED <= set(tracked), 'fixed compiled inputs missing from intended checkout')
    selected = COMPILED_FIXED | {name for name in tracked if name.startswith(COMPILED_ROOTS)}
    need(all(any(name.startswith(root) for name in selected) for root in COMPILED_ROOTS), 'compiled source roots incomplete')
    need(sum(name.startswith('fingerprints/') for name in selected) == 9, 'fingerprint input inventory differs')
    need(all(tracked[name] in (('100644', 'blob'), ('100755', 'blob')) for name in selected), 'nonregular compiled source input')
    return selected


def signed_handoff(repo, source, handoff_commit, expected_hash, verify_signature=None):
    for value in (source, handoff_commit):
        commit(value)
    sha(expected_hash)
    if verify_signature is None:
        def verify_signature(value):
            subprocess.run([sys.executable, str(repo/'scripts/verify-release-signature.py'), value],
                           cwd=repo, check=True, capture_output=True, timeout=30)
    # Both authorities use the existing pinned OpenPGP signer policy.
    verify_signature(source)
    verify_signature(handoff_commit)
    actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True, timeout=10).strip()
    need(actual == source, 'source checkout differs')
    raw = subprocess.check_output(['git', 'show', handoff_commit + ':' + HANDOFF_PATH], cwd=repo, timeout=10)
    need(len(raw) <= 2 * 1024**2 and digest(raw) == expected_hash, 'handoff bytes differ')
    return document(raw)


def select(handoff, repo, source, required):
    required_scope(required)
    exact(handoff, ('schema', 'kind', 'source_commit', 'producer_commit', 'version', 'release_tag',
                    'release_asset', 'staging_tag', 'staging_asset', 'archive_sha256', 'archive_bytes',
                    'compiled_inputs_sha256', 'scope_sha256', 'files'))
    need(handoff['schema'] == 1 and handoff['kind'] == 'owner-approved-core-lab-release', 'wrong handoff kind')
    need(handoff['source_commit'] == source, 'wrong release source')
    commit(handoff['producer_commit'])
    for key in ('archive_sha256', 'compiled_inputs_sha256', 'scope_sha256'):
        sha(handoff[key])
    need(handoff['scope_sha256'] == digest(required), 'required full-gate scope differs')
    version = tomllib.loads((repo/'Cargo.toml').read_text())['workspace']['package']['version']
    need(handoff['version'] == version, 'release version differs')
    need(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[+-][0-9A-Za-z.-]+)?', version), 'invalid release version')
    need(handoff['release_tag'] == 'v' + version, 'wrong release tag')
    for key in ('staging_tag', 'staging_asset', 'release_asset'):
        need(isinstance(handoff[key], str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,160}', handoff[key]), 'unsafe asset identity')
    need(handoff['staging_tag'] != handoff['release_tag'], 'staging and final release must differ')
    need(handoff['release_asset'].endswith('.tar.gz'), 'release archive name required')
    need(type(handoff['archive_bytes']) is int and 0 < handoff['archive_bytes'] <= MAX_ARCHIVE, 'archive size bound')
    need(isinstance(handoff['files'], dict) and 1 <= len(handoff['files']) <= 4096, 'invalid file inventory')
    for name, row in handoff['files'].items():
        safe_path(name)
        exact(row, ('sha256', 'bytes', 'mode'))
        sha(row['sha256'])
        need(type(row['bytes']) is int and 0 <= row['bytes'] <= MAX_ARCHIVE, 'file size bound')
        need(row['mode'] in (0o644, 0o755), 'file mode rejected')
    return handoff


def archive_files(raw, handoff):
    need(len(raw) == handoff['archive_bytes'] and digest(raw) == handoff['archive_sha256'], 'archive bytes differ')
    result = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        for member in archive:
            safe_path(member.name)
            need(member.isfile() and member.name not in result, 'nonregular or duplicate archive member')
            row = handoff['files'].get(member.name)
            need(row is not None and member.size == row['bytes'], 'unexpected archive member/size')
            total += member.size
            need(total <= MAX_EXPANDED, 'expanded archive too large')
            body = archive.extractfile(member).read(member.size + 1)
            need(len(body) == member.size and digest(body) == row['sha256'], 'member hash differs')
            result[member.name] = body
    need(set(result) == set(handoff['files']), 'missing archive member')
    return result


def android_elf(body, abi):
    need(abi in ANDROID_ELF_TYPES and len(body) >= 64 and body[:4] == b'\x7fELF' and body[5] == 1,
         'Android JNI ELF header differs')
    need((body[4], int.from_bytes(body[18:20], 'little')) == ANDROID_ELF_TYPES[abi]
         and int.from_bytes(body[16:18], 'little') == 3, 'Android JNI ABI/class/machine differs')


def verify_payload(handoff, files, repo, required):
    inputs_raw = files['metadata/compiled-inputs.json']
    need(digest(inputs_raw) == handoff['compiled_inputs_sha256'], 'compiled input manifest differs')
    inputs = document(inputs_raw)
    exact(inputs, ('schema', 'producer_commit', 'files'))
    need(inputs['schema'] == 1 and inputs['producer_commit'] == handoff['producer_commit'], 'wrong compiled producer')
    need(isinstance(inputs['files'], dict) and inputs['files'], 'empty compiled input closure')
    expected_paths = compiled_source_paths(repo, handoff['source_commit'])
    need(set(inputs['files']) == expected_paths, 'declared compiled source closure differs from intended checkout')
    for name, expected in inputs['files'].items():
        safe_path(name); sha(expected)
        p = repo/name
        need(not p.is_symlink() and p.resolve().is_relative_to(repo.resolve()) and p.is_file(), 'compiled source path rejected')
        need(digest(p.read_bytes()) == expected, 'compiled source equivalence differs: ' + name)
    gate = document(files['metadata/LAB-GATE.json'])
    exact(gate, ('schema', 'producer_commit', 'compiled_inputs_sha256', 'scope_sha256', 'checks'))
    need(gate['schema'] == 1 and gate['producer_commit'] == handoff['producer_commit'], 'wrong gate producer')
    need(gate['compiled_inputs_sha256'] == handoff['compiled_inputs_sha256'] and gate['scope_sha256'] == handoff['scope_sha256'], 'gate inputs/scope differ')
    scope = required_scope(required)
    need(set(gate['checks']) == set(scope['scopes']), 'full gate scope missing or extra')
    for name, expected in scope['scopes'].items():
        row = gate['checks'][name]
        exact(row, ('status', 'mode', 'definition_sha256', 'evidence_path', 'evidence_sha256'))
        need(row['status'] == 'PASS' and row['mode'] in ('fresh', 'retained-exact-input'), 'required gate did not pass')
        need(row['definition_sha256'] == expected, 'check definition differs')
        path = str(safe_path(row['evidence_path']));sha(row['evidence_sha256'])
        need(path.startswith('evidence/') and digest(files[path]) == row['evidence_sha256'], 'gate evidence differs')
    manifest = document(files['payload/MANIFEST.json'])
    need(manifest['git']['commit'] == handoff['producer_commit'] and manifest['git']['dirty'] is False, 'payload producer/dirty differs')
    need(manifest['core_version'] == handoff['version'], 'payload version differs')
    need(manifest['build_inputs']['cargo_lock_sha256'] == digest(files['payload/Cargo.lock']), 'payload lock differs')
    need(files['payload/Cargo.lock'] == (repo/'Cargo.lock').read_bytes(), 'source/payload lock differs')
    need(sorted(row['abi'] for row in manifest['libs']) == sorted(scope['releaseAbis']), 'release ABI policy differs')
    for row in manifest['libs']:
        body = files['payload/jniLibs/' + row['abi'] + '/libfoxhole_native.so']
        need(digest(body) == row['sha256'] and len(body) == row['bytes'], 'JNI payload differs')
        android_elf(body, row['abi'])
    need(b'abi-gate: PASS' in files['payload/abi-gate.log'].splitlines(), 'actual ABI result missing')
    caps_raw, origin_raw = files['payload/capabilities.json'], files['payload/capabilities-provenance.json']
    need(manifest['build_inputs']['current_capabilities_sha256'] == digest(caps_raw)
         and manifest['build_inputs']['capabilities_provenance_sha256'] == digest(origin_raw), 'capabilities artifact hash differs')
    current_capabilities(caps_raw, origin_raw, (repo/'fixtures/abi/v1/capabilities.json').read_bytes(),
                         handoff['version'], handoff['producer_commit'], manifest['libs'], source_fingerprint(inputs['files']))
    for name in ('foxcore-aarch64-linux-android.cdx.json', 'workspace-all-targets.cdx.json'):
        need(files['payload/sbom/' + name] == (repo/'sbom'/name).read_bytes(), 'SBOM bytes differ')
    compiler = files[COMPILER]
    need(compiler[:6] == b'\x7fELF\x02\x01' and len(compiler) >= 64 and int.from_bytes(compiler[18:20], 'little') == 62, 'Linux x86_64 compiler ELF required')
    need(handoff['files'][COMPILER]['mode'] == 0o755, 'compiler must be executable')
    producer = document(files['metadata/compiler-producer.json'])
    exact(producer, ('schema', 'source_commit', 'compiled_inputs_sha256', 'target', 'binary_sha256', 'bytes', 'exit_code'))
    need(producer['schema'] == 1 and producer['source_commit'] == handoff['producer_commit'], 'compiler producer differs')
    need(producer['compiled_inputs_sha256'] == handoff['compiled_inputs_sha256'], 'compiler compiled-input closure differs')
    need(producer['target'] in ('x86_64-unknown-linux-gnu', 'x86_64-unknown-linux-musl') and producer['exit_code'] == 0, 'compiler target/build result differs')
    need(producer['binary_sha256'] == digest(compiler) and producer['bytes'] == len(compiler), 'compiler receipt/binary differs')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('mode', choices=('describe', 'verify'))
    p.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument('--source', required=True)
    p.add_argument('--handoff-commit', required=True)
    p.add_argument('--handoff-sha256', required=True)
    p.add_argument('--archive', type=Path)
    p.add_argument('--output', type=Path)
    a = p.parse_args()
    required = (a.repo/'scripts/lab-release-required-scope.json').read_bytes()
    handoff = select(signed_handoff(a.repo, a.source, a.handoff_commit, a.handoff_sha256), a.repo, a.source, required)
    if a.mode == 'verify':
        need(a.archive is not None and a.output is not None and not a.output.exists(), 'new output and archive required')
        need(a.archive.stat().st_size == handoff['archive_bytes'], 'archive file size differs')
        files = archive_files(a.archive.read_bytes(), handoff)
        verify_payload(handoff, files, a.repo, required)
        a.output.mkdir(mode=0o700, parents=True)
        for name, body in files.items():
            target = a.output/name;target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(body);target.chmod(handoff['files'][name]['mode'])
    print(json.dumps(handoff, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError, tarfile.TarError) as error:
        sys.exit('LAB release admission failed: ' + str(error))
