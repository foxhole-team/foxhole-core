"""Offline checks for watcher input failures and retained capture-review gates."""
import contextlib
import importlib.util
import io
import json
import re
import shutil
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve()
SCRIPT = HERE.parents[1] / 'fingerprint-from-utls.py'
REPOSITORY = SCRIPT.parent.parent
spec = importlib.util.spec_from_file_location('fingerprint_watcher', SCRIPT)
watcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watcher)
REVISION = 'a' * 40


def reference_source():
    """Synthetic API-shaped155 table, not an upstream Go implementation.

    Principal field contract reviewed at upstream ff1b50fbbe9a6dff1dcb1cfc0493bd5b0f073f67.
    Lists come from the existing independent151 JSON plus only the two approved
    differences. Separate actual-upstream validation remains an offline gate.
    """
    fingerprint = json.loads((REPOSITORY / 'fingerprints/chrome_151.json').read_text())['fingerprint']
    def names(entries, table, extra=None):
        reverse = {value: name for name, value in table.items()}
        reverse.update(extra or {})
        result = []
        for entry in entries:
            value = entry['value'] if isinstance(entry, dict) else entry[0]
            result.append('GREASE_PLACEHOLDER' if value == 'GREASE' else reverse[int(value, 16)])
        return result
    def listing(values):
        return ''.join('\t\t\t\t\t' + value + ',\n' for value in values)
    ciphers = listing(names(fingerprint['cipher_suites'], watcher.CIPHERS))
    groups = listing(names(fingerprint['supported_groups'], watcher.CURVES))
    signatures = listing(['GREASE_PLACEHOLDER'] + names(fingerprint['signature_algorithms'], watcher.SIGALGS,
        {0x0904:'MLDSA44', 0x0905:'MLDSA65', 0x0906:'MLDSA87'}))
    shares = ''.join('\t\t\t\t\t' + ('{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},' if value == 'GREASE_PLACEHOLDER'
        else '{Group: ' + value + '},') + '\n' for value in names(fingerprint['key_shares'], watcher.CURVES))
    versions = listing(names(fingerprint['supported_versions'], {}, {0x0304:'VersionTLS13',0x0303:'VersionTLS12'}))
    return ('\tcase HelloChrome_155:\n\t\treturn ClientHelloSpec{\n'
        '\t\t\tCipherSuites: []uint16{\n' + ciphers + '\t\t\t},\n'
        '\t\t\tCompressionMethods: []byte{\n\t\t\t\t0x00, // compressionNone\n\t\t\t},\n'
        '\t\t\tExtensions: ShuffleChromeTLSExtensions([]TLSExtension{\n'
        '\t\t\t\t&UtlsGREASEExtension{},\n\t\t\t\t&SNIExtension{},\n'
        '\t\t\t\t&ExtendedMasterSecretExtension{},\n'
        '\t\t\t\t&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},\n'
        '\t\t\t\t&SupportedCurvesExtension{[]CurveID{\n' + groups + '\t\t\t\t}},\n'
        '\t\t\t\t&SupportedPointsExtension{SupportedPoints: []byte{\n\t\t\t\t\t0x00, // pointFormatUncompressed\n\t\t\t\t}},\n'
        '\t\t\t\t&SessionTicketExtension{},\n'
        '\t\t\t\t&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},\n'
        '\t\t\t\t&StatusRequestExtension{},\n'
        '\t\t\t\t&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{\n' + signatures + '\t\t\t\t}},\n'
        '\t\t\t\t&SCTExtension{},\n'
        '\t\t\t\t&KeyShareExtension{[]KeyShare{\n' + shares + '\t\t\t\t}},\n'
        '\t\t\t\t&PSKKeyExchangeModesExtension{[]uint8{\n\t\t\t\t\tPskModeDHE,\n\t\t\t\t}},\n'
        '\t\t\t\t&SupportedVersionsExtension{[]uint16{\n' + versions + '\t\t\t\t}},\n'
        '\t\t\t\t&UtlsCompressCertExtension{[]CertCompressionAlgo{\n\t\t\t\t\tCertCompressionBrotli,\n\t\t\t\t}},\n'
        '\t\t\t\t&ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}},\n'
        '\t\t\t\t&TrustAnchorsExtension{TrustAnchorIDs: chrome155TrustAnchorIDs()},\n'
        '\t\t\t\tBoringGREASEECH(),\n\t\t\t\t&UtlsGREASEExtension{},\n'
        '\t\t\t}),\n\t\t}, nil\n\tcase SyntheticNext:\n')


def reference_common():
    return ('HelloChrome_Auto        = HelloChrome_155\n'
            'HelloFirefox_Auto = HelloFirefox_148\n')


class FingerprintWatcherTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='fingerprint-fixture-')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / 'fingerprints').mkdir()
        for source in (REPOSITORY / 'fingerprints').glob('*.json'):
            shutil.copyfile(source, root / 'fingerprints' / source.name)
        constants = patch.object(watcher, 'UTLS_CONSTANTS', {'MLDSA44':0x0904,'MLDSA65':0x0905,'MLDSA87':0x0906,'utlsExtensionTrustAnchors':0xca34})
        constants.start()
        self.addCleanup(constants.stop)
        replace = patch.object(watcher, 'REPO', root)
        replace.start()
        self.addCleanup(replace.stop)

    def test_missing_companion_is_unavailable_instead_of_empty_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(OSError):
                watcher.fetch_companion(str(Path(temporary) / 'u_parrots.go'), 'u_common.go')

    def test_parse_failure_is_unavailable_and_does_not_claim_divergence(self):
        with patch.object(watcher.sys, 'argv', [str(SCRIPT), '--source', 'unused']), \
             patch.object(watcher, 'fetch', return_value='invalid upstream source'), \
             patch.object(watcher, 'fetch_constants', return_value={}), \
             contextlib.redirect_stderr(io.StringIO()) as errors:
            try:
                result = watcher.main()
            except SystemExit as error:
                result = error.code
            self.assertEqual(2, result)
        self.assertIn('could not read or parse', errors.getvalue())

    def test_auto_alias_drift_keeps_the_capture_review_open(self):
        failures = []
        watcher.check_capture_derived('', 'HelloChrome_Auto = HelloChrome_156\nHelloFirefox_Auto = HelloFirefox_148\n', failures)
        self.assertTrue(any('HelloChrome_156' in failure for failure in failures))

    def test_capture_table_appearing_upstream_is_still_a_failure(self):
        failures = []
        watcher.check_capture_derived('case HelloChrome_151:', 'HelloChrome_Auto = HelloChrome_133\nHelloFirefox_Auto = HelloFirefox_148\n', failures)
        self.assertTrue(any('now defines HelloChrome_151' in failure for failure in failures))

    def test_remote_inputs_use_one_immutable_revision(self):
        urls = []
        def open_file(url, **kwargs):
            urls.append(url)
            return io.BytesIO(b'// same snapshot')
        with patch.object(watcher.urllib.request, 'urlopen', side_effect=open_file):
            watcher.fetch(None, REVISION)
            for name in watcher.UTLS_CONSTANT_FILES:
                watcher.fetch_companion(None, name, REVISION)
        self.assertEqual(4, len(urls))
        self.assertTrue(all(f'/{REVISION}/' in url for url in urls), urls)

    def test_symbolic_revision_cannot_enter_immutable_fetch(self):
        with self.assertRaises(ValueError):
            watcher.resolve_revision('master')

    def test_default_revision_is_resolved_once_from_upstream_identity(self):
        metadata = io.BytesIO(json.dumps({'sha': REVISION}).encode())
        with patch.object(watcher.urllib.request, 'urlopen', return_value=metadata) as request:
            self.assertEqual(REVISION, watcher.resolve_revision(None))
        self.assertEqual(1, request.call_count)


    def reference_check(self, change=None, common_change=None):
        text = reference_source()
        common = reference_common()
        if change:
            match = re.search(r'(?m)^\tcase HelloChrome_155:\n([\s\S]*?)(?=^\tcase )', text)
            self.assertIsNotNone(match)
            changed = change(match.group(1))
            self.assertNotEqual(match.group(1), changed)
            text = text[:match.start(1)] + changed + text[match.end(1):]
        if common_change:
            common = common_change(common)
        failures = []
        lines = watcher.check_capture_derived(text, common, failures)
        return failures, lines

    def test_known_captured151_exact155_reference_differences_are_accepted(self):
        failures, lines = self.reference_check()
        self.assertEqual([], failures)
        self.assertTrue(any('HelloChrome_155' in line and 'intentional' in line for line in lines))

    def test_auto156_requires_another_deliberate_review(self):
        failures, _ = self.reference_check(common_change=lambda text: text.replace(
            'HelloChrome_Auto        = HelloChrome_155', 'HelloChrome_Auto        = HelloChrome_156'))
        self.assertTrue(failures)

    def test_missing_named155_reference_is_refused(self):
        text = reference_source().replace('case HelloChrome_155:', 'case HelloChrome_154:')
        failures = []
        watcher.check_capture_derived(text, reference_common(), failures)
        self.assertTrue(failures)

    def test_either_reviewed_difference_disappearing_is_refused(self):
        for old in ('\t\t\t\t\tGREASE_PLACEHOLDER,\n\t\t\t\t\tMLDSA44,',
                    '\t\t\t\t&TrustAnchorsExtension{TrustAnchorIDs: chrome155TrustAnchorIDs()},\n'):
            new = '\t\t\t\t\tMLDSA44,' if 'MLDSA44' in old else ''
            with self.subTest(removed=old):
                failures, _ = self.reference_check(change=lambda text: text.replace(old, new, 1))
                self.assertTrue(failures)

    def test_any_additional_principal_field_difference_is_refused(self):
        mutations = (
            ('TLS_AES_128_GCM_SHA256,', 'TLS_AES_256_GCM_SHA384,'),
            ('\t\t\t\t\tCurveP384,', '\t\t\t\t\tCurveP521,'),
            ('{Group: X25519},', '{Group: CurveP256},'),
            ('VersionTLS12,', 'VersionTLS11,'),
            ('AlpnProtocols: []string{"h2", "http/1.1"}', 'AlpnProtocols: []string{"h3", "http/1.1"}'),
            ('CertCompressionBrotli,', 'CertCompressionZlib,'),
            ('SupportedProtocols: []string{"h2"}', 'SupportedProtocols: []string{"h3"}'),
            ('0x00, // compressionNone', '0x01, // compressionNone'),
            ('0x00, // pointFormatUncompressed', '0x01, // pointFormatUncompressed'),
            ('PskModeDHE,', 'PskModePlain,'),
            ('Renegotiation: RenegotiateOnceAsClient', 'Renegotiation: RenegotiateNever'),
            ('\t\t\t\t&SCTExtension{},', '\t\t\t\t&SCTExtension{},\n\t\t\t\t&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},'),
            ('ShuffleChromeTLSExtensions([]TLSExtension{', '[]TLSExtension{'),
        )
        for old, new in mutations:
            with self.subTest(changed=old):
                failures, _ = self.reference_check(change=lambda text: text.replace(old, new, 1))
                self.assertTrue(failures)

    def test_trust_anchor_codepoint_drift_is_refused(self):
        with patch.dict(watcher.UTLS_CONSTANTS, {'utlsExtensionTrustAnchors': 0xca35}):
            failures, _ = self.reference_check()
        self.assertTrue(failures)

    def test_firefox_capture_claims_still_hold(self):
        failures, _ = self.reference_check(common_change=lambda text: text.replace(
            'HelloFirefox_Auto = HelloFirefox_148', 'HelloFirefox_Auto = HelloFirefox_149'))
        self.assertTrue(any('HelloFirefox_149' in failure for failure in failures))

    def test_changed_capture151_vector_is_refused(self):
        path = watcher.REPO / 'fingerprints/chrome_151.json'
        value = json.loads(path.read_text())
        value['fingerprint']['alpn'] = ['h3']
        path.write_text(json.dumps(value))
        failures, _ = self.reference_check()
        self.assertTrue(failures)


if __name__ == '__main__':
    unittest.main()
