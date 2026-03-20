import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:uuid/uuid.dart';
import '../services/http_service.dart';
import '../services/keystore_service.dart';
import '../services/storage_service.dart';

class ProvisioningScreen extends StatefulWidget {
  const ProvisioningScreen({super.key});

  @override
  State<ProvisioningScreen> createState() => _ProvisioningScreenState();
}

class _ProvisioningScreenState extends State<ProvisioningScreen> {
  bool _scanning = true;
  bool _processing = false;
  bool _done = false;
  bool _error = false;
  String _status = 'Scan the QR code shown on the PAM GUI';

  final _keystore = KeystoreService();
  final _storage = StorageService();
  final _http = HttpService();

  Future<void> _handleQr(String raw) async {
    if (_processing) return;
    _processing = true;

    // Device integrity check before provisioning
    try {
      final integrity = await _keystore.checkDeviceIntegrity();
      final warnLevel = integrity['warning_level'] as String? ?? 'NONE';
      if (warnLevel != 'NONE' && mounted) {
        final secLevel = integrity['security_level'] as String? ?? 'UNKNOWN';
        final msg = warnLevel == 'HIGH'
            ? 'No Trusted Execution Environment detected — keys will be stored in software ($secLevel). '
                'Commands may be less secure on this device.'
            : 'This device uses a test-keys firmware build, which may indicate modified system software. '
                'Ed25519 keys are still hardware-backed.';
        final proceed = await showDialog<bool>(
          context: context,
          builder: (_) => AlertDialog(
            title: Text(warnLevel == 'HIGH' ? 'Security Warning' : 'Device Notice'),
            content: Text(msg),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context, false),
                child: const Text('Cancel'),
              ),
              TextButton(
                onPressed: () => Navigator.pop(context, true),
                child: Text(
                    warnLevel == 'HIGH' ? 'Proceed anyway' : 'Continue'),
              ),
            ],
          ),
        );
        if (proceed != true) {
          _processing = false;
          return;
        }
      }
    } catch (_) {
      // Integrity check failure is non-blocking
    }

    setState(() {
      _scanning = false;
      _status = 'Provisioning…';
    });

    try {
      final qr = jsonDecode(raw) as Map<String, dynamic>;
      final otp = qr['otp'] as String;
      final addr = qr['addr'] as String;
      final lastColon = addr.lastIndexOf(':');
      final serverIp = addr.substring(0, lastColon);
      final port = int.tryParse(addr.substring(lastColon + 1)) ?? 7443;
      final fp = qr['fp'] as String;

      // Ensure device_id exists (persisted across re-provisioning)
      String? deviceId = await _storage.getDeviceId();
      if (deviceId == null || deviceId.isEmpty) {
        deviceId = const Uuid().v4();
        await _storage.setDeviceId(deviceId);
      }

      // ── Security mode selection (first provisioning only) ──────────────
      // 'standard': soft-gate biometric (optional, changeable in Settings)
      // 'hardened': hard-gate CryptoObject (mandatory, TEE-enforced per-command)
      // Mode is chosen once and baked into the Keystore key at generation time.
      // Changing mode later requires re-provisioning (key must be regenerated).
      String? existingMode = await _storage.getSecurityMode();
      String securityMode = existingMode ?? 'standard';

      if (existingMode == null && mounted) {
        final chosen = await showDialog<String>(
          context: context,
          barrierDismissible: false,
          builder: (_) => AlertDialog(
            title: const Text('Security Mode'),
            content: const Text(
              'Choose how commands are authenticated:\n\n'
              'Standard — biometric confirmation is optional and can be '
              'toggled in Settings without re-provisioning.\n\n'
              'Hardened — every command requires a biometric event enforced '
              'at the Trusted Execution Environment (TEE) level. '
              'Cannot be bypassed in software. Changing mode requires '
              're-provisioning the device.',
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context, 'standard'),
                child: const Text('Standard'),
              ),
              FilledButton(
                onPressed: () => Navigator.pop(context, 'hardened'),
                child: const Text('Hardened'),
              ),
            ],
          ),
        );
        securityMode = chosen ?? 'standard';
        await _storage.setSecurityMode(securityMode);
      }

      // ── Key generation (mode-aware) ────────────────────────────────────
      final bool keyExists = await _keystore.hasKey(deviceId);
      final String ed25519PubKey;

      if (keyExists) {
        // If the security mode changed (re-provisioning with different mode),
        // delete the old key so the new one is generated with the correct flags.
        if (existingMode != null && existingMode != securityMode) {
          await _keystore.deleteKey(deviceId);
          await _storage.setSecurityMode(securityMode);
          ed25519PubKey = securityMode == 'hardened'
              ? await _keystore.generateKeyPairHardened(deviceId)
              : await _keystore.generateKeyPair(deviceId);
        } else {
          ed25519PubKey = await _keystore.getPublicKey(deviceId);
        }
      } else {
        ed25519PubKey = securityMode == 'hardened'
            ? await _keystore.generateKeyPairHardened(deviceId)
            : await _keystore.generateKeyPair(deviceId);
      }

      final result = await _http.provision(
        serverIp: serverIp,
        port: port,
        fingerprintHex: fp,
        otp: otp,
        deviceId: deviceId,
        ed25519PubKeyB64: ed25519PubKey,
      );

      await _storage.setCaCert(result.caCertPem);
      await _storage.setTlsCert(result.tlsCertPem);
      await _storage.setTlsKey(result.tlsKeyPem);
      await _storage.setServerIp(serverIp);
      await _storage.setPort(port);
      await _storage.setProvisioned(true);

      setState(() {
        _done = true;
        _status = 'Provisioning complete.';
      });
    } catch (e) {
      setState(() {
        _error = true;
        _scanning = true;
        _status = 'Error: $e';
      });
      _processing = false;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Provision Device')),
      body: Column(
        children: [
          if (_scanning)
            Expanded(
              child: MobileScanner(
                onDetect: (capture) {
                  final barcode = capture.barcodes.firstOrNull;
                  if (barcode?.rawValue != null) {
                    _handleQr(barcode!.rawValue!);
                  }
                },
              ),
            )
          else
            const Expanded(child: SizedBox()),
          Padding(
            padding: const EdgeInsets.all(32),
            child: Column(
              children: [
                Icon(
                  _done
                      ? Icons.check_circle
                      : _error
                          ? Icons.error
                          : Icons.hourglass_top,
                  size: 56,
                  color: _done
                      ? Colors.green
                      : _error
                          ? Colors.red
                          : Colors.grey,
                ),
                const SizedBox(height: 16),
                Text(_status, textAlign: TextAlign.center),
                if (_done) ...[
                  const SizedBox(height: 24),
                  FilledButton(
                    onPressed: () => Navigator.pop(context, true),
                    child: const Text('Done'),
                  ),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }
}
