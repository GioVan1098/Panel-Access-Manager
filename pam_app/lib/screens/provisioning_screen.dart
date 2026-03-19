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
    setState(() {
      _scanning = false;
      _status = 'Provisioning…';
    });

    try {
      final qr = jsonDecode(raw) as Map<String, dynamic>;
      final otp = qr['otp'] as String;
      final serverIp = qr['ip'] as String;
      final port = (qr['port'] as num?)?.toInt() ?? 7443;
      final fp = qr['fp'] as String;

      // Ensure device_id exists (persisted across re-provisioning)
      String? deviceId = await _storage.getDeviceId();
      if (deviceId == null || deviceId.isEmpty) {
        deviceId = const Uuid().v4();
        await _storage.setDeviceId(deviceId);
      }

      // Generate Ed25519 keypair in hardware Keystore (idempotent)
      final bool keyExists = await _keystore.hasKey(deviceId);
      final String ed25519PubKey = keyExists
          ? await _keystore.getPublicKey(deviceId)
          : await _keystore.generateKeyPair(deviceId);

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
