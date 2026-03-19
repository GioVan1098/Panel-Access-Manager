import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import '../models/command.dart';
import '../models/config.dart';
import '../services/crypto_service.dart';
import '../services/http_service.dart';
import '../services/keystore_service.dart';
import '../services/storage_service.dart';
import 'settings_screen.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  final _storage = StorageService();
  final _keystore = KeystoreService();
  final _http = HttpService();
  late final CryptoService _crypto;

  bool _provisioned = false;
  PamConfig _config = PamConfig.empty;
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    _crypto = CryptoService(_keystore);
    _loadConfig();
  }

  Future<void> _loadConfig() async {
    final provisioned = await _storage.isProvisioned();
    final ip = await _storage.getServerIp() ?? '';
    final port = await _storage.getPort();
    final modeStr = await _storage.getMode();
    final deviceId = await _storage.getDeviceId() ?? '';
    setState(() {
      _provisioned = provisioned;
      _config = PamConfig(
        mode: modeStr == 'hardened' ? PamMode.hardened : PamMode.direct,
        serverIp: ip,
        port: port,
        deviceId: deviceId,
        provisioned: provisioned,
      );
    });
  }

  Future<void> _send(PamCommand cmd) async {
    if (_busy) return;
    if (!_provisioned) {
      _notify('Device not provisioned — go to Settings', error: true);
      return;
    }

    setState(() => _busy = true);
    try {
      final caCertPem = await _storage.getCaCert();
      final tlsCertPem = await _storage.getTlsCert();
      final tlsKeyPem = await _storage.getTlsKey();

      if (caCertPem == null || tlsCertPem == null || tlsKeyPem == null) {
        _notify('Missing certificates — re-provision', error: true);
        return;
      }

      final caCert = Uint8List.fromList(utf8.encode(caCertPem));
      final tlsCert = Uint8List.fromList(utf8.encode(tlsCertPem));
      final tlsKey = Uint8List.fromList(utf8.encode(tlsKeyPem));

      final ts = _crypto.currentTimestamp();
      final nonce = _crypto.generateNonce();
      final payload = _crypto.buildCanonicalPayload(cmd.wireValue, ts, nonce);
      final sig = await _crypto.signPayload(_config.deviceId, payload);

      final body = _crypto.buildCommandBody(
        command: cmd.wireValue,
        deviceId: _config.deviceId,
        signatureB64: sig,
        timestamp: ts,
        nonce: nonce,
      );

      final status = await _http.sendCommand(
        config: _config,
        body: body,
        caCertBytes: caCert,
        tlsCertBytes: tlsCert,
        tlsKeyBytes: tlsKey,
      );

      switch (status) {
        case 200:
          _notify('${cmd.label}: OK');
        case 401:
          _notify('Unauthorized — signature rejected', error: true);
        case 409:
          _notify('Replay detected', error: true);
        case 400:
          _notify('Bad request — check clock sync', error: true);
        default:
          _notify('Unexpected status: $status', error: true);
      }
    } catch (e) {
      _notify('$e', error: true);
    } finally {
      setState(() => _busy = false);
    }
  }

  void _notify(String msg, {bool error = false}) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: Text(msg),
      backgroundColor: error ? Colors.red[700] : Colors.green[700],
      duration: const Duration(seconds: 3),
    ));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('PAM'),
        actions: [
          IconButton(
            icon: const Icon(Icons.settings),
            onPressed: () async {
              await Navigator.push(
                context,
                MaterialPageRoute(builder: (_) => const SettingsScreen()),
              );
              _loadConfig();
            },
          ),
        ],
      ),
      body: Column(
        children: [
          if (!_provisioned)
            MaterialBanner(
              content: const Text('Device not provisioned — go to Settings'),
              backgroundColor: Colors.orange[50],
              actions: [
                TextButton(
                  onPressed: () async {
                    await Navigator.push(
                      context,
                      MaterialPageRoute(
                          builder: (_) => const SettingsScreen()),
                    );
                    _loadConfig();
                  },
                  child: const Text('Settings'),
                ),
              ],
            ),
          if (_busy) const LinearProgressIndicator(),
          Expanded(
            child: GridView.builder(
              padding: const EdgeInsets.all(16),
              gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                crossAxisCount: 3,
                crossAxisSpacing: 12,
                mainAxisSpacing: 12,
              ),
              itemCount: PamCommand.values.length,
              itemBuilder: (_, i) {
                final cmd = PamCommand.values[i];
                return _CommandTile(
                  command: cmd,
                  enabled: _provisioned && !_busy,
                  onTap: () => _send(cmd),
                );
              },
            ),
          ),
        ],
      ),
    );
  }
}

class _CommandTile extends StatelessWidget {
  final PamCommand command;
  final bool enabled;
  final VoidCallback onTap;

  const _CommandTile({
    required this.command,
    required this.enabled,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final color = enabled ? Theme.of(context).colorScheme.primary : Colors.grey;
    return Card(
      elevation: enabled ? 2 : 0,
      child: InkWell(
        onTap: enabled ? onTap : null,
        borderRadius: BorderRadius.circular(12),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(command.icon, size: 36, color: color),
            const SizedBox(height: 8),
            Text(
              command.label,
              style: TextStyle(color: color, fontWeight: FontWeight.w500),
            ),
          ],
        ),
      ),
    );
  }
}
