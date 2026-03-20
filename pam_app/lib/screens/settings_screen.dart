import 'package:flutter/material.dart';
import '../models/config.dart';
import '../services/keystore_service.dart';
import '../services/storage_service.dart';
import 'provisioning_screen.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  final _storage = StorageService();
  final _keystore = KeystoreService();
  final _ipController = TextEditingController();
  final _portController = TextEditingController(text: '7443');
  PamMode _mode = PamMode.direct;
  bool _provisioned = false;
  String _deviceId = '';
  bool _biometricEnabled = false;
  bool _biometricAvailable = false;
  String _biometricStatus = 'UNKNOWN';

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final ip = await _storage.getServerIp();
    final port = await _storage.getPort();
    final mode = await _storage.getMode();
    final provisioned = await _storage.isProvisioned();
    final deviceId = await _storage.getDeviceId();
    final biometricEnabled = await _storage.getBiometricAuthEnabled();
    Map<String, dynamic> availability = {};
    try {
      availability = await _keystore.getBiometricAvailability();
    } catch (_) {}
    setState(() {
      _ipController.text = ip ?? '';
      _portController.text = port.toString();
      _mode = mode == 'hardened' ? PamMode.hardened : PamMode.direct;
      _provisioned = provisioned;
      _deviceId = deviceId ?? '';
      _biometricEnabled = biometricEnabled;
      _biometricAvailable =
          availability['any_auth_available'] as bool? ?? false;
      _biometricStatus =
          availability['biometric_status'] as String? ?? 'UNKNOWN';
    });
  }

  String _biometricUnavailableMessage() {
    switch (_biometricStatus) {
      case 'NO_HARDWARE':
        return 'No biometric hardware on this device';
      case 'HW_UNAVAILABLE':
        return 'Biometric hardware temporarily unavailable';
      case 'NONE_ENROLLED':
        return 'No biometrics enrolled — add fingerprint or face in Android settings';
      case 'SECURITY_UPDATE_REQUIRED':
        return 'Security update required before biometrics can be used';
      default:
        return 'Biometric authentication not available';
    }
  }

  Future<void> _save() async {
    await _storage.setServerIp(_ipController.text.trim());
    final port = int.tryParse(_portController.text.trim()) ?? 7443;
    await _storage.setPort(port);
    await _storage.setMode(_mode == PamMode.hardened ? 'hardened' : 'direct');
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Settings saved')),
      );
    }
  }

  Future<void> _deprovision() async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Deprovision device'),
        content: const Text(
            'All certificates and keys will be deleted. You will need to re-provision from the GUI.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Deprovision',
                style: TextStyle(color: Colors.red)),
          ),
        ],
      ),
    );
    if (confirm == true) {
      await _storage.clearAll();
      setState(() {
        _provisioned = false;
        _deviceId = '';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          TextField(
            controller: _ipController,
            decoration: const InputDecoration(
              labelText: 'Server IP',
              hintText: '192.168.1.x',
            ),
            keyboardType: TextInputType.number,
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _portController,
            decoration: const InputDecoration(labelText: 'Port'),
            keyboardType: TextInputType.number,
          ),
          const SizedBox(height: 20),
          Row(
            children: [
              const Text('Mode:', style: TextStyle(fontSize: 16)),
              const SizedBox(width: 16),
              SegmentedButton<PamMode>(
                segments: const [
                  ButtonSegment(value: PamMode.direct, label: Text('PAM')),
                  ButtonSegment(
                      value: PamMode.hardened, label: Text('Hardened')),
                ],
                selected: {_mode},
                onSelectionChanged: (s) => setState(() => _mode = s.first),
              ),
            ],
          ),
          const SizedBox(height: 24),
          const Divider(),
          SwitchListTile(
            secondary: Icon(
              Icons.fingerprint,
              color: _biometricAvailable
                  ? Theme.of(context).colorScheme.primary
                  : Colors.grey,
            ),
            title: const Text('Require biometric for commands'),
            subtitle: Text(
              _biometricAvailable
                  ? (_biometricEnabled
                      ? 'Fingerprint / face / PIN required to send commands'
                      : 'Tap to enable biometric confirmation')
                  : _biometricUnavailableMessage(),
              style: TextStyle(
                color: _biometricAvailable ? null : Colors.grey,
              ),
            ),
            value: _biometricEnabled && _biometricAvailable,
            onChanged: _biometricAvailable
                ? (v) async {
                    await _storage.setBiometricAuthEnabled(v);
                    setState(() => _biometricEnabled = v);
                  }
                : null,
          ),
          const Divider(),
          ListTile(
            leading: Icon(
              _provisioned ? Icons.verified_user : Icons.no_accounts,
              color: _provisioned ? Colors.green : Colors.grey,
            ),
            title: Text(_provisioned ? 'Provisioned' : 'Not provisioned'),
            subtitle: _deviceId.isNotEmpty
                ? Text(_deviceId,
                    style: const TextStyle(fontSize: 11, fontFamily: 'monospace'))
                : null,
          ),
          const SizedBox(height: 8),
          if (!_provisioned)
            ElevatedButton.icon(
              icon: const Icon(Icons.qr_code_scanner),
              label: const Text('Provision Device'),
              onPressed: () async {
                await _save();
                if (!mounted) return;
                final ok = await Navigator.push<bool>(
                  context,
                  MaterialPageRoute(
                      builder: (_) => const ProvisioningScreen()),
                );
                if (ok == true) _load();
              },
            )
          else
            OutlinedButton.icon(
              icon: const Icon(Icons.delete_forever, color: Colors.red),
              label: const Text('Deprovision',
                  style: TextStyle(color: Colors.red)),
              onPressed: _deprovision,
            ),
          const SizedBox(height: 24),
          FilledButton(onPressed: _save, child: const Text('Save')),
        ],
      ),
    );
  }

  @override
  void dispose() {
    _ipController.dispose();
    _portController.dispose();
    super.dispose();
  }
}
