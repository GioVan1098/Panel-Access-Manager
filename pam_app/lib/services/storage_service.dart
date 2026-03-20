import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class StorageService {
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  static const _keyDeviceId = 'device_id';
  static const _keyServerIp = 'server_ip';
  static const _keyPort = 'port';
  static const _keyMode = 'mode';
  static const _keyCaCert = 'ca_crt';
  static const _keyTlsCert = 'tls_crt';
  static const _keyTlsKey = 'tls_key';
  static const _keyProvisioned = 'provisioned';
  static const _keyBiometricAuth = 'biometric_auth';
  static const _keySecurityMode  = 'security_mode';  // 'standard' | 'hardened'
  static const _keyWolEnabled    = 'wol_enabled';
  static const _keyWolMac        = 'wol_mac';

  Future<String?> getDeviceId() => _storage.read(key: _keyDeviceId);
  Future<void> setDeviceId(String v) => _storage.write(key: _keyDeviceId, value: v);

  Future<String?> getServerIp() => _storage.read(key: _keyServerIp);
  Future<void> setServerIp(String v) => _storage.write(key: _keyServerIp, value: v);

  Future<int> getPort() async {
    final v = await _storage.read(key: _keyPort);
    return int.tryParse(v ?? '') ?? 7443;
  }
  Future<void> setPort(int v) => _storage.write(key: _keyPort, value: v.toString());

  Future<String> getMode() async => await _storage.read(key: _keyMode) ?? 'direct';
  Future<void> setMode(String v) => _storage.write(key: _keyMode, value: v);

  Future<String?> getCaCert() => _storage.read(key: _keyCaCert);
  Future<void> setCaCert(String v) => _storage.write(key: _keyCaCert, value: v);

  Future<String?> getTlsCert() => _storage.read(key: _keyTlsCert);
  Future<void> setTlsCert(String v) => _storage.write(key: _keyTlsCert, value: v);

  Future<String?> getTlsKey() => _storage.read(key: _keyTlsKey);
  Future<void> setTlsKey(String v) => _storage.write(key: _keyTlsKey, value: v);

  Future<bool> isProvisioned() async =>
      await _storage.read(key: _keyProvisioned) == 'true';
  Future<void> setProvisioned(bool v) =>
      _storage.write(key: _keyProvisioned, value: v.toString());

  Future<bool> getBiometricAuthEnabled() async =>
      await _storage.read(key: _keyBiometricAuth) == 'true';
  Future<void> setBiometricAuthEnabled(bool v) =>
      _storage.write(key: _keyBiometricAuth, value: v.toString());

  // Security mode: 'standard' (soft-gate) or 'hardened' (hard-gate CryptoObject).
  // Null means not yet chosen (first provisioning).
  // Changing from 'standard' to 'hardened' requires re-provisioning (key regeneration).
  Future<String?> getSecurityMode() => _storage.read(key: _keySecurityMode);
  Future<void> setSecurityMode(String v) =>
      _storage.write(key: _keySecurityMode, value: v);

  // Wake-on-LAN
  Future<bool> getWolEnabled() async =>
      await _storage.read(key: _keyWolEnabled) == 'true';
  Future<void> setWolEnabled(bool v) =>
      _storage.write(key: _keyWolEnabled, value: v.toString());

  Future<String?> getWolMacAddress() => _storage.read(key: _keyWolMac);
  Future<void> setWolMacAddress(String v) =>
      _storage.write(key: _keyWolMac, value: v);

  Future<void> clearAll() => _storage.deleteAll();
}
