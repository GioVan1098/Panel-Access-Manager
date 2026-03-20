import 'dart:typed_data';
import 'package:flutter/services.dart';

class KeystoreService {
  static const _channel = MethodChannel('com.giovanni.pam/keystore');

  Future<String> generateKeyPair(String alias) async {
    final pubKey = await _channel.invokeMethod<String>(
      'generateKeyPair',
      {'alias': alias},
    );
    return pubKey!;
  }

  /// Generate a key pair with TEE-level biometric authentication required.
  /// The key cannot be used without a biometric event bound via CryptoObject.
  /// [setUserAuthenticationRequired] + [setUserAuthenticationValidityDurationSeconds(-1)]
  /// + [setInvalidatedByBiometricEnrollment] are set at generation time.
  Future<String> generateKeyPairHardened(String alias) async {
    final pubKey = await _channel.invokeMethod<String>(
      'generateKeyPairHardened',
      {'alias': alias},
    );
    return pubKey!;
  }

  Future<String> sign(String alias, Uint8List data) async {
    final sig = await _channel.invokeMethod<String>(
      'sign',
      {'alias': alias, 'data': data},
    );
    return sig!;
  }

  Future<String> getPublicKey(String alias) async {
    final key = await _channel.invokeMethod<String>(
      'getPublicKey',
      {'alias': alias},
    );
    return key!;
  }

  Future<bool> hasKey(String alias) async {
    final exists = await _channel.invokeMethod<bool>('hasKey', {'alias': alias});
    return exists ?? false;
  }

  Future<void> deleteKey(String alias) async {
    await _channel.invokeMethod('deleteKey', {'alias': alias});
  }

  Future<String> signWithBiometric(String alias, Uint8List data) async {
    final sig = await _channel.invokeMethod<String>(
      'signWithBiometric',
      {'alias': alias, 'data': data},
    );
    return sig!;
  }

  /// Sign using the hard-gate biometric path.
  /// Requires a key generated with [generateKeyPairHardened].
  /// The Signature object is bound to a CryptoObject — the TEE refuses
  /// to complete signing without a BIOMETRIC_STRONG authentication event.
  Future<String> signWithBiometricHardGate(String alias, Uint8List data) async {
    final sig = await _channel.invokeMethod<String>(
      'signWithBiometricHardGate',
      {'alias': alias, 'data': data},
    );
    return sig!;
  }

  Future<Map<String, dynamic>> checkDeviceIntegrity() async {
    final result = await _channel.invokeMethod<Map>('checkDeviceIntegrity');
    return Map<String, dynamic>.from(result ?? {});
  }

  Future<Map<String, dynamic>> getBiometricAvailability() async {
    final result = await _channel.invokeMethod<Map>('getBiometricAvailability');
    return Map<String, dynamic>.from(result ?? {});
  }
}
