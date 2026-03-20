import 'dart:convert';
import 'dart:typed_data';
import 'package:uuid/uuid.dart';
import 'keystore_service.dart';

class CryptoService {
  final KeystoreService _keystore;
  static const _uuid = Uuid();

  CryptoService(this._keystore);

  String generateNonce() => _uuid.v4();

  int currentTimestamp() => DateTime.now().millisecondsSinceEpoch ~/ 1000;

  // Canonical payload: command|timestamp|nonce
  // No JSON to avoid serialization ambiguity on the server side.
  String buildCanonicalPayload(String command, int timestamp, String nonce) =>
      '$command|$timestamp|$nonce';

  Future<String> signPayload(String alias, String payload) {
    final bytes = Uint8List.fromList(utf8.encode(payload));
    return _keystore.sign(alias, bytes);
  }

  Future<String> signPayloadWithBiometric(String alias, String payload) {
    final bytes = Uint8List.fromList(utf8.encode(payload));
    return _keystore.signWithBiometric(alias, bytes);
  }

  /// Sign using TEE-level biometric hard-gate (CryptoObject-bound).
  /// The key must have been generated with [KeystoreService.generateKeyPairHardened].
  Future<String> signPayloadWithBiometricHardGate(String alias, String payload) {
    final bytes = Uint8List.fromList(utf8.encode(payload));
    return _keystore.signWithBiometricHardGate(alias, bytes);
  }

  Map<String, dynamic> buildCommandBody({
    required String command,
    required String deviceId,
    required String signatureB64,
    required int timestamp,
    required String nonce,
  }) =>
      {
        'command': command,
        'device_id': deviceId,
        'timestamp': timestamp,
        'nonce': nonce,
        'signature': signatureB64,
      };
}
