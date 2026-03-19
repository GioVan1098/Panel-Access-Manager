import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import '../models/config.dart';

class ProvisioningResult {
  final String caCertPem;
  final String tlsCertPem;
  final String tlsKeyPem;

  const ProvisioningResult({
    required this.caCertPem,
    required this.tlsCertPem,
    required this.tlsKeyPem,
  });
}

class HttpService {
  HttpClient _buildMtlsClient({
    required Uint8List caCertBytes,
    required Uint8List tlsCertBytes,
    required Uint8List tlsKeyBytes,
  }) {
    final ctx = SecurityContext(withTrustedRoots: false);
    ctx.setTrustedCertificatesBytes(caCertBytes);
    ctx.useCertificateChainBytes(tlsCertBytes);
    ctx.usePrivateKeyBytes(tlsKeyBytes);
    final client = HttpClient(context: ctx);
    client.badCertificateCallback = (_, __, ___) => false;
    return client;
  }

  // TOFU client: accepts self-signed cert only if fingerprint matches QR value.
  HttpClient _buildTofuClient(String expectedFingerprintHex) {
    final client = HttpClient();
    client.badCertificateCallback =
        (X509Certificate cert, String host, int port) {
      final fp = sha256.convert(cert.der).toString();
      return fp == expectedFingerprintHex;
    };
    return client;
  }

  Future<bool> healthCheck(
    PamConfig config, {
    required Uint8List caCertBytes,
    required Uint8List tlsCertBytes,
    required Uint8List tlsKeyBytes,
  }) async {
    try {
      return await _doHealthCheck(
        config.primaryEndpoint,
        caCertBytes: caCertBytes,
        tlsCertBytes: tlsCertBytes,
        tlsKeyBytes: tlsKeyBytes,
      );
    } on TimeoutException {
      if (config.mode == PamMode.hardened) {
        return _doHealthCheck(
          config.fallbackEndpoint,
          caCertBytes: caCertBytes,
          tlsCertBytes: tlsCertBytes,
          tlsKeyBytes: tlsKeyBytes,
        );
      }
      return false;
    } on SocketException {
      if (config.mode == PamMode.hardened) {
        return _doHealthCheck(
          config.fallbackEndpoint,
          caCertBytes: caCertBytes,
          tlsCertBytes: tlsCertBytes,
          tlsKeyBytes: tlsKeyBytes,
        );
      }
      return false;
    }
  }

  Future<bool> _doHealthCheck(
    String baseUrl, {
    required Uint8List caCertBytes,
    required Uint8List tlsCertBytes,
    required Uint8List tlsKeyBytes,
  }) async {
    final client = _buildMtlsClient(
      caCertBytes: caCertBytes,
      tlsCertBytes: tlsCertBytes,
      tlsKeyBytes: tlsKeyBytes,
    );
    try {
      final req = await client
          .getUrl(Uri.parse('$baseUrl/health'))
          .timeout(const Duration(seconds: 5));
      final resp = await req.close().timeout(const Duration(seconds: 5));
      await resp.drain<void>();
      return resp.statusCode == 200;
    } finally {
      client.close();
    }
  }

  Future<int> sendCommand({
    required PamConfig config,
    required Map<String, dynamic> body,
    required Uint8List caCertBytes,
    required Uint8List tlsCertBytes,
    required Uint8List tlsKeyBytes,
  }) async {
    Future<int> tryEndpoint(String baseUrl) async {
      final client = _buildMtlsClient(
        caCertBytes: caCertBytes,
        tlsCertBytes: tlsCertBytes,
        tlsKeyBytes: tlsKeyBytes,
      );
      try {
        final req = await client
            .postUrl(Uri.parse('$baseUrl/run'))
            .timeout(const Duration(seconds: 10));
        req.headers.contentType = ContentType.json;
        req.write(jsonEncode(body));
        final resp = await req.close().timeout(const Duration(seconds: 10));
        await resp.drain<void>();
        return resp.statusCode;
      } finally {
        client.close();
      }
    }

    try {
      return await tryEndpoint(config.primaryEndpoint);
    } on TimeoutException {
      if (config.mode == PamMode.hardened) {
        return tryEndpoint(config.fallbackEndpoint);
      }
      rethrow;
    } on SocketException {
      if (config.mode == PamMode.hardened) {
        return tryEndpoint(config.fallbackEndpoint);
      }
      rethrow;
    }
  }

  Future<ProvisioningResult> provision({
    required String serverIp,
    required int port,
    required String fingerprintHex,
    required String otp,
    required String deviceId,
    required String ed25519PubKeyB64,
  }) async {
    final client = _buildTofuClient(fingerprintHex);
    try {
      final req = await client
          .postUrl(Uri.parse('https://$serverIp:$port/provision'))
          .timeout(const Duration(seconds: 15));
      req.headers.contentType = ContentType.json;
      req.write(jsonEncode({
        'otp': otp,
        'device_id': deviceId,
        'ed25519_pubkey': ed25519PubKeyB64,
      }));
      final resp = await req.close().timeout(const Duration(seconds: 15));
      final respBody =
          await resp.transform(utf8.decoder).join();

      if (resp.statusCode != 200) {
        throw Exception('Provisioning failed: HTTP ${resp.statusCode} — $respBody');
      }

      final json = jsonDecode(respBody) as Map<String, dynamic>;
      return ProvisioningResult(
        caCertPem: json['ca_crt'] as String,
        tlsCertPem: json['tls_crt'] as String,
        tlsKeyPem: json['tls_key'] as String,
      );
    } finally {
      client.close();
    }
  }
}
