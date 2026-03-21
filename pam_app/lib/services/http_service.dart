import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import '../models/config.dart';

// ── Wake-on-LAN ──────────────────────────────────────────────────────────
// Magic packet: 6 × 0xFF followed by the target MAC repeated 16 times (102 bytes).
// Sent as a UDP datagram to port 9.
//
// PAM (direct mode): targetIp = '255.255.255.255' (LAN broadcast)
// PAM-hardened:      targetIp = '10.0.0.2' (unicast via WireGuard tunnel)
//   Limitation: works only in light sleep where the WireGuard kernel module
//   is still loaded. Deep sleep (WireGuard process down) prevents IP-layer
//   delivery to the physical NIC.


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

  static Future<void> sendWolPacket(String targetIp, String macAddress) async {
    final parts = macAddress.split(RegExp(r'[:\-]'));
    if (parts.length != 6) {
      throw ArgumentError('Invalid MAC address format: $macAddress');
    }
    final mac = parts.map((s) => int.parse(s, radix: 16)).toList();
    final packet = Uint8List(102);
    // First 6 bytes: synchronization stream (0xFF × 6)
    for (int i = 0; i < 6; i++) {
      packet[i] = 0xFF;
    }
    // Remaining 96 bytes: MAC address repeated 16 times
    for (int rep = 0; rep < 16; rep++) {
      for (int b = 0; b < 6; b++) {
        packet[6 + rep * 6 + b] = mac[b];
      }
    }
    final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
    try {
      socket.broadcastEnabled = true;
      socket.send(packet, InternetAddress(targetIp), 9);
    } finally {
      socket.close();
    }
  }

  /// Fetch a one-time attestation challenge from the server (GET /provision/challenge).
  /// Returns the challenge as a base64 string. Must be called before key generation
  /// so the challenge can be passed to [generateKeyPairWithAttestation].
  Future<String> getAttestationChallenge({
    required String serverIp,
    required int port,
    required String fingerprintHex,
  }) async {
    final client = _buildTofuClient(fingerprintHex);
    try {
      final req = await client
          .getUrl(Uri.parse('https://$serverIp:$port/provision/challenge'))
          .timeout(const Duration(seconds: 10));
      final resp = await req.close().timeout(const Duration(seconds: 10));
      final body = await resp.transform(utf8.decoder).join();
      if (resp.statusCode != 200) {
        throw Exception('Challenge fetch failed: HTTP ${resp.statusCode}');
      }
      final json = jsonDecode(body) as Map<String, dynamic>;
      return json['challenge'] as String;
    } finally {
      client.close();
    }
  }

  Future<ProvisioningResult> provision({
    required String serverIp,
    required int port,
    required String fingerprintHex,
    required String otp,
    required String deviceId,
    required String ed25519PubKeyB64,
    List<String>? attestationChain,
    String? attestationChallenge,
  }) async {
    final client = _buildTofuClient(fingerprintHex);
    try {
      final req = await client
          .postUrl(Uri.parse('https://$serverIp:$port/provision'))
          .timeout(const Duration(seconds: 15));
      req.headers.contentType = ContentType.json;
      final body = <String, dynamic>{
        'otp': otp,
        'device_id': deviceId,
        'ed25519_pubkey': ed25519PubKeyB64,
      };
      if (attestationChain != null && attestationChallenge != null) {
        body['attestation_chain']     = attestationChain;
        body['attestation_challenge'] = attestationChallenge;
      }
      req.write(jsonEncode(body));
      final resp = await req.close().timeout(const Duration(seconds: 15));
      final respBody = await resp.transform(utf8.decoder).join();

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
