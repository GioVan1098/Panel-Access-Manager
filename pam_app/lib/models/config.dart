enum PamMode { direct, hardened }

class PamConfig {
  final PamMode mode;
  final String serverIp;
  final int port;
  final String deviceId;
  final bool provisioned;

  const PamConfig({
    required this.mode,
    required this.serverIp,
    required this.port,
    required this.deviceId,
    required this.provisioned,
  });

  static const PamConfig empty = PamConfig(
    mode: PamMode.direct,
    serverIp: '',
    port: 7443,
    deviceId: '',
    provisioned: false,
  );

  String get primaryEndpoint {
    if (mode == PamMode.hardened) return 'https://10.0.0.2:$port';
    return 'https://$serverIp:$port';
  }

  String get fallbackEndpoint => 'https://$serverIp:$port';
}
