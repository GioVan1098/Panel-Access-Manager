import 'package:flutter/material.dart';

enum PamCommand {
  lock,
  suspend,
  reboot,
  shutdown,
  wifiOn,
  wifiOff,
  volumeUp,
  volumeDown,
  mute;

  String get wireValue => switch (this) {
        PamCommand.lock => 'lock',
        PamCommand.suspend => 'suspend',
        PamCommand.reboot => 'reboot',
        PamCommand.shutdown => 'shutdown',
        PamCommand.wifiOn => 'wifi_on',
        PamCommand.wifiOff => 'wifi_off',
        PamCommand.volumeUp => 'volume_up',
        PamCommand.volumeDown => 'volume_down',
        PamCommand.mute => 'mute',
      };

  String get label => switch (this) {
        PamCommand.lock => 'Lock',
        PamCommand.suspend => 'Suspend',
        PamCommand.reboot => 'Reboot',
        PamCommand.shutdown => 'Shutdown',
        PamCommand.wifiOn => 'WiFi On',
        PamCommand.wifiOff => 'WiFi Off',
        PamCommand.volumeUp => 'Vol +',
        PamCommand.volumeDown => 'Vol -',
        PamCommand.mute => 'Mute',
      };

  IconData get icon => switch (this) {
        PamCommand.lock => Icons.lock,
        PamCommand.suspend => Icons.bedtime,
        PamCommand.reboot => Icons.restart_alt,
        PamCommand.shutdown => Icons.power_settings_new,
        PamCommand.wifiOn => Icons.wifi,
        PamCommand.wifiOff => Icons.wifi_off,
        PamCommand.volumeUp => Icons.volume_up,
        PamCommand.volumeDown => Icons.volume_down,
        PamCommand.mute => Icons.volume_mute,
      };
}
