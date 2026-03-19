package com.giovanni.pam

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature

class MainActivity : FlutterActivity() {

    private val channel = "com.giovanni.pam/keystore"

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, channel)
            .setMethodCallHandler { call, result ->
                try {
                    when (call.method) {
                        "generateKeyPair" -> {
                            val alias = call.argument<String>("alias")!!
                            result.success(generateKeyPair(alias))
                        }
                        "sign" -> {
                            val alias = call.argument<String>("alias")!!
                            val data = call.argument<ByteArray>("data")!!
                            result.success(sign(alias, data))
                        }
                        "getPublicKey" -> {
                            val alias = call.argument<String>("alias")!!
                            result.success(getPublicKey(alias))
                        }
                        "hasKey" -> {
                            val alias = call.argument<String>("alias")!!
                            result.success(hasKey(alias))
                        }
                        "deleteKey" -> {
                            val alias = call.argument<String>("alias")!!
                            deleteKey(alias)
                            result.success(null)
                        }
                        else -> result.notImplemented()
                    }
                } catch (e: Exception) {
                    result.error("KEYSTORE_ERROR", e.message, e.toString())
                }
            }
    }

    private fun generateKeyPair(alias: String): String {
        val kpg = KeyPairGenerator.getInstance("Ed25519", "AndroidKeyStore")

        fun buildSpec(strongBox: Boolean): KeyGenParameterSpec {
            val b = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            if (strongBox) b.setIsStrongBoxBacked(true)
            return b.build()
        }

        val keyPair = try {
            kpg.initialize(buildSpec(strongBox = true))
            kpg.generateKeyPair()
        } catch (e: StrongBoxUnavailableException) {
            kpg.initialize(buildSpec(strongBox = false))
            kpg.generateKeyPair()
        }

        return Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP)
    }

    private fun sign(alias: String, data: ByteArray): String {
        val ks = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }
        val privateKey = ks.getKey(alias, null) as PrivateKey
        val sig = Signature.getInstance("Ed25519")
        sig.initSign(privateKey)
        sig.update(data)
        return Base64.encodeToString(sig.sign(), Base64.NO_WRAP)
    }

    private fun getPublicKey(alias: String): String {
        val ks = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }
        val cert = ks.getCertificate(alias) ?: error("Key not found: $alias")
        return Base64.encodeToString(cert.publicKey.encoded, Base64.NO_WRAP)
    }

    private fun hasKey(alias: String): Boolean {
        val ks = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }
        return ks.containsAlias(alias)
    }

    private fun deleteKey(alias: String) {
        val ks = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }
        ks.deleteEntry(alias)
    }
}
