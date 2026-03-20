package com.giovanni.pam

import android.os.Build
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import android.view.WindowManager
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

class MainActivity : FlutterFragmentActivity() {

    private val channel = "com.giovanni.pam/keystore"

    // State for pending async biometric sign
    private var pendingSignResult: MethodChannel.Result? = null
    private var pendingSignAlias: String? = null
    private var pendingSignData: ByteArray? = null

    // ── FLAG_SECURE: block screenshots, screen recording, screen sharing ──
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }

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
                        "signWithBiometric" -> {
                            val alias = call.argument<String>("alias")!!
                            val data = call.argument<ByteArray>("data")!!
                            // Async: result will be completed in the BiometricPrompt callback
                            signWithBiometric(alias, data, result)
                            return@setMethodCallHandler
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
                        "checkDeviceIntegrity" -> {
                            result.success(checkDeviceIntegrity())
                        }
                        "getBiometricAvailability" -> {
                            result.success(getBiometricAvailability())
                        }
                        else -> result.notImplemented()
                    }
                } catch (e: Exception) {
                    result.error("KEYSTORE_ERROR", e.message, e.toString())
                }
            }
    }

    // ── Key generation ───────────────────────────────────────────────────

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

    // ── Signing ──────────────────────────────────────────────────────────

    private fun sign(alias: String, data: ByteArray): String {
        val ks = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }
        val privateKey = ks.getKey(alias, null) as PrivateKey
        val sig = Signature.getInstance("Ed25519")
        sig.initSign(privateKey)
        sig.update(data)
        return Base64.encodeToString(sig.sign(), Base64.NO_WRAP)
    }

    /**
     * Sign with biometric gate (soft-gate approach):
     * - Shows BiometricPrompt (BIOMETRIC_STRONG | DEVICE_CREDENTIAL fallback)
     * - On success, signs with the existing Keystore key
     * - Completes [result] asynchronously
     */
    private fun signWithBiometric(alias: String, data: ByteArray, result: MethodChannel.Result) {
        pendingSignResult = result
        pendingSignAlias = alias
        pendingSignData = data

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("PAM — Authorize Command")
            .setSubtitle("Authentication required to send command")
            .setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
            )
            .build()

        val executor = ContextCompat.getMainExecutor(this)
        val biometricPrompt = BiometricPrompt(
            this,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    authResult: BiometricPrompt.AuthenticationResult
                ) {
                    val pAlias  = pendingSignAlias  ?: return
                    val pData   = pendingSignData   ?: return
                    val pResult = pendingSignResult ?: return
                    pendingSignResult = null
                    pendingSignAlias  = null
                    pendingSignData   = null
                    try {
                        pResult.success(sign(pAlias, pData))
                    } catch (e: Exception) {
                        pResult.error("SIGN_ERROR", e.message, null)
                    }
                }

                // Called on each failed attempt — Android handles retries automatically
                override fun onAuthenticationFailed() {}

                override fun onAuthenticationError(
                    errorCode: Int,
                    errString: CharSequence
                ) {
                    val pResult = pendingSignResult ?: return
                    pendingSignResult = null
                    pendingSignAlias  = null
                    pendingSignData   = null
                    pResult.error(
                        "BIOMETRIC_CANCELLED",
                        errString.toString(),
                        errorCode.toString()
                    )
                }
            }
        )

        biometricPrompt.authenticate(promptInfo)
    }

    // ── Key management ───────────────────────────────────────────────────

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

    // ── Device integrity check ───────────────────────────────────────────

    /**
     * Returns a map describing the device's security posture:
     *   security_level  : "STRONG_BOX" | "TRUSTED_ENVIRONMENT" | "SOFTWARE" | "UNKNOWN"
     *   has_strong_box  : Boolean
     *   is_test_keys    : Boolean (Build.TAGS contains "test-keys")
     *   warning_level   : "NONE" | "MEDIUM" | "HIGH"
     */
    private fun checkDeviceIntegrity(): Map<String, Any> {
        val result = mutableMapOf<String, Any>()
        val ks = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }

        // 1. Build tags (soft check — can be spoofed by sophisticated root tools)
        val isTestKeys = (Build.TAGS ?: "").contains("test-keys")
        result["is_test_keys"] = isTestKeys

        // 2. Generate a temp P-256 key and inspect its security level via KeyInfo
        val tempAlias = "_pam_integrity_check_tmp"
        try {
            if (ks.containsAlias(tempAlias)) ks.deleteEntry(tempAlias)
            val kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
            )
            kpg.initialize(
                KeyGenParameterSpec.Builder(tempAlias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build()
            )
            val keyPair = kpg.generateKeyPair()
            val keyFactory = KeyFactory.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
            )
            val keyInfo = keyFactory.getKeySpec(keyPair.private, KeyInfo::class.java)
            result["security_level"] = when (keyInfo.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONG_BOX          -> "STRONG_BOX"
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TRUSTED_ENVIRONMENT"
                KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE       -> "TRUSTED_ENVIRONMENT"
                else                                               -> "SOFTWARE"
            }
        } catch (e: Exception) {
            result["security_level"] = "UNKNOWN"
        } finally {
            try { ks.deleteEntry(tempAlias) } catch (_: Exception) {}
        }

        // 3. Probe StrongBox availability
        val sbAlias = "_pam_strongbox_probe_tmp"
        var hasStrongBox = false
        try {
            if (ks.containsAlias(sbAlias)) ks.deleteEntry(sbAlias)
            val kpg2 = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
            )
            kpg2.initialize(
                KeyGenParameterSpec.Builder(sbAlias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setIsStrongBoxBacked(true)
                    .build()
            )
            kpg2.generateKeyPair()
            hasStrongBox = true
        } catch (_: StrongBoxUnavailableException) {
        } catch (_: Exception) {
        } finally {
            try { ks.deleteEntry(sbAlias) } catch (_: Exception) {}
        }
        result["has_strong_box"] = hasStrongBox

        // 4. Overall warning level
        val secLevel = result["security_level"] as? String ?: "UNKNOWN"
        result["warning_level"] = when {
            secLevel == "SOFTWARE" -> "HIGH"
            isTestKeys             -> "MEDIUM"
            else                   -> "NONE"
        }

        return result
    }

    // ── Biometric availability query ─────────────────────────────────────

    /**
     * Returns a map describing what authentication methods are available:
     *   biometric_strong_available : Boolean
     *   device_credential_available: Boolean
     *   any_auth_available         : Boolean
     *   biometric_status           : "SUCCESS" | "NO_HARDWARE" | "HW_UNAVAILABLE" |
     *                                "NONE_ENROLLED" | "SECURITY_UPDATE_REQUIRED" | "UNKNOWN"
     */
    private fun getBiometricAvailability(): Map<String, Any> {
        val bm = BiometricManager.from(this)
        val strongResult = bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        val credResult   = bm.canAuthenticate(BiometricManager.Authenticators.DEVICE_CREDENTIAL)
        val anyResult    = bm.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
        )
        return mapOf(
            "biometric_strong_available"  to (strongResult == BiometricManager.BIOMETRIC_SUCCESS),
            "device_credential_available" to (credResult   == BiometricManager.BIOMETRIC_SUCCESS),
            "any_auth_available"          to (anyResult    == BiometricManager.BIOMETRIC_SUCCESS),
            "biometric_status" to when (strongResult) {
                BiometricManager.BIOMETRIC_SUCCESS                    -> "SUCCESS"
                BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE          -> "NO_HARDWARE"
                BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE       -> "HW_UNAVAILABLE"
                BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED        -> "NONE_ENROLLED"
                BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> "SECURITY_UPDATE_REQUIRED"
                else                                                   -> "UNKNOWN"
            }
        )
    }
}
