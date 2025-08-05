package com.example.seguridad_priv_a.security

import android.util.Base64
import java.nio.charset.StandardCharsets

object StringObfuscator {
    // Strings sensibles ofuscadas como Base64
    private const val OBFUSCATED_MASTER_KEY_ALIAS = "bWFzdGVyX2tleQ==" // "master_key"
    private const val OBFUSCATED_PREFS_NAME = "c2VjdXJlX3ByZWZz" // "secure_prefs"
    private const val OBFUSCATED_HMAC_KEY = "c2VjcmV0X2htYWNfa2V5" // "secret_hmac_key"

    fun getMasterKeyAlias(): String {
        return decodeBase64(OBFUSCATED_MASTER_KEY_ALIAS)
    }

    fun getSecurePrefsName(): String {
        return decodeBase64(OBFUSCATED_PREFS_NAME)
    }

    fun getHmacKey(): String {
        return decodeBase64(OBFUSCATED_HMAC_KEY)
    }

    fun decodeBase64(input: String): String {
        return String(Base64.decode(input, Base64.DEFAULT), StandardCharsets.UTF_8)
    }

    // Método para ofuscar strings en tiempo de compilación
    fun obfuscateString(input: String): String {
        return Base64.encodeToString(input.toByteArray(StandardCharsets.UTF_8), Base64.DEFAULT)
    }
}