package com.example.seguridad_priv_a.security

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ZeroTrustManagerTest {

    private lateinit var context: Context
    private lateinit var zeroTrustManager: ZeroTrustManager

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        zeroTrustManager = ZeroTrustManager.getInstance(context)

        // Limpiar preferencias antes de cada test
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        val prefs = EncryptedSharedPreferences.create(
            context,
            "zero_trust_prefs",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        ) as EncryptedSharedPreferences

        prefs.edit().clear().apply()
    }

    @After
    fun tearDown() {
        zeroTrustManager.endSession()
    }

    @Test
    fun testSingletonPattern() {
        val instance1 = ZeroTrustManager.getInstance(context)
        val instance2 = ZeroTrustManager.getInstance(context)
        Assert.assertSame(instance1, instance2)
    }

    @Test
    fun testSessionManagement() {
        // Verificar que no hay sesión activa inicialmente
        Assert.assertFalse(zeroTrustManager.isSessionValid())

        // Crear una nueva sesión
        val userId = "testUser123"
        val privileges = setOf("settings_read", "settings_write")
        val token = zeroTrustManager.createSession(userId, privileges, 1) // 1 minuto de duración

        // Verificar que la sesión es válida
        Assert.assertTrue(zeroTrustManager.isSessionValid())
        Assert.assertNotNull(token)
        Assert.assertTrue(token.length >= 32) // Verificar longitud del token

        // Finalizar sesión
        zeroTrustManager.endSession()
        Assert.assertFalse(zeroTrustManager.isSessionValid())
    }

    @Test
    fun testOperationAuthorization() {
        // Crear sesión con privilegios básicos
        zeroTrustManager.createSession("testUser", setOf("basic"))

        // Verificar autorización para operaciones
        Assert.assertTrue(zeroTrustManager.authorizeOperation("read_profile", "profile"))
        Assert.assertFalse(zeroTrustManager.authorizeOperation("delete_user", "admin"))
    }

    @Test
    fun testPrivilegeSystem() {
        // Verificar mapeo de privilegios
        Assert.assertEquals(
            "settings_read",
            zeroTrustManager.getRequiredPrivilege("read", "settings")
        )
        Assert.assertEquals(
            "settings_write",
            zeroTrustManager.getRequiredPrivilege("write", "settings")
        )
        Assert.assertEquals("admin", zeroTrustManager.getRequiredPrivilege("delete", "any_context"))
        Assert.assertEquals("basic", zeroTrustManager.getRequiredPrivilege("unknown", "context"))

        // Verificar chequeo de privilegios
        zeroTrustManager.createSession("testUser", setOf("settings_read"))
        Assert.assertTrue(zeroTrustManager.hasPrivilege("settings_read"))
        Assert.assertFalse(zeroTrustManager.hasPrivilege("settings_write"))
    }

    @Test
    fun testAppIntegrityVerification() {
        // La primera verificación debería pasar y guardar el hash
        Assert.assertTrue(zeroTrustManager.verifyAppIntegrity())

        // Verificaciones posteriores deberían seguir pasando
        Assert.assertTrue(zeroTrustManager.verifyAppIntegrity())
    }

    @Test
    fun testAnonymizeData() {
        Assert.assertEquals("abc", zeroTrustManager.anonymizeData("abc"))
        Assert.assertEquals("test", zeroTrustManager.anonymizeData("test"))
        Assert.assertEquals("user***", zeroTrustManager.anonymizeData("user123"))
        Assert.assertEquals("***-***-****", zeroTrustManager.anonymizeData("123-456-7890"))
        Assert.assertEquals("a-b-c", zeroTrustManager.anonymizeData("a-b-c"))
    }

    @Test
    fun testSecurityLogging() {
        zeroTrustManager.createSession("testUser", setOf("admin"))

        // Verificar que se puede registrar un evento
        zeroTrustManager.logSecurityEvent("TEST_EVENT", "This is a test event")

        // No hay forma directa de verificar el log ya que está encriptado,
        // pero podemos verificar que no lanza excepciones
        Assert.assertTrue(true)
    }

    @Test
    fun testHmacKeyGeneration() {
        // Verificar indirectamente que la clave HMAC funciona
        val testData = "test_data"
        val hmac = zeroTrustManager.generateHmac(testData)

        Assert.assertNotNull(hmac)
        Assert.assertTrue(hmac.isNotEmpty())
        Assert.assertTrue(hmac.length > 10) // El HMAC debería ser una cadena larga
    }

    @Test
    fun testSessionExpiration() {
        // Crear sesión con duración muy corta (1ms)
        zeroTrustManager.createSession("testUser", setOf("basic"), 0)

        // Esperar un poco para que expire
        Thread.sleep(100)

        // Verificar que la sesión ha expirado
        Assert.assertFalse(zeroTrustManager.isSessionValid())
    }
}