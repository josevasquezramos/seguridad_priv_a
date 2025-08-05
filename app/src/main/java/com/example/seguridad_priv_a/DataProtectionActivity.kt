package com.example.seguridad_priv_a

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import com.example.seguridad_priv_a.databinding.ActivityDataProtectionBinding
import java.util.concurrent.Executors

class DataProtectionActivity : AppCompatActivity() {

    private lateinit var binding: ActivityDataProtectionBinding
    private val dataProtectionManager by lazy {
        (application as PermissionsApplication).dataProtectionManager
    }

    // Variables para manejo de sesión
    private var lastActivityTime = System.currentTimeMillis()
    private val sessionTimeout = 5 * 60 * 1000L // 5 minutos en milisegundos
    private val sessionHandler = Handler(Looper.getMainLooper())
    private val sessionCheck = object : Runnable {
        override fun run() {
            checkSessionTimeout()
            sessionHandler.postDelayed(this, 1000) // Verificar cada segundo
        }
    }

    // Variables para autenticación biométrica
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo
    private val executor = Executors.newSingleThreadExecutor()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityDataProtectionBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupBiometricAuthentication()
        authenticateUser()

        // Iniciar el chequeo de timeout de sesión
        sessionHandler.post(sessionCheck)
    }

    private fun setupBiometricAuthentication() {
        // Configurar BiometricPrompt
        biometricPrompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    runOnUiThread {
                        sessionHandler.removeCallbacks(sessionCheck)
                        finish()
                    }
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    runOnUiThread {
                        updateLastActivityTime()
                        // Autenticación exitosa, permitir acceso
                        Toast.makeText(this@DataProtectionActivity,
                            "Autenticación exitosa", Toast.LENGTH_SHORT).show()
                        setupUI()
                        loadDataProtectionInfo()
                        loadAccessLogs()
                        updateLastActivityTime()
                    }
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    runOnUiThread {
                        Toast.makeText(this@DataProtectionActivity,
                            "Autenticación fallida", Toast.LENGTH_SHORT).show()
                    }
                }
            })

        // Configurar PromptInfo basado en las capacidades del dispositivo
        val biometricManager = BiometricManager.from(this)
        when (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)) {
            BiometricManager.BIOMETRIC_SUCCESS -> {
                promptInfo = BiometricPrompt.PromptInfo.Builder()
                    .setTitle("Autenticación requerida")
                    .setSubtitle("Accede a los logs protegidos")
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                    .build()
            }
            else -> {
                // Si no hay ningún método de autenticación disponible
                runOnUiThread {
                    Toast.makeText(this,
                        "No hay métodos de autenticación configurados", Toast.LENGTH_LONG).show()
                    finish()
                }
                return
            }
        }
    }

    private fun authenticateUser() {
        try {
            biometricPrompt.authenticate(promptInfo)
        } catch (e: Exception) {
            runOnUiThread {
                Toast.makeText(this, "Error al iniciar autenticación: ${e.message}", Toast.LENGTH_SHORT).show()
                finish()
            }
        }
    }

    private fun showDeviceCredentialsAuthentication() {
        // Configurar para solo credenciales del dispositivo (PIN/Pattern/Password)
        val deviceCredentialPromptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Autenticación requerida")
            .setSubtitle("Accede usando tu PIN, patrón o contraseña")
            .setAllowedAuthenticators(BiometricManager.Authenticators.DEVICE_CREDENTIAL)
            .build()

        biometricPrompt.authenticate(deviceCredentialPromptInfo)
    }

    private fun setupUI() {
        binding.btnViewLogs.setOnClickListener {
            updateLastActivityTime()
            loadAccessLogs()
            Toast.makeText(this, "Logs actualizados", Toast.LENGTH_SHORT).show()
        }

        binding.btnClearData.setOnClickListener {
            updateLastActivityTime()
            showClearDataDialog()
        }
    }

    private fun loadDataProtectionInfo() {
        updateLastActivityTime()
        val info = dataProtectionManager.getDataProtectionInfo()
        val infoText = StringBuilder()

        infoText.append("🔐 INFORMACIÓN DE SEGURIDAD\\n\\n")
        info.forEach { (key, value) ->
            infoText.append("• $key: $value\\n")
        }

        infoText.append("\\n📊 EVIDENCIAS DE PROTECCIÓN:\\n")
        infoText.append("• Encriptación AES-256-GCM activa\\n")
        infoText.append("• Todos los accesos registrados\\n")
        infoText.append("• Datos anonimizados automáticamente\\n")
        infoText.append("• Almacenamiento local seguro\\n")
        infoText.append("• No hay compartición de datos\\n")

        binding.tvDataProtectionInfo.text = infoText.toString()

        dataProtectionManager.logAccess("DATA_PROTECTION", "Información de protección mostrada")
    }

    private fun loadAccessLogs() {
        updateLastActivityTime()
        val logs = dataProtectionManager.getAccessLogs()

        if (logs.isNotEmpty()) {
            val logsText = logs.joinToString("\\n")
            binding.tvAccessLogs.text = logsText
        } else {
            binding.tvAccessLogs.text = "No hay logs disponibles"
        }

        dataProtectionManager.logAccess("DATA_ACCESS", "Logs de acceso consultados")
    }

    private fun showClearDataDialog() {
        updateLastActivityTime()
        AlertDialog.Builder(this)
            .setTitle("Borrar Todos los Datos")
            .setMessage("¿Estás seguro de que deseas borrar todos los datos almacenados y logs de acceso? Esta acción no se puede deshacer.")
            .setPositiveButton("Borrar") { _, _ ->
                clearAllData()
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }

    private fun clearAllData() {
        updateLastActivityTime()
        dataProtectionManager.clearAllData()

        // Actualizar UI
        binding.tvAccessLogs.text = "Todos los datos han sido borrados"
        binding.tvDataProtectionInfo.text = "🔐 DATOS BORRADOS DE FORMA SEGURA\\n\\nTodos los datos personales y logs han sido eliminados del dispositivo."

        Toast.makeText(this, "Datos borrados de forma segura", Toast.LENGTH_LONG).show()

        // Este log se creará después del borrado
        dataProtectionManager.logAccess("DATA_MANAGEMENT", "Todos los datos borrados por el usuario")
    }

    private fun updateLastActivityTime() {
        lastActivityTime = System.currentTimeMillis()
    }

    private fun checkSessionTimeout() {
        val currentTime = System.currentTimeMillis()
        if (currentTime - lastActivityTime > sessionTimeout) {
            // Terminar sesión
            Toast.makeText(this, "Sesión terminada por inactividad", Toast.LENGTH_LONG).show()
            finish()
        }
    }

    override fun onResume() {
        super.onResume()
        updateLastActivityTime()
        loadAccessLogs() // Actualizar logs al volver a la actividad
    }

    override fun onPause() {
        super.onPause()
        updateLastActivityTime()
    }

    override fun onDestroy() {
        super.onDestroy()
        sessionHandler.removeCallbacks(sessionCheck)
    }
}