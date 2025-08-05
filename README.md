<p align="center"><a href="https://www.uns.edu.pe" target="_blank"><img src="https://upload.wikimedia.org/wikipedia/commons/1/1a/Universidad_Nacional_del_Santa_Logo.png" width="250" alt="UNS Logo"></a></p>

<p align="center">
  <a href="https://developer.android.com/" target="_blank"><img src="https://img.shields.io/badge/Android-0F9D58?style=for-the-badge&logo=android&logoColor=white" alt="Android"></a>
  <a href="https://kotlinlang.org/" target="_blank"><img src="https://img.shields.io/badge/Kotlin-7F52FF?style=for-the-badge&logo=kotlin&logoColor=white" alt="Kotlin"></a>
  <a href="https://developer.android.com/topic/security" target="_blank"><img src="https://img.shields.io/badge/Android_Security-737373?style=for-the-badge&logo=android&logoColor=white" alt="Android Security"></a>
  <a href="https://github.com/bumptech/glide" target="_blank"><img src="https://img.shields.io/badge/Glide-737373?style=for-the-badge&logo=github&logoColor=white" alt="Glide"></a>
</p>

<p align="center">
  <a href="https://developer.android.com/training/sign-in/biometric-auth" target="_blank"><img src="https://img.shields.io/badge/Biometric_Authentication-273DAB?style=for-the-badge&logo=google-chrome&logoColor=white" alt="Biometric Auth"></a>
  <a href="https://developer.android.com/training/data-storage/room" target="_blank"><img src="https://img.shields.io/badge/Room_SQLite-1A73E8?style=for-the-badge&logo=sqlite&logoColor=white" alt="Room SQLite"></a>
  <a href="https://www.sqlite.org/" target="_blank"><img src="https://img.shields.io/badge/SQLCipher-1A73E8?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLCipher"></a>
</p>

# App de Seguridad y Privacidad

Una aplicación Android que demuestra el manejo seguro de permisos y protección de datos personales.

## Características

### Gestión de Permisos
- **Cámara**: Captura de fotos con manejo seguro
- **Galería**: Acceso a imágenes del dispositivo
- **Micrófono**: Grabación de audio con permisos dinámicos
- **Contactos**: Lectura segura de la lista de contactos
- **Teléfono**: Funcionalidad de llamadas
- **Ubicación**: Acceso a localización del usuario

### Seguridad y Privacidad
- **Protección de Datos**: Sistema de logging encriptado
- **Almacenamiento Seguro**: Base de datos SQLCipher
- **Permisos Runtime**: Solicitud dinámica de permisos
- **Política de Privacidad**: Información transparente sobre el uso de datos

## Tecnologías Utilizadas

- **Kotlin**: Lenguaje principal
- **Android Jetpack**: Componentes modernos
- **SQLCipher**: Encriptación de base de datos
- **Camera2 API**: Manejo avanzado de cámara
- **Security Crypto**: Encriptación de datos sensibles

## Instalación

1. Clona el repositorio
2. Abre el proyecto en Android Studio
3. Sincroniza las dependencias
4. Ejecuta en dispositivo o emulador

## Estructura del Proyecto

```
📁 app/
├── 📁 src/main/java/com/example/seguridad_priv_a/
│   ├── 📁 adapter/
│   │   └── 📄 PermissionsAdapter.kt       # Adaptador RecyclerView
│   ├── 📁 data/
│   │   ├── 📄 DataProtectionManager.kt    # Gestión de datos seguros
│   │   └── 📄 PermissionItem.kt           # Modelo de permisos
│   ├── 📁 forense/
│   │   └── 📄 ForensicAnalysisSystem.kt   # Análisis Forense y Compliance
│   ├── 📁 security/
│   │   ├── 📄 AdvancedAnonymizer.kt       # Anonimización avanzada de datos
│   │   ├── 📄 AntiTampering.kt            # Detección de manipulación de la app
│   │   ├── 📄 AppSignatureVerifier.kt     # Verificación de firma de la app
│   │   ├── 📄 CertificatePinnerHelper.kt  # Pinning de certificados SSL
│   │   ├── 📄 SecurityAuditManager.kt     # Gestión de auditorías de seguridad
│   │   ├── 📄 StringObfuscator.kt         # Ofuscación de cadenas
│   │   └── 📄 ZeroTrustManager.kt         # Implementación de Zero Trust
│   ├── 📄 MainActivity.kt                 # Pantalla principal
│   ├── 📄 PermissionsApplication.kt       # Configuración global
│   └── 📄 [Actividades individuales]
└── 📁 res/
    ├── 📁 layout/                         # Diseños XML
    ├── 📁 values/                         # Recursos y strings
    └── 📁 xml/                            # Configuraciones
```

## Permisos Requeridos

- `CAMERA` - Para captura de fotos
- `READ_MEDIA_IMAGES` - Acceso a galería
- `RECORD_AUDIO` - Grabación de audio
- `READ_CONTACTS` - Lectura de contactos
- `CALL_PHONE` - Realizar llamadas
- `ACCESS_COARSE_LOCATION` - Ubicación aproximada

## Licencia

Este proyecto es para fines educativos y demostrativos.